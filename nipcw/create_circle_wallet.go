package nipcw

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

// JoinFreshness is a join proof's freshness window into the past, in seconds:
// its deadline is its created_at plus this (NIP-CW §Identity Proof, §Lost Join
// Reply).
const JoinFreshness = 300

// joinFuture is how far ahead of the Hub's clock a join proof may be dated.
const joinFuture = 60

var (
	// ErrPreparedJoinUsed is a PreparedJoin built into a second item: every
	// send, a retry included, needs a new proof (NIP-CW §Errors).
	ErrPreparedJoinUsed = errors.New("nipcw: this prepared join was already used; prepare a new one")
	// ErrDetailsConnection is a reply whose details carry no connection_pubkey,
	// or another one than the request's: an old reply, never this join's.
	ErrDetailsConnection = errors.New("nipcw: the details name another connection_pubkey than the request")
)

// CreateCircleWalletParams is a member's join: the credential that signs the
// proof, the member-generated connection key and the requested terms.
type CreateCircleWalletParams struct {
	Credential Credential
	// Connection is the member-generated keypair the wallet is issued to (NIP-CW
	// §Pairing Connection). REQUIRED, and its pubkey MUST differ from the
	// Credential's. Only the pubkey is sent; the secret never leaves the member.
	// nipcw/client fills it with a fresh key when left zero.
	Connection ConnectionKey
	// MaxAmountMillis and MaxReceiveMillis are the requested send and receive
	// caps per budget period (wire max_amount, max_receive), each at most 2^63-1.
	MaxAmountMillis, MaxReceiveMillis uint64
	// Expiry is the requested lifetime; zero asks for the Hub's default. It is
	// sent in whole seconds.
	Expiry time.Duration
	// BudgetRenewal is daily, weekly, monthly, yearly or never; empty is never,
	// which is what is sent and signed.
	BudgetRenewal string
}

// CreateCircleWalletRequest is create_circle_wallet's wire params.
type CreateCircleWalletRequest struct {
	Pubkey           string `json:"pubkey"`
	ConnectionPubkey string `json:"connection_pubkey"`
	MaxAmount        uint64 `json:"max_amount"`
	MaxReceive       uint64 `json:"max_receive"`
	Expiry           uint64 `json:"expiry"`
	BudgetRenewal    string `json:"budget_renewal,omitempty"`
	IdentityEvent    string `json:"identity_event"`
}

// Terms are the terms the request asks for, as its proof's terms tag binds them.
func (r CreateCircleWalletRequest) Terms() Terms {
	return Terms{MaxAmount: r.MaxAmount, MaxReceive: r.MaxReceive, Expiry: r.Expiry, Renewal: r.BudgetRenewal}
}

// ParseCreateCircleWalletRequest reads create_circle_wallet's params as a Hub
// receives them (NIP-CW §Processing Algorithm, step 1): pubkey,
// connection_pubkey, max_amount, max_receive and identity_event are required,
// the numbers JSON integers, identity_event a string. A failure is a
// *JoinProofError with BAD_REQUEST; the rest of step 1 is VerifyJoinProof's.
func ParseCreateCircleWalletRequest(raw []byte) (CreateCircleWalletRequest, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return CreateCircleWalletRequest{}, badRequest("params are not a JSON object")
	}
	for _, k := range []string{"pubkey", "connection_pubkey", "max_amount", "max_receive", "identity_event"} {
		if v, ok := keys[k]; !ok || string(v) == "null" {
			return CreateCircleWalletRequest{}, badRequest(k + " is required")
		}
	}
	var req CreateCircleWalletRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return CreateCircleWalletRequest{}, badRequest(err.Error())
	}
	// Omitted means never; present, it is one of the five values, and an empty
	// string is none of them (NIP-CW §Processing Algorithm step 1).
	if v, ok := keys["budget_renewal"]; ok && string(v) != "null" && req.BudgetRenewal == "" {
		return CreateCircleWalletRequest{}, badRequest("budget_renewal is empty")
	}
	return req, nil
}

// PreparedJoin is one signed join: its request, its proof's id and created_at,
// and the deadline a lost reply is looked up with (created_at + 300). It is
// built by Prepare and goes out at most once: Item refuses a second use.
type PreparedJoin struct {
	Request          CreateCircleWalletRequest
	ProofID          string
	CreatedAt        int64
	Deadline         int64
	ConnectionPubkey string
	// HubPubkey is the Hub connection's pubkey (TLV 0) the proof binds; the
	// item targets it and the details are decrypted from it.
	HubPubkey string

	cred Credential
	mu   sync.Mutex
	used bool
}

// Prepare signs the join once, bound to hubPubkey (the circlehub1 string's TLV
// 0) at now. It refuses a missing connection key, one equal to the requester's,
// a term above 2^63-1, a negative expiry and a renewal outside the enum; an
// omitted renewal is sent and signed as never.
func (p CreateCircleWalletParams) Prepare(hubPubkey string, now time.Time) (*PreparedJoin, error) {
	if !isLowerHex64(hubPubkey) {
		return nil, fmt.Errorf("nipcw: hub pubkey must be 64 lowercase hex")
	}
	pubkey, err := p.Credential.pubkey()
	if err != nil {
		return nil, fmt.Errorf("nipcw: credential: %w", err)
	}
	if p.Connection.IsZero() {
		return nil, ErrNoConnectionKey
	}
	if p.Connection.Pubkey() == pubkey {
		return nil, fmt.Errorf("nipcw: the connection key must differ from the requester's own key")
	}
	if p.Expiry < 0 {
		return nil, fmt.Errorf("nipcw: expiry is negative")
	}
	renewal, err := resolveRenewal(p.BudgetRenewal)
	if err != nil {
		return nil, err
	}
	req := CreateCircleWalletRequest{
		Pubkey: pubkey, ConnectionPubkey: p.Connection.Pubkey(),
		MaxAmount: p.MaxAmountMillis, MaxReceive: p.MaxReceiveMillis,
		Expiry: uint64(p.Expiry / time.Second), BudgetRenewal: renewal,
	}
	terms, err := TermsTag(req.Terms())
	if err != nil {
		return nil, err
	}
	createdAt := now.Unix()
	ev, err := p.Credential.signProof(createdAt,
		[]string{"d", hubPubkey}, []string{"connection", req.ConnectionPubkey}, []string{"terms", terms})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("nipcw: marshal identity proof: %w", err)
	}
	req.IdentityEvent = string(raw)
	return &PreparedJoin{
		Request: req, ProofID: ev.ID, CreatedAt: createdAt, Deadline: createdAt + JoinFreshness,
		ConnectionPubkey: req.ConnectionPubkey, HubPubkey: hubPubkey, cred: p.Credential,
	}, nil
}

// claim marks j used, refusing a second use.
func (j *PreparedJoin) claim() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.used {
		return ErrPreparedJoinUsed
	}
	j.used = true
	return nil
}

// Used reports whether j was already built into an item.
func (j *PreparedJoin) Used() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.used
}

// createCircleWalletResponseWire is create_circle_wallet's result: exactly one
// field. Every term of the wallet travels inside the ciphertext.
type createCircleWalletResponseWire struct {
	EncryptedDetails string `json:"encrypted_details"`
}

// CircleWalletDetails is the plaintext of encrypted_details (NIP-CW §Response):
// every term of the issued wallet and no secret.
type CircleWalletDetails struct {
	WalletPubkey        string   `json:"wallet_pubkey"`
	ConnectionPubkey    string   `json:"connection_pubkey"`
	Relays              []string `json:"relays"`
	MaxAmount           uint64   `json:"max_amount"`
	MaxReceive          uint64   `json:"max_receive"`
	ExpiresAt           int64    `json:"expires_at"`
	FeesPpm             uint64   `json:"fees_ppm"`
	DustThresholdMillis uint64   `json:"dust_threshold_millis"`
	RotationDelaySecs   *uint64  `json:"rotation_delay_secs,omitempty"`
	BudgetRenewal       string   `json:"budget_renewal"`
}

// EncryptDetails is the Hub side of the reply: d as JSON, NIP-44 encrypted
// from the Hub connection key (TLV 0's private key) to the requester's pubkey,
// wrapped as the one-field result {"encrypted_details": ...}.
func EncryptDetails(hubConnPriv, requesterPub string, d CircleWalletDetails) (string, error) {
	plain, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	key, err := conversationKey(hubConnPriv, requesterPub)
	if err != nil {
		return "", err
	}
	ct, err := nip44.Encrypt(string(plain), key)
	if err != nil {
		return "", fmt.Errorf("nipcw: encrypt details: %w", err)
	}
	out, err := json.Marshal(createCircleWalletResponseWire{EncryptedDetails: ct})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// CreateCircleWalletResponse is a parsed join reply. The member's connection is
// WalletPubkey, Relays and the secret it kept; nothing here is a secret.
type CreateCircleWalletResponse struct {
	WalletPubkey     string
	ConnectionPubkey string
	// Relays are the wallet's relays, non-blank, in failover order.
	Relays []string
	// MaxAmountMillis and MaxReceiveMillis are the caps as the Hub resolved them.
	MaxAmountMillis, MaxReceiveMillis uint64
	ExpiresAt                         int64
	FeesPpm                           uint64
	DustThresholdMillis               uint64
	// RotationDelaySecs is nil on a wallet that cannot be rotated.
	RotationDelaySecs *uint64
	BudgetRenewal     string
	// MissingTerms names the required terms the details did not carry. The
	// wallet exists all the same; a client shows them as unknown.
	MissingTerms []string
	// LeakedFields names keys that should never be there: a secret or a URI
	// form in the details, or any field beside encrypted_details.
	LeakedFields []string
	// CapsRaised is a resolved cap above the requested one, which a Hub MUST
	// NOT do.
	CapsRaised bool
}

// requiredTerms are the details' required keys besides wallet_pubkey,
// connection_pubkey and relays, which parseDetails refuses outright.
var requiredTerms = []string{"max_amount", "max_receive", "expires_at", "fees_ppm", "dust_threshold_millis", "budget_renewal"}

// ParseResult reads the join's reply: the details decrypt under the requester's
// key and the Hub pubkey only, carry this join's connection_pubkey, a valid
// wallet_pubkey and at least one usable relay, or the reply is rejected.
// Missing terms, leaked fields and raised caps are reported, never fatal: the
// wallet exists.
func (j *PreparedJoin) ParseResult(data []byte) (*CreateCircleWalletResponse, error) {
	r, err := parseDetails(j.cred, j.HubPubkey, j.ConnectionPubkey, data)
	if err != nil {
		return nil, err
	}
	r.CapsRaised = r.MaxAmountMillis > j.Request.MaxAmount || r.MaxReceiveMillis > j.Request.MaxReceive
	return r, nil
}

func parseDetails(cred Credential, hubPubkey, connectionPubkey string, data []byte) (*CreateCircleWalletResponse, error) {
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("nipcw: reply is not a JSON object: %w", err)
	}
	var ct string
	if raw, ok := outer["encrypted_details"]; !ok || json.Unmarshal(raw, &ct) != nil || ct == "" {
		return nil, fmt.Errorf("nipcw: reply carries no encrypted_details")
	}
	key, err := conversationKey(cred.privKeyHex, hubPubkey)
	if err != nil {
		return nil, err
	}
	plain, err := nip44.Decrypt(ct, key)
	if err != nil {
		return nil, fmt.Errorf("nipcw: details do not decrypt under the Hub connection key: %w", err)
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plain), &inner); err != nil {
		return nil, fmt.Errorf("nipcw: details are not a JSON object: %w", err)
	}
	var d CircleWalletDetails
	if err := json.Unmarshal([]byte(plain), &d); err != nil {
		return nil, fmt.Errorf("nipcw: parse details: %w", err)
	}
	if d.ConnectionPubkey == "" || d.ConnectionPubkey != connectionPubkey {
		return nil, fmt.Errorf("%w: %q, want %q", ErrDetailsConnection, d.ConnectionPubkey, connectionPubkey)
	}
	if !isLowerHex64(d.WalletPubkey) {
		return nil, fmt.Errorf("nipcw: details carry no valid wallet_pubkey")
	}
	var relays []string
	for _, r := range d.Relays {
		if strings.TrimSpace(r) != "" {
			relays = append(relays, r)
		}
	}
	if len(relays) == 0 {
		return nil, fmt.Errorf("nipcw: details carry no usable relay, so the wallet is unreachable")
	}
	resp := &CreateCircleWalletResponse{
		WalletPubkey: d.WalletPubkey, ConnectionPubkey: d.ConnectionPubkey, Relays: relays,
		MaxAmountMillis: d.MaxAmount, MaxReceiveMillis: d.MaxReceive, ExpiresAt: d.ExpiresAt,
		FeesPpm: d.FeesPpm, DustThresholdMillis: d.DustThresholdMillis, RotationDelaySecs: d.RotationDelaySecs,
		BudgetRenewal: d.BudgetRenewal,
	}
	for _, k := range requiredTerms {
		if v, ok := inner[k]; !ok || string(v) == "null" {
			resp.MissingTerms = append(resp.MissingTerms, k)
		}
	}
	for k := range inner {
		if leakyKey(k) {
			resp.LeakedFields = append(resp.LeakedFields, k)
		}
	}
	for k := range outer {
		if k != "encrypted_details" {
			resp.LeakedFields = append(resp.LeakedFields, k)
		}
	}
	sort.Strings(resp.LeakedFields)
	return resp, nil
}

// leakyKey is a key that names a secret or a URI form: whatever it holds would be
// derived from the member's secret, which a Hub never has.
func leakyKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "secret") || strings.Contains(k, "uri")
}

// conversationKey is the NIP-44 conversation key between privKeyHex and the
// x-only pubKeyHex.
func conversationKey(privKeyHex, pubKeyHex string) ([]byte, error) {
	priv, err := utils.ParsePrivateKeyHex(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("nipcw: invalid private key: %w", err)
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("nipcw: derive conversation key: %w", err)
	}
	return key, nil
}

// WalletConnection is a member's own Circle Wallet connection, held as fields:
// the Hub's wallet_pubkey and relays from the details, and the secret the
// member generated and kept. A Circle Wallet has no bech32 or URI form; the
// member's client speaks NIP-47 to it directly.
type WalletConnection struct {
	WalletPubkey string
	Relays       []string
	Secret       string
}
