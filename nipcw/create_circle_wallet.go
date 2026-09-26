package nipcw

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
)

// CreateCircleWalletParams is create_circle_wallet's friendly request —
// self-service request for the caller's own Circle Wallet.
type CreateCircleWalletParams struct {
	Credential Credential
	// MaxAmountMillis is the requested spend cap, MUST NOT exceed the Hub's
	// own per-wallet ceiling. NIP-CW's own wire field is the un-suffixed
	// "max_amount" — it predates, and was deliberately left out of,
	// NIP-CASH's own coin-agnostic "_millis" rename, since a circle isn't
	// coin-agnostic today (NIP-CW §Non-Goals). The Go field here is still
	// named MaxAmountMillis for terminology consistency with nipcash at the
	// SDK layer only — that naming choice doesn't change the wire contract.
	MaxAmountMillis uint64
	// Expiry is OPTIONAL. Zero means "use the Hub's own expiry ceiling."
	Expiry time.Duration
	// BudgetRenewal is OPTIONAL ("daily"/"weekly"/"monthly"/"yearly"/
	// "never"). Empty means "use the Hub's own default (never)." Whether
	// omitted or explicit, the resolved value MUST satisfy the Hub's own
	// renewal floor (NIP-CW §Budget Renewal Floor).
	BudgetRenewal string
}

// CreateCircleWalletRequest is create_circle_wallet's wire request shape.
type CreateCircleWalletRequest struct {
	Pubkey        string `json:"pubkey"`
	MaxAmount     uint64 `json:"max_amount"`
	Expiry        int    `json:"expiry"`
	BudgetRenewal string `json:"budget_renewal,omitempty"`
	IdentityEvent string `json:"identity_event"`
}

// Request builds create_circle_wallet's wire request from p, bound to
// hubPubkey (the Circle Wallet Hub connection's own pubkey — nipcw/client
// supplies this). Exported for nipcw/client's use; a caller using
// nipcw/client's CreateCircleWallet method never calls this directly.
func (p CreateCircleWalletParams) Request(hubPubkey string) (CreateCircleWalletRequest, error) {
	pubkey, err := p.Credential.pubkey()
	if err != nil {
		return CreateCircleWalletRequest{}, err
	}
	proof, err := p.Credential.buildProof(hubPubkey)
	if err != nil {
		return CreateCircleWalletRequest{}, err
	}
	return CreateCircleWalletRequest{
		Pubkey:        pubkey,
		MaxAmount:     p.MaxAmountMillis,
		Expiry:        int(p.Expiry / time.Second),
		BudgetRenewal: p.BudgetRenewal,
		IdentityEvent: string(proof),
	}, nil
}

// createCircleWalletResponseWire is create_circle_wallet's raw wire response.
//
// It carries exactly one field, and that is the security property, not an
// accident: a circle join is made over the *shared* circlehub connection, so the
// NIP-47 response envelope is encrypted only to a key every member of the circle
// holds. Any field placed outside EncryptedDetails is therefore readable by every
// other member — and the worst of those is the joiner's own wallet pubkey, which
// appears in the clear `p` tag of every subsequent call that wallet makes, so a
// co-member who learned it could follow that member for the wallet's whole life.
//
// Nothing may be added here. New fields belong in circleWalletDetailsWire.
type createCircleWalletResponseWire struct {
	EncryptedDetails string `json:"encrypted_details"`
}

// circleWalletDetailsWire is the plaintext inside EncryptedDetails — the
// joining member's own wallet identity and terms, readable only by them.
type circleWalletDetailsWire struct {
	PairingURI    string `json:"pairing_uri"`
	WalletPubkey  string `json:"wallet_pubkey"`
	ExpiresAt     int64  `json:"expires_at"`
	FeesPpm       int    `json:"fees_ppm"`
	BudgetRenewal string `json:"budget_renewal"`
}

// CreateCircleWalletResponse is create_circle_wallet's response, with
// PairingURI already decrypted — connect straight from it.
type CreateCircleWalletResponse struct {
	PairingURI    string
	WalletPubkey  string
	ExpiresAt     int64
	FeesPpm       int
	BudgetRenewal string
}

// ParseResult parses create_circle_wallet's wire response, decrypting
// encrypted_details with p.Credential's own privkey (NIP-44 to the requester's
// own pubkey — NIP-CW §Creating a Circle Wallet — so no other holder of the
// shared Hub connection can read it).
//
// That guarantee now covers the whole result. It previously covered only the
// pairing URI: wallet_pubkey, expires_at, fees_ppm and budget_renewal travelled
// beside the ciphertext, where every other member of the circle could read them.
// The returned CreateCircleWalletResponse is unchanged, so callers see nothing
// of this.
//
// Exported for nipcw/client's use; a caller using nipcw/client's
// CreateCircleWallet method never calls this directly.
func (p CreateCircleWalletParams) ParseResult(hubPubkey string, data []byte) (*CreateCircleWalletResponse, error) {
	var wire createCircleWalletResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	if wire.EncryptedDetails == "" {
		// Either a hub that predates nested details, or a stripped response.
		// Both are indeterminate rather than empty: returning a zero-valued
		// response here would hand the caller a blank wallet pubkey and blank
		// terms that read as real values.
		return nil, fmt.Errorf("nipcw: response carries no encrypted_details")
	}
	plaintext, err := decryptFromPubkey(p.Credential.privKeyHex, hubPubkey, wire.EncryptedDetails)
	if err != nil {
		return nil, fmt.Errorf("nipcw: decrypt wallet details: %w", err)
	}
	var details circleWalletDetailsWire
	if err := json.Unmarshal([]byte(plaintext), &details); err != nil {
		return nil, fmt.Errorf("nipcw: parse wallet details: %w", err)
	}
	return &CreateCircleWalletResponse{
		PairingURI:    details.PairingURI,
		WalletPubkey:  details.WalletPubkey,
		ExpiresAt:     details.ExpiresAt,
		FeesPpm:       details.FeesPpm,
		BudgetRenewal: details.BudgetRenewal,
	}, nil
}

// decryptFromPubkey decrypts a NIP-44 payload keyed to privKeyHex and
// pubKeyHex — the same derivation nip47's own encrypted-response handling
// uses (schnorr.ParsePubKey for the 32-byte x-only nostr pubkey,
// nip44.GenerateConversationKey, nip44.Decrypt). Mirrors nipcash's own
// unexported helper of the same name — small enough (and specific enough to
// each package's own error-wrapping conventions) that a shared package
// isn't worth the indirection.
func decryptFromPubkey(privKeyHex, pubKeyHex, ciphertext string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return "", fmt.Errorf("nipcw: derive decryption key: %w", err)
	}
	return nip44.Decrypt(ciphertext, key)
}
