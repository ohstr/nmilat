package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kinds for the private transport. Contiguous with NIP-47's own 23194-23197 and
// NIP-CASH's 23198/23199, and inside the ephemeral range (20000-29999) so relays
// do not persist a ciphertext archive of every wallet request ever made.
const (
	KindPrivateRequest  = 23190
	KindPrivateResponse = 23191
	KindItemProof       = 23192
	// KindBillProof proves possession of the BILL — that the sender holds its
	// lokicash token — as opposed to KindItemProof, which proves control of a
	// SLICE of it.
	//
	// Two different questions, and the hub needs both. A slice proof is signed by
	// whatever key the signer chooses, so it establishes "I am identity K" and
	// nothing more: anyone can mint a key and sign a structurally perfect slice
	// proof for a wallet pubkey they merely guessed. A bill proof is signed by the
	// token's own connection secret, which only someone who was GIVEN the token
	// can produce.
	//
	// The standard transport had this for free — a request was encrypted to the
	// bill's wallet pubkey, so sending one at all proved possession — and moving
	// to an envelope addressed to the hub's inbox silently dropped it. Everything
	// that needs to distinguish "you hold this bill but not this slice" from "no
	// such bill" depends on it, because without it any such answer confirms a
	// guessed wallet pubkey exists.
	KindBillProof = 23193
)

// EnvelopeVersion is the only version this package emits. Present so a future
// change to the envelope shape is a version bump rather than a guess.
const EnvelopeVersion = 1

// MaxNotAfterWindow bounds how far ahead an envelope may claim to be valid. It
// also bounds the hub's replay-dedupe memory, since a nonce need only be
// remembered until the envelope it belongs to can no longer be accepted.
const MaxNotAfterWindow = 120 * time.Second

// keyHexLen is the length of a hex-encoded 32-byte value: a pubkey, a nonce, or
// a reply tag.
const keyHexLen = 64

var (
	ErrEnvelopeVersion   = errors.New("transport: unsupported envelope version")
	ErrEnvelopeNoItems   = errors.New("transport: envelope carries no items")
	ErrEnvelopeExpired   = errors.New("transport: envelope not_after has passed")
	ErrEnvelopeTooFresh  = errors.New("transport: envelope not_after is too far ahead")
	ErrEnvelopeMalformed = errors.New("transport: envelope is malformed")
	ErrDuplicateItemID   = errors.New("transport: envelope reuses an item id")
	// ErrDuplicateItem rejects two items asking the same thing of the same bill.
	//
	// Distinct ids are not enough. A proof binds target, hub, method, params, nonce
	// and expiry — but NOT the item id — so one signed pair authorizes an arbitrary
	// number of otherwise-identical items, and only each method's own idempotency
	// guard stops the duplicates from executing. That makes the guards the single
	// line of defence, and any bill method added without one inherits a
	// duplicate-execution hole with no warning.
	//
	// Adding the id to the proof binding would fix it at the root and break every
	// signature already in circulation, for something with no live impact. Refusing
	// the duplicate costs nothing and removes the amplifier.
	ErrDuplicateItem = errors.New("transport: envelope repeats an identical item")
)

// Item is one bill operation inside an envelope.
//
// Params stays json.RawMessage rather than a decoded map because ParamsHash must
// be computed over a canonical form, and because the hub hands these bytes
// straight to the existing per-method controllers — a decode/re-encode round trip
// in between would be both wasted work and a chance to alter what the caller
// actually signed for.
type Item struct {
	// ID is client-chosen and need only be unique within the envelope; the
	// response uses it to say which result belongs to which request.
	ID     string          `json:"id"`
	Target string          `json:"target"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	// Proof is the item's own signed kind-23192 event. It is a nested object, not
	// a JSON string: a string would need escaping (costing ~5%) and force every
	// reader through a second parse.
	//
	// omitempty is load-bearing, not tidiness. A nil json.RawMessage without it
	// marshals to `"proof":null`, and decoding that literal yields a FOUR-BYTE
	// value — so `len(Proof) == 0` is false on the far side and a proofless bearer
	// item arrives looking like it carries a proof. Read HasProof rather than the
	// length, which also survives a peer that sends an explicit null anyway.
	Proof json.RawMessage `json:"proof,omitempty"`
	// BillProof is the item's signed kind-23193 bill proof: possession of the
	// bill's token, signed with its connection secret.
	//
	// REQUIRED on every item, whatever the bill's identity mode. A cash-mode item
	// carries no slice Proof (§Bearer Items) but still carries this, because the
	// two answer different questions — the cash secret says which slice, this says
	// which bill the sender actually holds.
	//
	// Same omitempty reasoning as Proof, and the same rule: read HasBillProof, not
	// the length.
	BillProof json.RawMessage `json:"bill_proof,omitempty"`
}

// nullLiteral is what a nil json.RawMessage marshals to when it is not omitted.
var nullLiteral = []byte("null")

// HasProof reports whether this item actually carries a kind-23192 proof.
//
// Not a length check, because JSON gives three different spellings of "no proof":
// absent, empty, and the literal `null`. The last one is the dangerous one — it
// decodes to four bytes, so a length check reads it as a proof that is present and
// unverifiable, and every such item is refused. That made cash-mode bills, which
// are proofless BY DESIGN (§Bearer Items), impossible to serve over this transport
// at all: the failure is an omission, which is information-free, so no caller could
// ever learn why.
func (i Item) HasProof() bool {
	return hasRawValue(i.Proof)
}

// HasBillProof reports whether this item actually carries a kind-23193 bill proof.
// Same null-literal hazard as HasProof; see there.
func (i Item) HasBillProof() bool {
	return hasRawValue(i.BillProof)
}

// hasRawValue is HasProof and HasBillProof's shared test, so the two cannot drift
// on the one detail that has already caused a live outage.
func hasRawValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, nullLiteral)
}

// Envelope is the plaintext inside one private-transport ciphertext.
type Envelope struct {
	Version int `json:"v"`
	// NotAfter is the envelope's own expiry, in unix seconds. The wrapping event's
	// created_at is randomised up to two days into the past (NIP-59), so it says
	// nothing about freshness — replay protection has to live in here.
	NotAfter int64 `json:"not_after"`
	// Nonce is the single value a hub stores to detect replay. Items bind to it,
	// so an item lifted into another envelope fails without any per-item state.
	Nonce string `json:"nonce"`
	// ReplyTo is an opaque routing tag, NOT a pubkey: the response is encrypted
	// under a key derived from the request's own conversation key plus this tag,
	// which saves an ECDH and a signature while still being unlinkable.
	ReplyTo string `json:"reply_to"`
	Items   []Item `json:"items"`
	// Pad is filler so ciphertext length lands on a bucket boundary and stops
	// disclosing how much is inside. Never read.
	Pad string `json:"pad,omitempty"`
}

// NewNonce returns a random 32-byte hex value, for Nonce and ReplyTo.
func NewNonce() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("transport: read randomness: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// CanonicalParamsHash returns the sha256, hex-encoded, of an item's params in a
// canonical form: object keys sorted, insignificant whitespace removed, numbers
// left exactly as written.
//
// Canonicalising rather than hashing the received bytes is deliberate. The bytes
// do travel verbatim inside the ciphertext today, so hashing them raw would work
// — but it would silently make the binding depend on nothing ever re-serialising
// params along the way, and the moment something did, every proof would fail with
// no indication why. Numbers are preserved via json.Number because an amount in
// millis can exceed float64's exact integer range, and rounding one during
// canonicalisation would change what the caller signed for.
func CanonicalParamsHash(params json.RawMessage) (string, error) {
	canonical, err := canonicalJSON(params)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		// An item with no params still needs a stable hash, so the absent and
		// empty-object cases must agree on one representation.
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("transport: params are not valid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: params carry trailing content", ErrEnvelopeMalformed)
	}
	// json.Marshal sorts map keys, which is what makes this canonical.
	out, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("transport: canonicalise params: %w", err)
	}
	return out, nil
}

// VerificationCost reports how many signature verifications this item will demand
// if it is processed: its own transport proof, plus any nested per-source proofs
// its params declare.
//
// Counted structurally, from the shape of the params, so an envelope's total cost
// is known BEFORE any crypto runs. That ordering is the whole point: a caller must
// not be able to make the hub spend a second of secp256k1 time and only then be
// told the envelope was over budget.
func (i Item) VerificationCost() int {
	// Every item carries a kind-23193 bill proof, whatever its identity mode, so
	// that signature is unconditional. Undercounting it would let a batch of
	// cash-mode items — each previously counted as free — spend far more
	// secp256k1 time than the hub's budget believed it had authorised.
	cost := 1 // the kind-23193 bill proof
	if !i.IsBearer() {
		// Plus the kind-23192 slice proof. A cash-mode item carries none: its
		// secret IS the slice authorization, so there is no second signature.
		// Counting a phantom verification would make a hub's budget refuse batches
		// it could actually serve.
		cost++
	}

	// cash_consolidate is the only method carrying nested proofs today: one per
	// source, plus an attestation for a connection_key source.
	var params struct {
		Sources []struct {
			IdentityEvent    string `json:"identity_event"`
			AttestationEvent string `json:"attestation_event"`
		} `json:"sources"`
	}
	// A params body that will not decode costs nothing extra to count; it fails
	// later, on its own terms.
	if err := json.Unmarshal(i.Params, &params); err != nil {
		return cost
	}
	for _, source := range params.Sources {
		if source.IdentityEvent != "" {
			cost++
		}
		if source.AttestationEvent != "" {
			cost++
		}
	}
	return cost
}

// SourceCount reports how many consolidate sources an item declares, for checking
// against Limits.MaxConsolidateSources. Zero for every other method.
// IsBearer reports whether this item authorizes with a cash secret rather than a
// signature — a cash-mode ("bearer") bill.
//
// Such an item legitimately carries NO kind-23192 proof, because a cash credential
// has no keypair to sign one with. NIP-CASH permits this for the private transport
// specifically: the binding a proof provides adds nothing here, since anyone holding
// the envelope already holds the secret and could spend it regardless. (The reason
// cash-mode sources are banned from cash_consolidate does not apply — that ban is
// about a secret sitting in a request readable by co-recipients of a SHARED calling
// connection, and this transport has no shared calling connection: it encrypts to
// the hub's inbox alone.)
//
// Inferred from params rather than flagged separately, for the same reason
// SourceCount is: a separate flag could disagree with the params it describes, and
// the params are what the hub acts on.
func (i Item) IsBearer() bool {
	var params struct {
		CashSecret string `json:"cash_secret"`
	}
	if err := json.Unmarshal(i.Params, &params); err != nil {
		return false
	}
	return params.CashSecret != ""
}

func (i Item) SourceCount() int {
	var params struct {
		Sources []json.RawMessage `json:"sources"`
	}
	if err := json.Unmarshal(i.Params, &params); err != nil {
		return 0
	}
	return len(params.Sources)
}

// Encode serialises the envelope, pads it to a bucket boundary and returns the
// plaintext to hand to NIP-44.
//
// Every limit is enforced here as well as on receipt, so a client learns locally
// that its batch is too large instead of publishing an event the hub will drop —
// a drop it would experience as silence.
func (e Envelope) Encode(limits Limits) ([]byte, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if err := e.check(limits); err != nil {
		return nil, err
	}

	e.Pad = "" // never trust an incoming pad; recompute
	body, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal envelope: %w", err)
	}

	// Padding is a JSON string field, so the filler has to account for the bytes
	// the field itself adds. Solve it directly rather than looping.
	const padFieldOverhead = len(`,"pad":""`)
	target, err := limits.PaddedSize(len(body) + padFieldOverhead)
	if err != nil {
		return nil, err
	}
	fill := target - len(body) - padFieldOverhead
	if fill < 0 {
		fill = 0
	}
	e.Pad = strings.Repeat("0", fill)

	padded, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal padded envelope: %w", err)
	}
	if len(padded) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: %d bytes after padding, limit %d",
			ErrEnvelopeTooLarge, len(padded), limits.MaxEnvelopeBytes)
	}
	return padded, nil
}

// Decode parses and checks an envelope plaintext against limits.
//
// Checks run cheapest-first and structurally only: size, version, item count,
// tags, then the verification budget. No signature is verified and no database is
// touched here, so rejecting a hostile envelope stays cheap.
func Decode(plaintext []byte, limits Limits) (*Envelope, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(plaintext) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d",
			ErrEnvelopeTooLarge, len(plaintext), limits.MaxEnvelopeBytes)
	}

	var e Envelope
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelopeMalformed, err)
	}
	if err := e.check(limits); err != nil {
		return nil, err
	}
	return &e, nil
}

// check holds the rules Encode and Decode share, so a client cannot build
// something the hub would refuse.
func (e Envelope) check(limits Limits) error {
	if e.Version != EnvelopeVersion {
		return fmt.Errorf("%w: %d", ErrEnvelopeVersion, e.Version)
	}
	if len(e.Nonce) != keyHexLen || !isLowerHex(e.Nonce) {
		return fmt.Errorf("%w: nonce must be %d lowercase hex characters", ErrEnvelopeMalformed, keyHexLen)
	}
	if len(e.ReplyTo) != keyHexLen || !isLowerHex(e.ReplyTo) {
		return fmt.Errorf("%w: reply_to must be %d lowercase hex characters", ErrEnvelopeMalformed, keyHexLen)
	}
	if len(e.Items) == 0 {
		return ErrEnvelopeNoItems
	}
	if len(e.Items) > limits.MaxItems {
		return fmt.Errorf("%w: %d items, limit %d", ErrTooManyItems, len(e.Items), limits.MaxItems)
	}

	seen := make(map[string]struct{}, len(e.Items))
	seenItems := make(map[string]string, len(e.Items))
	budget := 0
	for i, item := range e.Items {
		if item.ID == "" {
			return fmt.Errorf("%w: item %d has no id", ErrEnvelopeMalformed, i)
		}
		// Bounded because the REPLY echoes every id back alongside the result bodies,
		// so an id that fits in the request need not fit in the answer — see
		// MaxItemIDBytes. Deliberately not quoting the id in this error: an uncapped id
		// is exactly the thing being refused, and echoing it would write the
		// attacker's 48 KiB string into the log line that reports it.
		if len(item.ID) > MaxItemIDBytes {
			return fmt.Errorf("%w: item %d has a %d-byte id, over the %d limit",
				ErrEnvelopeMalformed, i, len(item.ID), MaxItemIDBytes)
		}
		if _, dup := seen[item.ID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateItemID, item.ID)
		}
		seen[item.ID] = struct{}{}

		// Same bill, same method, same params is the same request. Two of them in one
		// envelope can only ever mean a replay of a signed item, since the second
		// cannot succeed at anything the first did not already do.
		//
		// Keyed on the params HASH rather than the raw bytes so that a
		// re-serialisation with different whitespace or key order is still caught —
		// it is the same hash the proof itself binds, so this matches exactly the set
		// of items one signature covers. Different params (two transfers of different
		// amounts on one bill) hash differently and stay legal, which is the whole
		// point of batching.
		paramsHash, hashErr := CanonicalParamsHash(item.Params)
		if hashErr != nil {
			return fmt.Errorf("%w: item %q params: %v", ErrEnvelopeMalformed, item.ID, hashErr)
		}
		fingerprint := item.Target + "\x00" + item.Method + "\x00" + paramsHash
		if prior, dup := seenItems[fingerprint]; dup {
			return fmt.Errorf("%w: items %q and %q", ErrDuplicateItem, prior, item.ID)
		}
		seenItems[fingerprint] = item.ID

		if len(item.Target) != keyHexLen || !isLowerHex(item.Target) {
			return fmt.Errorf("%w: item %q target must be %d lowercase hex characters",
				ErrEnvelopeMalformed, item.ID, keyHexLen)
		}
		if item.Method == "" {
			return fmt.Errorf("%w: item %q has no method", ErrEnvelopeMalformed, item.ID)
		}
		// A proof is required EXCEPT for a cash-mode item, which has no signing key
		// to make one with — its secret, carried in params, is the whole
		// authorization (NIP-CASH §Bearer Items). Note this check is a client-side
		// coherence aid only: a hub decides what a bill actually is from its own
		// records, never from what the item claims, so omitting a proof cannot be
		// used to escape authorization on an identity-bound bill.
		if !item.HasProof() && !item.IsBearer() {
			return fmt.Errorf("%w: item %q has no proof and carries no cash secret",
				ErrEnvelopeMalformed, item.ID)
		}
		// A BILL proof is required unconditionally — cash-mode included. The slice
		// proof above says which slice; this says the sender holds the bill at all,
		// and no identity mode exempts an item from it.
		//
		// Same caveat as above: client-side coherence only. The hub verifies this
		// itself and omits anything that fails, because a client-side check cannot
		// be an authorization boundary.
		if !item.HasBillProof() {
			return fmt.Errorf("%w: item %q has no bill proof", ErrEnvelopeMalformed, item.ID)
		}
		if sources := item.SourceCount(); sources > limits.MaxConsolidateSources {
			return fmt.Errorf("%w: item %q declares %d sources, limit %d",
				ErrTooManyItems, item.ID, sources, limits.MaxConsolidateSources)
		}
		budget += item.VerificationCost()
	}

	if budget > limits.MaxVerifyBudget {
		return fmt.Errorf("%w: %d verifications, limit %d",
			ErrVerifyBudgetExceeded, budget, limits.MaxVerifyBudget)
	}
	return nil
}

// CheckFreshness validates not_after against now. Kept separate from check so a
// client can build an envelope without its own clock deciding validity, while the
// hub still refuses a stale or absurdly long-lived one.
func (e Envelope) CheckFreshness(now time.Time) error {
	notAfter := time.Unix(e.NotAfter, 0)
	if now.After(notAfter) {
		return fmt.Errorf("%w: expired at %s", ErrEnvelopeExpired, notAfter.UTC().Format(time.RFC3339))
	}
	if notAfter.Sub(now) > MaxNotAfterWindow {
		return fmt.Errorf("%w: valid for %s, maximum %s",
			ErrEnvelopeTooFresh, notAfter.Sub(now), MaxNotAfterWindow)
	}
	return nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
