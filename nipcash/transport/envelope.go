package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

// EnvelopeVersion is kept for source compatibility only. The envelope and the
// response carry no version on the wire since nips 631341c; the Version fields
// are never written or read.
const EnvelopeVersion = 1

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
	// Version is never on the wire (see EnvelopeVersion).
	Version int `json:"-"`
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

	// Rejected lists the items Decode dropped as structurally unservable. Never
	// on the wire. Each item is authorized on its own (NIP-CASH §Batching Across
	// Bills), so one bad item is omitted rather than failing its co-items.
	Rejected []ItemRejection `json:"-"`
}

// ItemRejection is one item Decode dropped: its position in the received
// envelope and why. The id is not kept, since an oversized id is itself a
// reason for rejection.
type ItemRejection struct {
	Index int
	Err   error
	// Code is the item error a Hub answers with, when the item is answered rather
	// than omitted: QUOTA_EXCEEDED for a consolidate over max_consolidate_sources.
	// Empty for a structural (I1) omission.
	Code string
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
// left exactly as written, strings serialized as RFC 8785 does (NIP-CASH §Item
// Proofs).
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
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, fmt.Errorf("transport: canonicalise params: %w", err)
	}
	return out.Bytes(), nil
}

// writeCanonical writes v in NIP-CASH's canonical form: keys sorted, no
// insignificant whitespace, numbers verbatim, strings as RFC 8785 writes them.
// Not json.Marshal: it escapes <, >, &, U+2028 and U+2029, so its hash differs
// from any implementation following the spec.
func writeCanonical(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(v.String())
	case string:
		writeCanonicalString(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, elem := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value of type %T", v)
	}
	return nil
}

// writeCanonicalString writes s as RFC 8785 does: only ", \ and control
// characters below U+0020 are escaped, as \b \t \n \f \r or else lowercase
// \u00XX; every other character is literal UTF-8. The decoder has already
// replaced invalid UTF-8, so s is valid.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
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
	// that signature is unconditional.
	cost := 1
	if i.HasProof() {
		cost++ // the kind-23192 item proof
	}
	// Every signed event the params carry costs one: a claim proof
	// (identity_event, a 23198 or a join's 23199), an attestation (35522), a
	// withdraw quote (23187), and each source's own pair for a consolidate.
	var params struct {
		IdentityEvent    json.RawMessage   `json:"identity_event"`
		AttestationEvent json.RawMessage   `json:"attestation_event"`
		Quote            json.RawMessage   `json:"quote"`
		Sources          []json.RawMessage `json:"sources"`
	}
	if err := json.Unmarshal(i.Params, &params); err != nil {
		return cost
	}
	cost += countSigned(params.IdentityEvent) + countSigned(params.AttestationEvent) + countSigned(params.Quote)
	for _, raw := range params.Sources {
		var source struct {
			IdentityEvent    json.RawMessage `json:"identity_event"`
			AttestationEvent json.RawMessage `json:"attestation_event"`
		}
		if json.Unmarshal(raw, &source) != nil {
			continue // a non-object element costs nothing
		}
		cost += countSigned(source.IdentityEvent) + countSigned(source.AttestationEvent)
	}
	return cost
}

// countSigned is 1 for a present, non-empty event value (a JSON string or
// object), 0 for an absent, null or empty one.
func countSigned(raw json.RawMessage) int {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, nullLiteral) || bytes.Equal(t, []byte(`""`)) {
		return 0
	}
	return 1
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

// Decode parses an envelope plaintext for a Hub that has already classified it
// (ClassifyEnvelope: E1 to E6). It omits only what I1 makes a structural
// omission (ItemShapeOK fails) and reports a consolidate over
// max_consolidate_sources with Code QUOTA_EXCEEDED; every other item is kept,
// proofless, secretless or repeated ones included, for the Hub's own steps (I2
// onward) to decide. An envelope whose items are all omitted decodes with no
// items: the Hub still answers it, with "results": [].
//
// The header checks repeat E4/E5 so a caller using Decode alone cannot run a
// malformed envelope; the budget counts the kept items.
func Decode(plaintext []byte, limits Limits) (*Envelope, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(plaintext) > limits.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d",
			ErrEnvelopeTooLarge, len(plaintext), limits.MaxEnvelopeBytes)
	}
	var wire struct {
		NotAfter int64             `json:"not_after"`
		Nonce    string            `json:"nonce"`
		ReplyTo  string            `json:"reply_to"`
		Items    []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelopeMalformed, err)
	}
	e := Envelope{Version: EnvelopeVersion, NotAfter: wire.NotAfter, Nonce: wire.Nonce, ReplyTo: wire.ReplyTo}
	if len(e.Nonce) != keyHexLen || !isLowerHex(e.Nonce) {
		return nil, fmt.Errorf("%w: nonce must be %d lowercase hex characters", ErrEnvelopeMalformed, keyHexLen)
	}
	if len(e.ReplyTo) != keyHexLen || !isLowerHex(e.ReplyTo) {
		return nil, fmt.Errorf("%w: reply_to must be %d lowercase hex characters", ErrEnvelopeMalformed, keyHexLen)
	}
	if len(wire.Items) == 0 {
		return nil, ErrEnvelopeNoItems
	}
	if len(wire.Items) > limits.MaxItems {
		return nil, fmt.Errorf("%w: %d items, limit %d", ErrTooManyItems, len(wire.Items), limits.MaxItems)
	}
	if duplicateItemIDs(wire.Items) {
		return nil, fmt.Errorf("%w: two items share an id", ErrDuplicateItemID)
	}
	for i, raw := range wire.Items {
		if !ItemShapeOK(raw) {
			e.Rejected = append(e.Rejected, ItemRejection{Index: i, Err: fmt.Errorf("%w: item %d is not well formed", ErrEnvelopeMalformed, i)})
			continue
		}
		var item Item
		if err := json.Unmarshal(raw, &item); err != nil {
			e.Rejected = append(e.Rejected, ItemRejection{Index: i, Err: fmt.Errorf("%w: %v", ErrEnvelopeMalformed, err)})
			continue
		}
		if sources := item.SourceCount(); sources > limits.MaxConsolidateSources {
			e.Rejected = append(e.Rejected, ItemRejection{Index: i, Code: "QUOTA_EXCEEDED",
				Err: fmt.Errorf("%w: item %q declares %d sources, limit %d", ErrTooManyItems, item.ID, sources, limits.MaxConsolidateSources)})
			continue
		}
		e.Items = append(e.Items, item)
	}
	if err := checkBudget(e.Items, limits); err != nil {
		return nil, err
	}
	return &e, nil
}

// ItemShapeOK is I1: an item is a JSON object with string id, target and method,
// and params absent, null or an object. Anything else is omitted.
func ItemShapeOK(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return false
	}
	for _, name := range []string{"id", "target", "method"} {
		var s string
		if v, ok := fields[name]; !ok || json.Unmarshal(v, &s) != nil {
			return false
		}
	}
	if p, ok := fields["params"]; ok {
		t := bytes.TrimSpace(p)
		if !bytes.Equal(t, nullLiteral) && (len(t) == 0 || t[0] != '{') {
			return false
		}
	}
	return true
}

// duplicateItemIDs reports two items, of whatever shape, carrying one string id.
func duplicateItemIDs(items []json.RawMessage) bool {
	seen := make(map[string]bool, len(items))
	for _, raw := range items {
		var it struct {
			ID *string `json:"id"`
		}
		if json.Unmarshal(raw, &it) != nil || it.ID == nil {
			continue
		}
		if seen[*it.ID] {
			return true
		}
		seen[*it.ID] = true
	}
	return false
}

// check holds the rules Encode and Decode share, so a client cannot build
// something the hub would refuse. Encode is strict: any bad item fails it.
func (e Envelope) check(limits Limits) error {
	if err := e.checkHeader(limits); err != nil {
		return err
	}
	kept, rejected := e.checkItems(limits)
	if len(rejected) > 0 {
		return rejected[0].Err
	}
	return checkBudget(kept, limits)
}

// checkHeader holds the envelope-level rules: a failure here leaves no item that
// could be answered.
func (e Envelope) checkHeader(limits Limits) error {
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
	return nil
}

// checkItems splits e.Items into those that pass every per-item rule and those
// that do not. Every item sharing an id is rejected, since a reply to that id
// could not say which one it answers; a repeat of an identical item is rejected
// and the first kept.
func (e Envelope) checkItems(limits Limits) (kept []Item, rejected []ItemRejection) {
	idCount := make(map[string]int, len(e.Items))
	for _, item := range e.Items {
		idCount[item.ID]++
	}
	seenItems := make(map[string]string, len(e.Items))
	for i, item := range e.Items {
		paramsHash, err := checkItem(i, item, limits)
		if err == nil && idCount[item.ID] > 1 {
			err = fmt.Errorf("%w: %q", ErrDuplicateItemID, item.ID)
		}
		if err == nil {
			// Same bill, same method, same params is the same request. Two of them in
			// one envelope can only ever mean a replay of a signed item, since the
			// second cannot succeed at anything the first did not already do.
			//
			// Keyed on the params HASH rather than the raw bytes so that a
			// re-serialisation with different whitespace or key order is still caught
			// — it is the same hash the proof itself binds, so this matches exactly
			// the set of items one signature covers. Different params (two transfers
			// of different amounts on one bill) hash differently and stay legal,
			// which is the whole point of batching.
			fingerprint := item.Target + "\x00" + item.Method + "\x00" + paramsHash
			if prior, dup := seenItems[fingerprint]; dup {
				err = fmt.Errorf("%w: items %q and %q", ErrDuplicateItem, prior, item.ID)
			} else {
				seenItems[fingerprint] = item.ID
			}
		}
		if err != nil {
			rejected = append(rejected, ItemRejection{Index: i, Err: err})
			continue
		}
		kept = append(kept, item)
	}
	return kept, rejected
}

// checkItem holds the rules one item must pass on its own, and returns its
// canonical params hash.
func checkItem(i int, item Item, limits Limits) (string, error) {
	if item.ID == "" {
		return "", fmt.Errorf("%w: item %d has no id", ErrEnvelopeMalformed, i)
	}
	// Bounded because the REPLY echoes every id back alongside the result bodies,
	// so an id that fits in the request need not fit in the answer — see
	// MaxItemIDBytes. Deliberately not quoting the id in this error: an uncapped id
	// is exactly the thing being refused, and echoing it would write the
	// attacker's 48 KiB string into the log line that reports it.
	if len(item.ID) > MaxItemIDBytes {
		return "", fmt.Errorf("%w: item %d has a %d-byte id, over the %d limit",
			ErrEnvelopeMalformed, i, len(item.ID), MaxItemIDBytes)
	}
	paramsHash, err := CanonicalParamsHash(item.Params)
	if err != nil {
		return "", fmt.Errorf("%w: item %q params: %v", ErrEnvelopeMalformed, item.ID, err)
	}
	if len(item.Target) != keyHexLen || !isLowerHex(item.Target) {
		return "", fmt.Errorf("%w: item %q target must be %d lowercase hex characters",
			ErrEnvelopeMalformed, item.ID, keyHexLen)
	}
	if item.Method == "" {
		return "", fmt.Errorf("%w: item %q has no method", ErrEnvelopeMalformed, item.ID)
	}
	// The I8 shapes a Hub refuses (NIP-CASH §Serving an Envelope): never both a
	// proof and a cash_secret; a spend carries one of them; cash_status and
	// cash_withdraw_quote carry no secret, and with neither are served on the
	// bill proof alone for a cash-mode slice. Client-side coherence only: a Hub
	// decides from its own records.
	if !BearerShapeOK(item.Method, item.HasProof(), item.IsBearer()) {
		return "", fmt.Errorf("%w: item %q has a proof and cash_secret combination %s refuses",
			ErrEnvelopeMalformed, item.ID, item.Method)
	}
	// A BILL proof is required unconditionally — cash-mode included. The slice
	// proof above says which slice; this says the sender holds the bill at all,
	// and no identity mode exempts an item from it.
	//
	// Same caveat as above: client-side coherence only. The hub verifies this
	// itself and omits anything that fails, because a client-side check cannot
	// be an authorization boundary.
	if !item.HasBillProof() {
		return "", fmt.Errorf("%w: item %q has no bill proof", ErrEnvelopeMalformed, item.ID)
	}
	if sources := item.SourceCount(); sources > limits.MaxConsolidateSources {
		return "", fmt.Errorf("%w: item %q declares %d sources, limit %d",
			ErrTooManyItems, item.ID, sources, limits.MaxConsolidateSources)
	}
	return paramsHash, nil
}

// checkBudget bounds the signature verifications items would cost the hub.
func checkBudget(items []Item, limits Limits) error {
	budget := 0
	for _, item := range items {
		budget += item.VerificationCost()
	}
	if budget > limits.MaxVerifyBudget {
		return fmt.Errorf("%w: %d verifications, limit %d",
			ErrVerifyBudgetExceeded, budget, limits.MaxVerifyBudget)
	}
	return nil
}

// CheckFreshness is a Hub's deadline check of an envelope's not_after against
// its horizon H (NIP-CASH §Deadlines): passed (now > not_after) and more than H
// ahead are refused; exactly H ahead is accepted.
func CheckFreshness(e Envelope, now time.Time, horizon int64) error {
	n := now.Unix()
	if n > e.NotAfter {
		return fmt.Errorf("%w: expired at %d", ErrEnvelopeExpired, e.NotAfter)
	}
	if e.NotAfter > n+horizon {
		return fmt.Errorf("%w: not_after %d is more than %d s past %d", ErrEnvelopeTooFresh, e.NotAfter, horizon, n)
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
