package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// Tag names on a kind-23192 item proof. Single letters to keep an item small,
// following NIP-CASH's own kind-23198 convention.
const (
	tagTarget     = "d"  // the wallet this item acts on
	tagHub        = "h"  // the hub's x-only identity: no cross-hub replay
	tagMethod     = "m"  // the method: no method substitution
	tagParamsHash = "ph" // sha256 of canonical params: no params substitution
	tagEnvelope   = "en" // the envelope nonce: no lifting into another envelope
	tagExpiration = "expiration"
)

// ProofFreshnessPast and ProofFreshnessFuture bound a proof's created_at. They
// match NIP-CW's kind-23199 window so a caller's clock tolerance is the same
// everywhere in this protocol family.
const (
	ProofFreshnessPast   = 5 * time.Minute
	ProofFreshnessFuture = 1 * time.Minute
)

var (
	ErrProofMalformed   = errors.New("transport: item proof is malformed")
	ErrProofWrongTarget = errors.New("transport: item proof is bound to a different wallet")
	ErrProofWrongHub    = errors.New("transport: item proof is bound to a different hub")
	ErrProofWrongMethod = errors.New("transport: item proof is bound to a different method")
	ErrProofWrongParams = errors.New("transport: item proof is bound to different params")
	ErrProofWrongNonce  = errors.New("transport: item proof is bound to a different envelope")
	ErrProofStale       = errors.New("transport: item proof is outside its freshness window")
	ErrProofSignature   = errors.New("transport: item proof signature is invalid")
)

// ProofBinding is everything an item proof commits to. Every field is a separate
// substitution an aggregator could otherwise perform.
//
// The reason all of this is bound, rather than just the target: one envelope
// carries items owned by DIFFERENT parties, so whoever assembles it is holding
// other people's signed proofs. Without the params hash they could re-point
// someone's cash_redeem at their own invoice; without the envelope nonce they
// could bank a proof and replay it later; without the method they could turn a
// status read into a transfer. NIP-CASH's own kind-23198 proofs already bind
// bolt11_hash and new_identity_hash for exactly this reason.
type ProofBinding struct {
	Target     string
	HubXOnly   string
	Method     string
	ParamsHash string
	Nonce      string
	NotAfter   int64
}

func (b ProofBinding) tags() [][]string {
	return [][]string{
		{tagTarget, b.Target},
		{tagHub, b.HubXOnly},
		{tagMethod, b.Method},
		{tagParamsHash, b.ParamsHash},
		{tagEnvelope, b.Nonce},
		{tagExpiration, fmt.Sprintf("%d", b.NotAfter)},
	}
}

// BuildItemProof signs a kind-23192 SLICE proof for one item. privKeyHex is the
// key that identifies the recipient — their own signing identity for a
// pubkey-bound slice — so the proof establishes "I am identity K".
//
// It deliberately does NOT establish that the signer holds the bill: the key is
// the signer's own choice, so anyone can produce a structurally valid proof for
// any target they can name. BuildBillProof is what demonstrates possession.
func BuildItemProof(privKeyHex string, binding ProofBinding) (json.RawMessage, error) {
	return buildProof(KindItemProof, "slice", privKeyHex, binding)
}

// BuildBillProof signs a kind-23193 BILL proof for one item. connSecretHex is the
// bill's own connection secret, straight out of its token — holding it is exactly
// what the proof demonstrates, and nothing else can produce it.
//
// Bound to the same six fields as the slice proof, so it is per-item and cannot be
// lifted onto a different item, method, params, envelope or hub. An aggregator
// assembling an envelope holds other people's bill proofs; binding them this
// tightly is what stops one being reused to probe a bill its holder never asked
// about.
func BuildBillProof(connSecretHex string, binding ProofBinding) (json.RawMessage, error) {
	return buildProof(KindBillProof, "bill", connSecretHex, binding)
}

func buildProof(kind int, what, privKeyHex string, binding ProofBinding) (json.RawMessage, error) {
	if binding.Target == "" || binding.HubXOnly == "" || binding.Method == "" ||
		binding.ParamsHash == "" || binding.Nonce == "" {
		return nil, fmt.Errorf("%w: every binding field is required", ErrProofMalformed)
	}
	ev, err := nip01.NewSignedEvent(kind, "", privKeyHex, binding.tags()...)
	if err != nil {
		return nil, fmt.Errorf("transport: sign %s proof: %w", what, err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal %s proof: %w", what, err)
	}
	return raw, nil
}

// VerifyItemProof checks one item's proof against the binding the hub computed
// itself, and returns the pubkey that signed it — the connection key the hub then
// looks up.
//
// Order is deliberate and is the hub's DoS posture: every structural comparison
// runs first, and the signature (measured at ~373us, by far the most expensive
// thing here) is verified last. A proof that fails any binding therefore costs a
// few string comparisons, not secp256k1 time.
//
// Shared by hub and client so the two cannot disagree on what a valid proof is.
func VerifyItemProof(proof json.RawMessage, want ProofBinding, now time.Time) (signerPubkey string, err error) {
	return verifyProof(KindItemProof, proof, want, now)
}

// VerifyBillProof checks one item's kind-23193 bill proof and returns the pubkey
// that signed it — which the hub compares against the bill's own connection
// pubkey.
//
// Identical checks to the slice proof, including the expected KIND. That last
// point is load-bearing rather than incidental: the two proofs bind to the same
// six fields, so without a kind check a slice proof would verify as a bill proof
// and possession would be provable by anyone holding a key. The kind is the only
// thing separating them.
func VerifyBillProof(proof json.RawMessage, want ProofBinding, now time.Time) (signerPubkey string, err error) {
	return verifyProof(KindBillProof, proof, want, now)
}

func verifyProof(wantKind int, proof json.RawMessage, want ProofBinding, now time.Time) (signerPubkey string, err error) {
	var ev nip01.Event
	if err := json.Unmarshal(proof, &ev); err != nil {
		return "", fmt.Errorf("%w: %v", ErrProofMalformed, err)
	}
	if ev.Kind != wantKind {
		return "", fmt.Errorf("%w: kind %d, want %d", ErrProofMalformed, ev.Kind, wantKind)
	}
	if len(ev.PubKey) != keyHexLen || !isLowerHex(ev.PubKey) {
		return "", fmt.Errorf("%w: signer pubkey must be %d lowercase hex characters",
			ErrProofMalformed, keyHexLen)
	}

	got, err := proofTags(ev.Tags)
	if err != nil {
		return "", err
	}

	// Cheapest first, and each with its own error so a caller can tell which
	// substitution was attempted.
	if got[tagTarget] != want.Target {
		return "", fmt.Errorf("%w: bound to %q, item targets %q", ErrProofWrongTarget, got[tagTarget], want.Target)
	}
	if got[tagHub] != want.HubXOnly {
		return "", fmt.Errorf("%w: bound to %q", ErrProofWrongHub, got[tagHub])
	}
	if got[tagMethod] != want.Method {
		return "", fmt.Errorf("%w: bound to %q, item calls %q", ErrProofWrongMethod, got[tagMethod], want.Method)
	}
	if got[tagParamsHash] != want.ParamsHash {
		return "", ErrProofWrongParams
	}
	if got[tagEnvelope] != want.Nonce {
		return "", ErrProofWrongNonce
	}

	created := time.Unix(int64(ev.CreatedAt), 0) //nolint:gosec // event timestamps are seconds since epoch
	if created.Before(now.Add(-ProofFreshnessPast)) || created.After(now.Add(ProofFreshnessFuture)) {
		return "", fmt.Errorf("%w: created_at %s, now %s",
			ErrProofStale, created.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}

	// Last, and only now: the ID must be the event's own hash and the signature
	// must verify. WithoutPowCheck because an item proof never travels as its own
	// relay event, so a nonce tag on it would be meaningless.
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return "", fmt.Errorf("%w: %v", ErrProofSignature, err)
	}
	return ev.PubKey, nil
}

// proofTags collects the binding tags, rejecting a duplicate rather than letting
// the last or first occurrence win. A proof carrying two different "m" tags is
// ambiguous about what it authorises, and an implementation that quietly picked
// one would be a substitution vector of its own.
func proofTags(tags [][]string) (map[string]string, error) {
	out := make(map[string]string, len(proofRequiredTags))
	for _, tag := range tags {
		if len(tag) < 2 {
			continue
		}
		name := tag[0]
		if !proofRequiredTags[name] {
			continue
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicate %q tag", ErrProofMalformed, name)
		}
		out[name] = tag[1]
	}
	for name := range proofRequiredTags {
		if out[name] == "" {
			return nil, fmt.Errorf("%w: missing %q tag", ErrProofMalformed, name)
		}
	}
	return out, nil
}

var proofRequiredTags = map[string]bool{
	tagTarget:     true,
	tagHub:        true,
	tagMethod:     true,
	tagParamsHash: true,
	tagEnvelope:   true,
}
