// Package nipOA implements NIP-OA: Owner Attestation, an optional "auth"
// tag by which an owner key authorizes an agent key to publish events
// under the agent's own authorship. This package is a pure tag-format and
// cryptographic-verification library: it has no dependency on relay/ and
// performs no relay-side behavior of its own. Per the spec, "Relays
// require no changes to support this NIP... Relays MUST NOT be required
// to verify an auth tag" -- verification is something a client, or
// (per NIP-AA) a relay implementing a different NIP, chooses to do with
// the functions here.
//
// An event carrying a valid auth tag remains authored solely by its own
// pubkey; this package does not define impersonation, key derivation, or
// author rewriting of any kind.
package nipOA

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/utils"
)

// TagName is the tag name this package parses: ["auth", owner, conditions, sig].
const TagName = "auth"

// domainSeparator is prefixed to every signing preimage, byte-for-byte, so
// an owner's signature over an agent-auth preimage can never be replayed
// as a signature over some other protocol's message.
const domainSeparator = "nostr:agent-auth:"

const (
	maxKindValue      = 65535
	maxCreatedAtValue = 4294967295
)

// Failure modes, for callers that need to distinguish them (e.g. via
// errors.Is) rather than match on message text.
var (
	ErrMultipleAuthTags            = errors.New("nipoa: multiple auth tags")
	ErrWrongElementCount           = errors.New("nipoa: auth tag must have exactly 4 elements")
	ErrInvalidOwnerPubkey          = errors.New("nipoa: invalid owner pubkey")
	ErrInvalidSignatureHex         = errors.New("nipoa: invalid signature hex")
	ErrSelfAttestation             = errors.New("nipoa: owner pubkey must not equal event pubkey")
	ErrMalformedConditions         = errors.New("nipoa: malformed conditions")
	ErrUnsupportedClause           = errors.New("nipoa: unsupported condition clause")
	ErrSignatureVerificationFailed = errors.New("nipoa: signature verification failed")
)

// Conditions is the parsed form of an auth tag's <conditions> string: zero
// or more clauses, each either kind=<n>, created_at<t>, or created_at>t,
// conjunctive -- an event (or, per NIP-AA, an AUTH event's own timestamp)
// must satisfy every clause.
//
// Raw is retained verbatim because the signing preimage is built from the
// exact <conditions> string bytes -- per spec, implementations MUST NOT
// reorder, deduplicate, normalize, or canonicalize it before computing the
// preimage. Preimage uses Raw, never a reserialization of the parsed
// Kinds/CreatedAtLT/CreatedAtGT fields.
type Conditions struct {
	Kinds       []int
	CreatedAtLT []uint64
	CreatedAtGT []uint64
	Raw         string
}

// EvaluateKind reports whether kind satisfies every kind= clause
// (vacuously true if there are none). Multiple kind= clauses are
// conjunctive per spec -- "kind=1&kind=7" can never be satisfied by any
// single event, since no event has two kinds at once. That is a footgun
// for whoever issues such a credential, not a bug in this evaluation.
func (c Conditions) EvaluateKind(kind int) bool {
	for _, k := range c.Kinds {
		if kind != k {
			return false
		}
	}
	return true
}

// EvaluateTimeClauses reports whether createdAt satisfies every
// created_at</created_at> clause (vacuously true if there are none).
func (c Conditions) EvaluateTimeClauses(createdAt uint64) bool {
	for _, t := range c.CreatedAtLT {
		if createdAt >= t {
			return false
		}
	}
	for _, t := range c.CreatedAtGT {
		if createdAt <= t {
			return false
		}
	}
	return true
}

// Tag is a fully parsed and cryptographically verified auth tag.
type Tag struct {
	OwnerPubkey string
	Conditions  Conditions
	Sig         string
}

// ParseConditions parses the <conditions> grammar: the empty string (no
// constraints), or "&"-separated clauses each of the form kind=<decimal>,
// created_at<<decimal>, or created_at><decimal>. Decimal values must be
// canonical base-10 (no leading zeros except a lone "0", no sign, no
// whitespace); kind values are 0-65535, created_at values are
// 0-4294967295. A leading, trailing, or doubled "&" produces an empty
// clause somewhere in the split, which is rejected uniformly by the
// empty-clause check below -- no special-casing needed per position.
func ParseConditions(raw string) (Conditions, error) {
	if raw == "" {
		return Conditions{Raw: raw}, nil
	}

	cond := Conditions{Raw: raw}

	for clause := range strings.SplitSeq(raw, "&") {
		if clause == "" {
			return Conditions{}, fmt.Errorf("%w: empty clause", ErrMalformedConditions)
		}

		switch {
		case strings.HasPrefix(clause, "kind="):
			n, err := parseCanonicalDecimal(clause[len("kind="):], maxKindValue)
			if err != nil {
				return Conditions{}, fmt.Errorf("%w: %v", ErrMalformedConditions, err)
			}
			cond.Kinds = append(cond.Kinds, int(n))

		case strings.HasPrefix(clause, "created_at<"):
			n, err := parseCanonicalDecimal(clause[len("created_at<"):], maxCreatedAtValue)
			if err != nil {
				return Conditions{}, fmt.Errorf("%w: %v", ErrMalformedConditions, err)
			}
			cond.CreatedAtLT = append(cond.CreatedAtLT, n)

		case strings.HasPrefix(clause, "created_at>"):
			n, err := parseCanonicalDecimal(clause[len("created_at>"):], maxCreatedAtValue)
			if err != nil {
				return Conditions{}, fmt.Errorf("%w: %v", ErrMalformedConditions, err)
			}
			cond.CreatedAtGT = append(cond.CreatedAtGT, n)

		default:
			return Conditions{}, fmt.Errorf("%w: %q", ErrUnsupportedClause, clause)
		}
	}

	return cond, nil
}

// parseCanonicalDecimal parses s as base-10 with no leading zeros (except
// a lone "0") and no sign, in range [0, max]. strconv.ParseUint alone
// accepts leading zeros ("01" -> 1), which the spec explicitly forbids
// (an invalid vector: kind=01).
func parseCanonicalDecimal(s string, max uint64) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty decimal value")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zero in decimal value %q", s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit in decimal value %q", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, fmt.Errorf("value %d exceeds maximum %d", n, max)
	}
	return n, nil
}

// Preimage builds the exact signing preimage bytes: the domain separator,
// the event's pubkey, ":", and the conditions string, verbatim.
// eventPubkey and conditions are used byte-for-byte -- no normalization,
// reordering, deduplication, or canonicalization of any kind.
func Preimage(eventPubkey, conditions string) []byte {
	var b strings.Builder
	b.Grow(len(domainSeparator) + len(eventPubkey) + 1 + len(conditions))
	b.WriteString(domainSeparator)
	b.WriteString(eventPubkey)
	b.WriteByte(':')
	b.WriteString(conditions)
	return []byte(b.String())
}

// VerifySignature checks sigHex as a BIP-340 Schnorr signature, by
// ownerPubkeyHex, over SHA256(Preimage(eventPubkey, conditions)). Reuses
// the same schnorr parsing/verification nip01.Event.Verify uses
// elsewhere in this SDK.
func VerifySignature(ownerPubkeyHex, eventPubkey, conditions, sigHex string) error {
	if err := utils.Validate32Key(ownerPubkeyHex); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != 64 {
		return ErrInvalidSignatureHex
	}
	signature, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignatureHex, err)
	}

	ownerPubkeyBytes, err := hex.DecodeString(ownerPubkeyHex)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}
	ownerPubkey, err := schnorr.ParsePubKey(ownerPubkeyBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}

	digest := sha256.Sum256(Preimage(eventPubkey, conditions))
	if !signature.Verify(digest[:], ownerPubkey) {
		return ErrSignatureVerificationFailed
	}

	return nil
}

// ParseAuthTag finds and fully verifies event's "auth" tag, if any, using
// eventPubkey as the event's own pubkey (the preimage's identity
// component). Returns (nil, nil) -- not an error -- when there is no auth
// tag at all: "no credential offered" is a valid, distinct outcome from
// "malformed credential offered", and callers (e.g. NIP-AA's Step 3, which
// treats the two differently) must be able to tell them apart.
//
// Per spec: an event with two or more auth tags MUST be treated as having
// no valid auth tag -- but unlike the zero-tag case, this is reported as
// an error (ErrMultipleAuthTags), not (nil, nil), so a caller that must
// react differently to "no credential" vs. "malformed/ambiguous
// credential" (again, NIP-AA's Step 3) still can.
func ParseAuthTag(tags [][]string, eventPubkey string) (*Tag, error) {
	matches, found := utils.LookupEventTag(tags, TagName)
	if !found {
		return nil, nil
	}
	if len(matches) > 1 {
		return nil, ErrMultipleAuthTags
	}

	tag := matches[0]
	if len(tag) != 4 {
		return nil, fmt.Errorf("%w: got %d", ErrWrongElementCount, len(tag))
	}

	ownerPubkey, conditionsRaw, sigHex := tag[1], tag[2], tag[3]

	if err := utils.Validate32Key(ownerPubkey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}
	if ownerPubkey == eventPubkey {
		return nil, ErrSelfAttestation
	}

	conditions, err := ParseConditions(conditionsRaw)
	if err != nil {
		return nil, err
	}

	if err := VerifySignature(ownerPubkey, eventPubkey, conditionsRaw, sigHex); err != nil {
		return nil, err
	}

	return &Tag{OwnerPubkey: ownerPubkey, Conditions: conditions, Sig: sigHex}, nil
}
