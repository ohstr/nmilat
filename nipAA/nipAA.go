// Package nipAA implements NIP-AA's pure, relay-independent orchestration
// pieces: the AUTH-event freshness check and Steps 3-4 of its relay
// verification algorithm (find the "auth" tag, verify it via nipOA, and
// evaluate only its created_at</created_at> clauses -- kind= clauses are
// deliberately not evaluated here, per the spec's explicit divergence from
// full NIP-OA verification at connection admission). Everything else
// (Steps 1-2, 5-6: NIP-42 checks, the direct-member fast path, the owner
// membership check, and granting virtual membership) is session/store-aware
// and lives in relay/, not here.
package nipAA

import (
	"errors"
	"time"

	"github.com/ohstr/nmilat/nipOA"
)

// DefaultFreshnessWindow is the spec's own recommendation: "A ±120-second
// window is RECOMMENDED" for the AUTH event's created_at, on top of (not
// instead of) NIP-42's own ValidateAuthEvent freshness window.
const DefaultFreshnessWindow = 120 * time.Second

// ErrStale means the AUTH event's created_at falls outside the configured
// freshness window.
var ErrStale = errors.New("nipaa: created_at outside the freshness window")

// ErrCredentialTimestampUnsatisfied means the auth tag parsed and verified
// successfully, but its created_at</created_at> clauses are not satisfied
// by the AUTH event's own created_at.
var ErrCredentialTimestampUnsatisfied = errors.New("nipaa: credential's created_at conditions not satisfied by this AUTH event")

// ValidateFreshness checks the AUTH event's created_at against now, within
// window. This is NIP-AA's own additional freshness requirement, applied
// on top of nip42.ValidateAuthEvent's own (wider, ±600s) window -- both
// checks run; neither replaces the other.
func ValidateFreshness(createdAt uint64, now time.Time, window time.Duration) error {
	delta := int64(window.Seconds())
	nowUnix := now.Unix()
	if int64(createdAt) < nowUnix-delta || int64(createdAt) > nowUnix+delta {
		return ErrStale
	}
	return nil
}

// EvaluateCredential runs Steps 3-4 of NIP-AA's relay verification
// algorithm against an AUTH event's tags: find exactly one "auth" tag
// (via nipOA.ParseAuthTag, which also verifies the Schnorr signature and
// rejects self-attestation/malformed tags), then evaluate only its
// created_at</created_at> clauses against eventCreatedAt -- kind= clauses
// are deliberately skipped here (see the spec's "Kind Conditions"
// section); optional per-event kind enforcement, if a relay implements
// it, evaluates them later, per-EVENT, against the already-verified
// credential this returns.
//
// Returns (nil, nil) -- not an error -- when there is no auth tag at all:
// Step 3's "no credential offered" case, which the relay-side caller
// (processAuth) is responsible for treating as a reject, since a
// non-member with no credential is not itself something this pure
// function can distinguish from "not applicable here" without relay
// context (e.g. whether the connection is even attempting NIP-AA).
func EvaluateCredential(eventPubkey string, tags [][]string, eventCreatedAt uint64) (*nipOA.Tag, error) {
	tag, err := nipOA.ParseAuthTag(tags, eventPubkey)
	if err != nil {
		return nil, err
	}
	if tag == nil {
		return nil, nil
	}
	if !tag.Conditions.EvaluateTimeClauses(eventCreatedAt) {
		return nil, ErrCredentialTimestampUnsatisfied
	}
	return tag, nil
}
