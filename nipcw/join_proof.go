package nipcw

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// JoinProofError is a join proof or member request refused with Code, the NIP-47
// code a Hub answers with: BAD_REQUEST, UNAUTHORIZED or REQUEST_REUSED (or a
// RESTRICTED hint from MemberRequest.CheckConnection).
type JoinProofError struct {
	Code   string
	Reason string
}

func (e *JoinProofError) Error() string { return "nipcw: " + e.Code + ": " + e.Reason }

func badRequest(reason string) error   { return &JoinProofError{Code: ErrBadRequest, Reason: reason} }
func unauthorized(reason string) error { return &JoinProofError{Code: ErrUnauthorized, Reason: reason} }

// JoinProofRetainUntil is how long a join proof's id stays in the single-use
// record: its created_at plus 6 minutes, past the last moment check 4 can still
// accept it (NIP-CW §Data Model).
func JoinProofRetainUntil(createdAt int64) int64 { return createdAt + 360 }

// VerifyJoinProof runs NIP-CW §Processing Algorithm steps 1–3 on a parsed
// request for the Hub whose circlehub1 TLV 0 is hubPubkey, at now on the Hub's
// clock, and returns the proof's id.
//
// Step 1 refuses malformed params with BAD_REQUEST before any proof check, so
// nothing is consumed. Checks 1–7 of §Identity Proof refuse with UNAUTHORIZED:
// kind 23199 without an action tag; the id recomputed; the signature by pubkey;
// created_at from now−300 to now+60 inclusive; one d tag equal to hubPubkey; one
// connection tag equal to connection_pubkey; one terms tag byte-equal to the
// request's terms. Only then is consumed called, once: it reports whether the
// id was already used, and a Hub implements it as one atomic test-and-record, so
// a used id is REQUEST_REUSED and a fresh one is recorded before any later step.
// Membership is checked after this returns.
func VerifyJoinProof(req CreateCircleWalletRequest, hubPubkey string, now time.Time, consumed func(id string) bool) (string, error) {
	if err := validateRequest(req); err != nil {
		return "", err
	}
	var ev nip01.Event
	if err := json.Unmarshal([]byte(req.IdentityEvent), &ev); err != nil {
		return "", unauthorized("identity_event is not an event")
	}
	// Check 1.
	if ev.Kind != KindCircleIdentityProof {
		return "", unauthorized(fmt.Sprintf("kind %d, want %d", ev.Kind, KindCircleIdentityProof))
	}
	if len(tagValues(&ev, "action")) != 0 {
		return "", unauthorized("a join proof carries no action tag")
	}
	// Checks 2 and 3.
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return "", unauthorized("proof does not verify: " + err.Error())
	}
	if ev.PubKey != req.Pubkey {
		return "", unauthorized("proof signer is not the request's pubkey")
	}
	// Check 4.
	if err := fresh(ev.CreatedAt, now, JoinFreshness, joinFuture); err != nil {
		return "", err
	}
	// Check 5.
	if d, ok := oneTag(&ev, "d"); !ok || d != strings.ToLower(hubPubkey) {
		return "", unauthorized("d tag is not this Hub's pubkey")
	}
	// Check 6.
	if c, ok := oneTag(&ev, "connection"); !ok || c != req.ConnectionPubkey {
		return "", unauthorized("connection tag is not the request's connection_pubkey")
	}
	// Check 7.
	want, _ := TermsTag(req.Terms()) // validated in step 1
	if t, ok := oneTag(&ev, "terms"); !ok || t != want {
		return "", unauthorized("terms tag does not match the request")
	}
	// Check 8.
	if consumed != nil && consumed(ev.ID) {
		return "", &JoinProofError{Code: ErrRequestReused, Reason: "proof already used"}
	}
	return ev.ID, nil
}

// validateRequest is step 1.
func validateRequest(req CreateCircleWalletRequest) error {
	switch {
	case !isLowerHex64(req.Pubkey):
		return badRequest("pubkey must be 64 lowercase hex")
	case !validXOnly(req.ConnectionPubkey):
		return badRequest("connection_pubkey must be a valid x-only key in 64 lowercase hex")
	case req.ConnectionPubkey == req.Pubkey:
		return badRequest("connection_pubkey must differ from pubkey")
	}
	if err := req.Terms().check(); err != nil {
		return badRequest(err.Error())
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(req.IdentityEvent), &obj); err != nil || obj == nil {
		return badRequest("identity_event does not parse to a JSON object")
	}
	return nil
}

// fresh checks created_at within [now-past, now+future], both inclusive.
func fresh(createdAt uint64, now time.Time, past, future int64) error {
	c := int64(createdAt)
	n := now.Unix()
	if createdAt > uint64(1<<62) || c < n-past || c > n+future {
		return unauthorized(fmt.Sprintf("created_at %d is outside [%d, %d]", createdAt, n-past, n+future))
	}
	return nil
}
