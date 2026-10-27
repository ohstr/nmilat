package nipcw

import (
	"fmt"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// MemberAction is a member request's action (NIP-CW §Recovering a Lost
// Connection).
type MemberAction string

// The three member actions.
const (
	ActionRotate   MemberAction = "rotate"
	ActionFreeze   MemberAction = "freeze"
	ActionUnfreeze MemberAction = "unfreeze"
)

func (a MemberAction) valid() bool {
	return a == ActionRotate || a == ActionFreeze || a == ActionUnfreeze
}

// memberRequestFreshness is a member request's window into the past: 24 hours.
const memberRequestFreshness = 86400

// MemberRequestRetainUntil is how long a member request's id stays in the
// single-use record: its created_at plus 24 hours and 1 minute.
func MemberRequestRetainUntil(createdAt int64) int64 { return createdAt + 86460 }

// MemberRequest is a verified member request.
type MemberRequest struct {
	ID        string
	Pubkey    string
	CreatedAt int64
	Action    MemberAction
	Wallet    string
	// Connection is the key a rotate moves the wallet to; "" otherwise.
	Connection string
}

// NewMemberRequest signs a member request with the member's key (the join's
// pubkey) for the Hub whose circlehub1 TLV 0 is hubPubkey: d, action, wallet
// and, on a rotate only, connection. The host submits it; a Hub never acts on
// the host's word alone.
func NewMemberRequest(priv, hubPubkey string, a MemberAction, wallet, newConnection string) (*nip01.Event, error) {
	if !a.valid() {
		return nil, fmt.Errorf("nipcw: unknown member action %q", a)
	}
	if !isLowerHex64(hubPubkey) || !isLowerHex64(wallet) {
		return nil, fmt.Errorf("nipcw: hub pubkey and wallet must be 64 lowercase hex")
	}
	tags := [][]string{{"d", hubPubkey}, {"action", string(a)}, {"wallet", wallet}}
	switch {
	case a == ActionRotate && !validXOnly(newConnection):
		return nil, fmt.Errorf("nipcw: a rotate names the new connection key as a valid x-only key")
	case a == ActionRotate:
		tags = append(tags, []string{"connection", newConnection})
	case newConnection != "":
		return nil, fmt.Errorf("nipcw: only a rotate names a connection key")
	}
	return BySigning(priv).signProof(time.Now().Unix(), tags...)
}

// VerifyMemberRequest runs a member request's steps 2 and 3 for the Hub whose
// circlehub1 TLV 0 is hubPubkey, at now on the Hub's clock. Step 2 refuses with
// UNAUTHORIZED, recording nothing: kind 23199, the id recomputed, the signature
// by its pubkey, created_at from now−86400 to now+60 inclusive, one d tag equal
// to hubPubkey, exactly one action (rotate, freeze or unfreeze), one wallet,
// one connection on a rotate and none otherwise, and no terms tag. Step 3 then
// calls consumed once, an atomic test-and-record: a used id is REQUEST_REUSED.
// The steps after (wallet, member, delay, action) are the Hub's; on a rotate,
// CheckConnection gives step 7's key check.
func VerifyMemberRequest(ev *nip01.Event, hubPubkey string, now time.Time, consumed func(string) bool) (MemberRequest, error) {
	if ev == nil {
		return MemberRequest{}, unauthorized("no member request")
	}
	if ev.Kind != KindCircleIdentityProof {
		return MemberRequest{}, unauthorized(fmt.Sprintf("kind %d, want %d", ev.Kind, KindCircleIdentityProof))
	}
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return MemberRequest{}, unauthorized("member request does not verify: " + err.Error())
	}
	if err := fresh(ev.CreatedAt, now, memberRequestFreshness, joinFuture); err != nil {
		return MemberRequest{}, err
	}
	if d, ok := oneTag(ev, "d"); !ok || d != strings.ToLower(hubPubkey) {
		return MemberRequest{}, unauthorized("d tag is not this Hub's pubkey")
	}
	action, ok := oneTag(ev, "action")
	if !ok || !MemberAction(action).valid() {
		return MemberRequest{}, unauthorized("a member request carries exactly one action: rotate, freeze or unfreeze")
	}
	wallet, ok := oneTag(ev, "wallet")
	if !ok {
		return MemberRequest{}, unauthorized("a member request carries exactly one wallet tag")
	}
	conns := tagValues(ev, "connection")
	if (MemberAction(action) == ActionRotate) != (len(conns) == 1) || len(conns) > 1 {
		return MemberRequest{}, unauthorized("a rotate carries exactly one connection tag, and nothing else carries one")
	}
	if len(tagValues(ev, "terms")) != 0 {
		return MemberRequest{}, unauthorized("a member request carries no terms tag")
	}
	if consumed != nil && consumed(ev.ID) {
		return MemberRequest{}, &JoinProofError{Code: ErrRequestReused, Reason: "member request already used"}
	}
	mr := MemberRequest{ID: ev.ID, Pubkey: ev.PubKey, CreatedAt: int64(ev.CreatedAt), Action: MemberAction(action), Wallet: wallet}
	if len(conns) == 1 {
		mr.Connection = conns[0]
	}
	return mr, nil
}

// CheckConnection is step 7's key check for a rotate: a connection that is not a
// valid x-only key is RESTRICTED. Whether another connection on the node uses it
// is the Hub's to check. It is nil for a freeze or an unfreeze.
func (m MemberRequest) CheckConnection() error {
	if m.Action == ActionRotate && !validXOnly(m.Connection) {
		return &JoinProofError{Code: ErrRestricted, Reason: "the new connection is not a valid x-only key"}
	}
	return nil
}
