package relay

import (
	"context"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip43"
)

// init registers NIP-43's purely structural, session-independent
// validators through the existing RegisterEventValidator hook -- tag
// shape, hex format, and (for Join/Leave) timestamp freshness. This is
// deliberately the only NIP-43 enforcement that goes through that
// mechanism: everything else (self-authored-pubkey checks, join/leave side
// effects) needs *Session/*SessionContext, which EventValidator's
// signature has no access to (see relay/packet.go's processEvent gate,
// and a later phase's join/leave handling).
func init() {
	for _, kind := range []int{
		nip43.KindRoleDefinition,
		nip43.KindMembershipList,
		nip43.KindAddUser,
		nip43.KindRemoveUser,
		nip43.KindInviteRequest,
	} {
		RegisterEventValidator(kind, validateNip43Structure)
	}
	RegisterEventValidator(nip43.KindJoinRequest, validateNip43RequestStructure)
	RegisterEventValidator(nip43.KindLeaveRequest, validateNip43RequestStructure)
}

func validateNip43Structure(_ context.Context, ev *nip01.Event) error {
	switch ev.Kind {
	case nip43.KindRoleDefinition:
		_, err := nip43.ParseRole(ev)
		return err
	case nip43.KindMembershipList:
		_, err := nip43.ParseMembershipList(ev)
		return err
	case nip43.KindAddUser:
		_, err := nip43.ParseAddUser(ev)
		return err
	case nip43.KindRemoveUser:
		_, err := nip43.ParseRemoveUser(ev)
		return err
	case nip43.KindInviteRequest:
		_, err := nip43.ParseInviteResponse(ev)
		return err
	}
	return nil
}

// validateNip43RequestStructure checks Join/Leave request tag shape and
// created_at freshness. Claim-validity (is this actually a live invite
// code) is session/store-aware and handled separately by a later phase.
func validateNip43RequestStructure(_ context.Context, ev *nip01.Event) error {
	switch ev.Kind {
	case nip43.KindJoinRequest:
		if _, err := nip43.ParseJoinRequest(ev); err != nil {
			return err
		}
	case nip43.KindLeaveRequest:
		if _, err := nip43.ParseLeaveRequest(ev); err != nil {
			return err
		}
	default:
		return nil
	}
	return nip43.ValidateFreshness(ev.CreatedAt, time.Now(), nip43.DefaultRequestFreshnessWindow)
}

// CheckSelfAuthored reports whether ev is allowed given selfPubkey, the
// relay's own configured NIP-11 "self" identity (relay/nip11.Metadata.Self).
// Kinds NIP-43 requires to be relay-authored (role definitions, membership
// lists, add/remove-user, invite responses) MUST be signed by selfPubkey;
// every other kind passes unconditionally. selfPubkey == "" (no self
// identity configured) means every relay-authored kind is rejected outright
// -- there is no valid signer for them, so failing closed is the only sound
// default.
func CheckSelfAuthored(ev *nip01.Event, selfPubkey string) (ok bool, message string) {
	if !nip43.IsRelayAuthoredKind(ev.Kind) {
		return true, ""
	}
	if selfPubkey == "" || ev.PubKey != selfPubkey {
		return false, "restricted: this event kind may only be published by the relay itself"
	}
	return true, ""
}
