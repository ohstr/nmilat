// Package relayreg declares NIP-29 support to a relay engine. Blank-import it
// from a relay-embedding binary that wants NIP-29 auto-declared in its NIP-11
// document and group moderation, membership-request and relay-authored
// metadata events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip29/relayreg"
//
// nip29 itself has no dependency on relay, so pure clients that only
// build/parse group events don't pay for relay's bbolt/websocket dependency.
//
// Structural validation is all this registers. Two NIP-29 rules are
// deliberately left to the relay because they need state this layer does not
// have: that a moderation event's signer actually holds a role permitting the
// action (see nip29.ModerationPolicy), and that the relay-authored 39000-39005
// events are signed by the relay's own NIP-11 "self" key.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(29)

	// Moderation actions share one validator: ParseModerationAction
	// dispatches on kind and enforces each action's own required arguments.
	for _, kind := range []int{
		nip29.KindPutUser,
		nip29.KindRemoveUser,
		nip29.KindEditMetadata,
		nip29.KindDeleteEvent,
		nip29.KindCreateGroup,
		nip29.KindDeleteGroup,
		nip29.KindCreateInvite,
		nip29.KindUpdatePinList,
	} {
		relay.RegisterEventValidator(kind, func(_ context.Context, event *nip01.Event) error {
			return nip29.ValidateModerationAction(event)
		})
	}

	relay.RegisterEventValidator(nip29.KindJoinRequest, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateJoinRequest(event)
	})
	relay.RegisterEventValidator(nip29.KindLeaveRequest, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateLeaveRequest(event)
	})

	relay.RegisterEventValidator(nip29.KindGroupMetadata, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateGroupMetadata(event)
	})
	relay.RegisterEventValidator(nip29.KindGroupAdmins, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateGroupAdmins(event)
	})
	relay.RegisterEventValidator(nip29.KindGroupMembers, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateGroupMembers(event)
	})
	relay.RegisterEventValidator(nip29.KindGroupRoles, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateGroupRoles(event)
	})
	relay.RegisterEventValidator(nip29.KindLiveParticipants, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateLiveParticipants(event)
	})
	relay.RegisterEventValidator(nip29.KindGroupPinnedEvents, func(_ context.Context, event *nip01.Event) error {
		return nip29.ValidateGroupPinnedEvents(event)
	})
}
