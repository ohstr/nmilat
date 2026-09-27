// Package relayreg declares NIP-53 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-53 auto-declared in its
// NIP-11 document and live-streaming, meeting-space, meeting, presence and
// live-chat events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip53/relayreg"
//
// nip53 itself has no dependency on relay, so pure clients that only
// build/parse these events don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip53"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(53)

	relay.RegisterEventValidator(nip53.KindLiveStreamingEvent, func(_ context.Context, event *nip01.Event) error {
		return nip53.ValidateLiveStream(event)
	})
	relay.RegisterEventValidator(nip53.KindMeetingSpace, func(_ context.Context, event *nip01.Event) error {
		return nip53.ValidateMeetingSpace(event)
	})
	relay.RegisterEventValidator(nip53.KindMeetingRoomEvent, func(_ context.Context, event *nip01.Event) error {
		return nip53.ValidateMeetingRoomEvent(event)
	})
	relay.RegisterEventValidator(nip53.KindRoomPresence, func(_ context.Context, event *nip01.Event) error {
		return nip53.ValidateRoomPresence(event)
	})
	relay.RegisterEventValidator(nip53.KindLiveChatMessage, func(_ context.Context, event *nip01.Event) error {
		return nip53.ValidateLiveChatMessage(event)
	})
}
