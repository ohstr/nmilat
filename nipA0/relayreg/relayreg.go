// Package relayreg declares NIP-A0 support to a relay engine. Blank-import it
// from a relay-embedding binary that wants NIP-A0 auto-declared in its NIP-11
// document and voice messages auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nipA0/relayreg"
//
// nipA0 itself has no dependency on relay, so pure clients that only
// build/parse voice messages don't pay for relay's bbolt/websocket dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipA0"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterLetteredNIP("A0")

	for _, kind := range []int{nipA0.KindVoiceMessage, nipA0.KindVoiceMessageReply} {
		relay.RegisterEventValidator(kind, func(_ context.Context, event *nip01.Event) error {
			return nipA0.ValidateVoiceMessage(event)
		})
	}
}
