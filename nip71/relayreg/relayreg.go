// Package relayreg declares NIP-71 support to a relay engine. Blank-import it
// from a relay-embedding binary that wants NIP-71 auto-declared in its NIP-11
// document and video events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip71/relayreg"
//
// nip71 itself has no dependency on relay, so pure clients that only
// build/parse video events don't pay for relay's bbolt/websocket dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip71"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(71)

	for _, kind := range []int{
		nip71.KindVideo,
		nip71.KindShortVideo,
		nip71.KindAddressableVideo,
		nip71.KindAddressableShortVideo,
	} {
		relay.RegisterEventValidator(kind, func(_ context.Context, event *nip01.Event) error {
			return nip71.ValidateVideo(event)
		})
	}
}
