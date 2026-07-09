// Package relayreg declares NIP-B0 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-B0 auto-declared in its
// NIP-11 document and bookmark events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nipB0/relayreg"
//
// nipB0 itself has no dependency on relay, so pure clients that only
// build/parse bookmarks don't pay for relay's bbolt/websocket dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB0"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(0xB0)

	relay.RegisterEventValidator(nipB0.KindWebBookmark, func(_ context.Context, event *nip01.Event) error {
		return nipB0.ValidateWebBookmark(event)
	})
}
