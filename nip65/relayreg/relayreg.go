// Package relayreg declares NIP-65 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-65 auto-declared in its
// NIP-11 document and relay-list events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip65/relayreg"
//
// nip65 itself has no dependency on relay, so pure clients that only
// build/parse relay lists don't pay for relay's bbolt/websocket dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip65"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(65)

	relay.RegisterEventValidator(nip65.KindRelayListMetadata, func(_ context.Context, event *nip01.Event) error {
		return nip65.ValidateRelayList(event)
	})
}
