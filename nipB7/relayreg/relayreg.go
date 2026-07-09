// Package relayreg declares NIP-B7 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-B7 auto-declared in its
// NIP-11 document and server-list events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nipB7/relayreg"
//
// nipB7 itself has no dependency on relay, so pure clients that only
// build/parse server lists don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(0xB7)

	relay.RegisterEventValidator(nipB7.KindBlossomServerList, func(_ context.Context, event *nip01.Event) error {
		return nipB7.ValidateBlossomServerList(event)
	})
}
