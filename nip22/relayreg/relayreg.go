// Package relayreg declares NIP-22 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-22 auto-declared in its
// NIP-11 document and kind:1111 comment events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip22/relayreg"
//
// nip22 itself has no dependency on relay, so pure clients that only
// build/parse comment events don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip22"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(22)

	relay.RegisterEventValidator(nip22.KindComment, func(_ context.Context, event *nip01.Event) error {
		return nip22.ValidateComment(event)
	})
}
