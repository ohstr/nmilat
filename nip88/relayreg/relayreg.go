// Package relayreg declares NIP-88 support to a relay engine. Blank-import
// it from a relay-embedding binary that wants NIP-88 auto-declared in its
// NIP-11 document and poll/response events auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip88/relayreg"
//
// nip88 itself has no dependency on relay, so pure clients that only
// build/parse polls don't pay for relay's bbolt/websocket dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip88"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(88)

	relay.RegisterEventValidator(nip88.KindPoll, func(_ context.Context, event *nip01.Event) error {
		return nip88.ValidatePoll(event)
	})
	relay.RegisterEventValidator(nip88.KindPollResponse, func(_ context.Context, event *nip01.Event) error {
		return nip88.ValidatePollResponse(event, nil)
	})
}
