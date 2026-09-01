// Package relayreg declares NIP-AZ (AltZap) support to a relay engine.
// Blank-import it from a relay-embedding binary that wants NIP-AZ
// auto-declared in its NIP-11 document and its event kinds auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nipAZ/relayreg"
//
// nipAZ itself has no dependency on relay, so pure clients that only
// build/parse/validate AltZap events don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterLetteredNIP("AZ")

	relay.RegisterEventValidator(nipAZ.KindAltZapRequest, func(_ context.Context, event *nip01.Event) error {
		return nipAZ.ValidateAltZapRequest(event, 0)
	})
	relay.RegisterEventValidator(nipAZ.KindAltZapOnBehalfRequest, func(_ context.Context, event *nip01.Event) error {
		return nipAZ.ValidateAltZapRequest(event, 0)
	})
	relay.RegisterEventValidator(nipAZ.KindAltZapDirectPayment, func(_ context.Context, event *nip01.Event) error {
		return nipAZ.ValidateAltZapRequest(event, 0)
	})
	relay.RegisterEventValidator(nipAZ.KindAltZapReceipt, func(_ context.Context, event *nip01.Event) error {
		return nipAZ.ValidateAltZapReceipt(event)
	})
}
