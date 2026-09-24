// Package relayreg declares NIP-57 (Zaps) support to a relay engine.
// Blank-import it from a relay-embedding binary that wants NIP-57
// auto-declared in its NIP-11 document and its event kinds auto-validated:
//
//	import _ "github.com/ohstr/nmilat/nip57/relayreg"
//
// nip57 itself has no dependency on relay, so pure clients that only
// build/parse/validate zap events don't pay for relay's bbolt/websocket
// dependency.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterNIP(57)

	// The *ForRelay validators enforce NIP-57's MUST-level rules and
	// tolerate its SHOULD-level ones. A relay stores zap events settled by
	// someone else, so rejecting a correctly signed receipt over an
	// optional tag's encoding would silently drop the record of a payment
	// that happened. Callers settling or accounting for their own zaps
	// should use nip57.ValidateZapRequest/ValidateZapReceipt directly.
	relay.RegisterEventValidator(nip57.KindZapRequest, func(_ context.Context, event *nip01.Event) error {
		return nip57.ValidateZapRequestForRelay(event)
	})
	relay.RegisterEventValidator(nip57.KindZapReceipt, func(_ context.Context, event *nip01.Event) error {
		return nip57.ValidateZapReceiptForRelay(event)
	})
}
