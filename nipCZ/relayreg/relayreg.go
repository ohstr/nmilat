// Package relayreg declares NIP-CZ (Cash Zaps) support to a relay engine and
// validates kind 9522 events at ingest. A relay MAY skip validation, so this is
// opt-in: blank-import it from a relay-embedding binary that wants it.
//
//	import _ "github.com/ohstr/nmilat/nipCZ/relayreg"
//
// A relay that validates applies the Client column's rules 1-6 and refuses an
// event that fails one; rules 7 and 8 only decide counting, and rule 9 is never
// run. nipCZ itself has no dependency on relay.
package relayreg

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCZ"
	"github.com/ohstr/nmilat/relay"
)

func init() {
	relay.RegisterLetteredNIP("CZ")
	relay.RegisterEventValidator(nipCZ.KindCashZap, func(_ context.Context, ev *nip01.Event) error {
		return nipCZ.ValidateForRelay(ev)
	})
}
