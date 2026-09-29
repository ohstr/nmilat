package client

import (
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// TestServableMethods_MatchNipcashConstants pins transport's servable-method set to
// nipcash's own method constants.
//
// transport spells those names as wire strings rather than importing the constants,
// and that is a layering requirement rather than laziness: an item proof is signed
// with a bill's own key, that key lives behind nipcash.Credential's unexported
// methods, so nipcash is the package that must build item proofs — which means
// nipcash has to be able to import transport. Importing nipcash from transport
// would make that a cycle.
//
// The cost of spelling them out is that a rename in nipcash would silently
// desynchronise the two. This test is what pays that cost, and it lives here
// because nipcash/client is the lowest package that can import both without
// cycling.
func TestServableMethods_MatchNipcashConstants(t *testing.T) {
	for _, m := range []string{
		nipcash.MethodCashStatus,
		nipcash.MethodCashRedeem,
		nipcash.MethodCashTransfer,
		nipcash.MethodCashConsolidate,
	} {
		if !transport.IsServableMethod(m) {
			t.Errorf("transport does not recognise %q; a method constant was renamed "+
				"and transport's own copy of the name was not updated", m)
		}
	}

	// The list_recipients alias is gone, and must stay gone. It existed only so a
	// released client could lag a Hub; with no released client it is dead weight, and
	// leaving it servable would keep a second spelling of one method alive forever.
	if transport.IsServableMethod("list_recipients") {
		t.Error("list_recipients is still servable; the deprecated alias was removed and must not return")
	}

	// mint_cash must stay excluded: hub-owner method, and the only one with no
	// retry idempotency, which is what makes a bounded replay set safe.
	if transport.IsServableMethod(nipcash.MethodMintCash) {
		t.Errorf("%q must not be servable over the private transport", nipcash.MethodMintCash)
	}
}
