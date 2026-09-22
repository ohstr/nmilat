package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// transferConsolidater is the narrow slice of *Client that
// RekeyCashSlice/TransferFromSources actually call — *Client already
// satisfies this. Factored out purely so their own call-sequencing logic
// (which call, in what order, on what condition) is unit-testable against
// a hand-built fake, without a live Cash Hub or a fake NWC relay: this
// package has no existing fake-transport harness (the only one in this
// repo, relay/client/nwc_test.go's newFakeWalletServer, is unexported one
// package over), and building one is a bigger, separate investment this
// doesn't need.
type transferConsolidater interface {
	CashTransfer(ctx context.Context, params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error)
	CashConsolidate(ctx context.Context, params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error)
}
