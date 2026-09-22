package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// fakeTransferConsolidater is a hand-built transferConsolidater for
// exercising RekeyCashSlice/TransferFromSources' own call-sequencing
// logic without a network — see transferConsolidater's own doc comment.
// closed counts Close calls (transferFromSources must release whatever
// reconnect hands it); reconnectCalls records every walletToken
// transferFromSources asked to rebind to, so a test can assert it's
// always the interim consolidate's own NewWalletToken, never the
// original dial target.
type fakeTransferConsolidater struct {
	transferFunc     func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error)
	consolidateFunc  func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error)
	reconnectFunc    func(walletToken string) (transferConsolidaterCloser, error)
	transferCalls    []nipcash.CashTransferParams
	consolidateCalls []nipcash.CashConsolidateParams
	reconnectCalls   []string
	closed           int
}

func (f *fakeTransferConsolidater) CashTransfer(_ context.Context, params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
	f.transferCalls = append(f.transferCalls, params)
	return f.transferFunc(params)
}

func (f *fakeTransferConsolidater) CashConsolidate(_ context.Context, params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
	f.consolidateCalls = append(f.consolidateCalls, params)
	return f.consolidateFunc(params)
}

func (f *fakeTransferConsolidater) reconnect(_ context.Context, walletToken string) (transferConsolidaterCloser, error) {
	f.reconnectCalls = append(f.reconnectCalls, walletToken)
	if f.reconnectFunc != nil {
		return f.reconnectFunc(walletToken)
	}
	return f, nil
}

func (f *fakeTransferConsolidater) Close() { f.closed++ }
