package client

import "github.com/ohstr/nmilat/nipcash"

// PartialProgressError is returned by both TransferFromSources and
// RekeyCashSlice when their first wire call landed for real but their
// second then failed — exactly one of Transferred/Consolidated is set,
// whichever call type actually succeeded (the two composites run the
// same two calls in opposite order: TransferFromSources consolidates
// then transfers, RekeyCashSlice reassigns [a transfer] then
// consolidates). Both nipcash.CashTransferResult and
// nipcash.CashConsolidateResult already carry AmountMillis/
// NewWalletPubkey/NewWalletToken, so the caller can update its own
// ledger from whichever landed without an extra round trip to
// rediscover what already happened.
type PartialProgressError struct {
	Transferred  *nipcash.CashTransferResult
	Consolidated *nipcash.CashConsolidateResult
	// Cause is the error the second (failed) call actually returned.
	Cause error
}

func (e *PartialProgressError) Error() string {
	if e.Transferred != nil {
		return "nipcash/client: interim transfer landed, but the following consolidate failed: " + e.Cause.Error()
	}
	return "nipcash/client: interim consolidate landed, but the following transfer failed: " + e.Cause.Error()
}

func (e *PartialProgressError) Unwrap() error { return e.Cause }
