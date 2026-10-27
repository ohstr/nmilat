package client

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// A batch transfer or consolidate outcome gives the same error a single call
// does, with the refusal code on the call, so Recover can close a call the Hub
// refused rather than re-place it.
func TestTransferConsolidateOutcome_CallError(t *testing.T) {
	pc := &nipcash.PendingCall{RequestID: "r1", Method: nipcash.MethodCashTransfer}
	coded := func(c string) ItemOutcome {
		return ItemOutcome{State: OutcomeError, Error: &transport.ResultError{Code: c}, pending: pc}
	}
	var ie *IndeterminateError
	if err := (TransferOutcome{ItemOutcome: coded(nipcash.ErrCodeRestricted)}).CallError(nil); !errors.As(err, &ie) || ie.Call.LastCode != nipcash.ErrCodeRestricted {
		t.Fatalf("RESTRICTED: %v", err)
	}
	if err := (ConsolidateOutcome{ItemOutcome: coded(nipcash.ErrCodeRequestReused)}).CallError(nil); !errors.As(err, &ie) || !ie.Call.SawReused {
		t.Fatalf("REQUEST_REUSED: %v", err)
	}
	var fe *FinalError
	if err := (TransferOutcome{ItemOutcome: coded(nipcash.ErrCodeBadRequest)}).CallError(nil); !errors.As(err, &fe) {
		t.Fatalf("BAD_REQUEST: %v", err)
	}
	gone := ItemOutcome{State: OutcomeError, Error: &transport.ResultError{}, Gone: &nipcash.Tombstone{Status: nipcash.StatusSpent}, pending: pc}
	var bg *nipcash.BillGone
	if err := (ConsolidateOutcome{ItemOutcome: gone}).CallError(nil); !errors.As(err, &bg) {
		t.Fatalf("tombstone: %v", err)
	}
	if err := (TransferOutcome{ItemOutcome: ItemOutcome{State: OutcomeResult, pending: pc}}).CallError(nil); err != nil {
		t.Fatalf("result: %v", err)
	}
	if pc.LastCode != "" || pc.SawReused {
		t.Error("CallError changed the outcome's own call")
	}
}
