package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
)

// Journal is where a client writes a call ahead of sending it (NIP-CASH
// §request_id: a caller SHOULD save the id, the call, its exact deadline and any
// secret it generated before sending). Every bill-creating entry point takes one.
type Journal interface {
	// WriteAhead stores calls durably and reads them back before returning nil.
	WriteAhead(ctx context.Context, calls []nipcash.PendingCall) error
	// RecordDerived notes, on this device, that a derived id was placed.
	RecordDerived(ctx context.Context, id string, keepUntil int64) error
	// DerivedPlaced reports whether a derived id was already placed here.
	DerivedPlaced(ctx context.Context, id string) (bool, error)
}

// AcceptedRecorder is an optional Journal extension: told, after publish, which
// relays accepted a call, so a later process can watch for its notices there. A
// failure is reported and never fails the call.
type AcceptedRecorder interface {
	RecordAccepted(ctx context.Context, requestID string, relays []string) error
}

var (
	// ErrNoJournal is a bill-creating call without a Journal.
	ErrNoJournal = errors.New("nipcash/client: a call carrying a request_id needs a journal to write it ahead")
	// ErrNotSent wraps every reason a written-ahead call was not published; the
	// caller closes it as not sent.
	ErrNotSent = errors.New("nipcash/client: the call was not sent")
	// ErrDeadlineTooClose is fewer than MinPublishMargin seconds left before the
	// deadline at publish time.
	ErrDeadlineTooClose = errors.New("nipcash/client: too little time left before the call's deadline to publish it")
	// ErrDuplicateRequestID is two items of one batch carrying one request_id.
	ErrDuplicateRequestID = errors.New("nipcash/client: two calls in one batch share a request_id")
	// ErrReplaceNeedsConfirmation is a mint or order re-placed without its user's
	// explicit confirmation.
	ErrReplaceNeedsConfirmation = errors.New("nipcash/client: re-placing this call needs the user's explicit confirmation")
	// ErrCashHubConnection is a cashhub1 string given where a bill was expected.
	ErrCashHubConnection = errors.New("nipcash/client: this is a Cash Hub connection, not a bill; use ConnectCashHub")
	// ErrSecretIsConnectionSecret is a bill's own TLV 2 secret presented as its
	// cash secret: it opens nothing.
	ErrSecretIsConnectionSecret = errors.New("nipcash/client: that is the bill's connection secret, not its cash secret")
	// ErrZapContextRequired is a zap bill dialled without its Cash Zap context.
	ErrZapContextRequired = errors.New("nipcash/client: a zap bill needs its Cash Zap context to verify its provenance")
	// ErrMixedOrdered is consolidate sources whose ordered marks differ.
	ErrMixedOrdered = errors.New("nipcash/client: ordered and unordered bills cannot be consolidated together")
)

// FinalError is a BAD_REQUEST answered to a call carrying a request_id: the call
// never committed, and the caller closes it.
type FinalError struct{ Method, Code, Message, Detail string }

func (e *FinalError) Error() string {
	return fmt.Sprintf("nipcash/client: %s refused, final: %s: %s", e.Method, e.Code, e.Message)
}

// IndeterminateError is any other answer to a call carrying a request_id — a
// code other than BAD_REQUEST, an omission, an unanswered or conflicting item,
// an undecodable result, a timeout after publish. The call stays pending and is
// looked up (NIP-CASH §Errors: a client MUST NOT read it as a failure).
type IndeterminateError struct {
	Call          nipcash.PendingCall
	Code, Message string
	Detail        string
	Cause         error
}

func (e *IndeterminateError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("nipcash/client: %s %s is pending (answered %s: %s); look it up", e.Call.Method, e.Call.RequestID, e.Code, e.Message)
	}
	return fmt.Sprintf("nipcash/client: %s %s is pending; look it up: %v", e.Call.Method, e.Call.RequestID, e.Cause)
}

func (e *IndeterminateError) Unwrap() error { return e.Cause }

// NeedsLookup reports an outcome of a call carrying a request_id that has no
// decided answer: anything but a decoded result or a BAD_REQUEST.
func (o ItemOutcome) NeedsLookup() bool {
	if o.RequestID == "" {
		return false
	}
	switch {
	case o.State == OutcomeResult && !o.Undecodable:
		return false
	case o.Gone != nil:
		// A tombstone answer is decided: the bill is destroyed and nothing moved.
		return false
	case o.State == OutcomeError && o.Error != nil && nipcash.FinalCode(o.Error.Code):
		return false
	}
	return true
}

// callOutcome turns one bill-creating call's outcome into the caller's error:
// nil for a result, *FinalError for BAD_REQUEST, *IndeterminateError otherwise.
// It records the coded refusal on the pending call (LastCode, SawReused).
func callOutcome(o ItemOutcome, pc *nipcash.PendingCall, sendErr error) error {
	if o.State == OutcomeResult && !o.Undecodable {
		return nil
	}
	if o.Gone != nil {
		return &nipcash.BillGone{Method: pc.Method, Tombstone: *o.Gone}
	}
	if o.State == OutcomeError && o.Error != nil && o.Gone == nil && !o.Undecodable {
		code := o.Error.Code
		if nipcash.FinalCode(code) {
			return &FinalError{Method: pc.Method, Code: code, Message: o.Error.Message, Detail: o.Error.Detail}
		}
		if code == nipcash.ErrCodeRequestReused {
			pc.SawReused = true
		} else {
			pc.LastCode = code
		}
		return &IndeterminateError{Call: *pc, Code: code, Message: o.Error.Message, Detail: o.Error.Detail, Cause: sendErr}
	}
	cause := sendErr
	if cause == nil {
		cause = fmt.Errorf("outcome %v", o.State)
	}
	return &IndeterminateError{Call: *pc, Cause: cause}
}

// oneCall is the single-call wrappers' error for a call carrying a request_id:
// callOutcome over the call written ahead, or the send error when nothing was.
func oneCall(o ItemOutcome, sendErr error, method string) error {
	if o.pending == nil {
		if o.Gone != nil {
			return &nipcash.BillGone{Method: method, Tombstone: *o.Gone}
		}
		return oneItemOutcome(o.State, o.Error, sendErr, method)
	}
	pc := *o.pending
	return callOutcome(o, &pc, sendErr)
}
