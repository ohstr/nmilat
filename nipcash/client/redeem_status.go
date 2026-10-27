package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
)

// ErrNeedsStatus is a redeem whose outcome this client did not learn: it may
// have paid, may still pay, or may have done nothing. The caller reads
// cash_status of its own row (RedeemFollowUp) and never resends the redeem
// blind (NIP-CASH §Answering About a Destroyed Bill, §Redeeming a Slice).
var ErrNeedsStatus = errors.New("nipcash/client: the redeem's outcome is unknown; read cash_status of your own row, never resend it blind")

// NeedsStatusError is a redeem that needs a status read before anything else.
// Code and Message are the Hub's when it answered (INTERNAL), "" after an
// omission, an unanswered or conflicting item, a timeout or an undecodable
// result. Cause is what the redeem returned before (a *NotServedError, a
// relay/client *WalletError, ErrIncompleteReply, a context error), so
// errors.As on those keeps working.
type NeedsStatusError struct {
	Code, Message string
	Cause         error
}

func (e *NeedsStatusError) Error() string {
	why := "no answer"
	if e.Code != "" {
		why = e.Code
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s (%s): %v", ErrNeedsStatus.Error(), why, e.Cause)
	}
	return fmt.Sprintf("%s (%s)", ErrNeedsStatus.Error(), why)
}

// Unwrap matches ErrNeedsStatus and the cause.
func (e *NeedsStatusError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrNeedsStatus}
	}
	return []error{ErrNeedsStatus, e.Cause}
}

// NeedsStatus reports a redeem item whose outcome is unknown: omitted,
// unanswered, conflicting, a result that did not decode, or refused INTERNAL
// (a Hub answers INTERNAL while the payment may still settle). An
// envelope-level refusal is not one (no item ran), nor is any other code,
// nor an item that was never sent. Such an item is never resent: the caller
// reads cash_status of its own row (RedeemFollowUp, nipcash.RedeemProgressOf).
func (o RedeemOutcome) NeedsStatus() bool {
	switch o.State {
	case OutcomeNotServed, OutcomeUnanswered, OutcomeConflict:
		return true
	case OutcomeError:
		if o.envelopeLevel || o.Gone != nil {
			return false
		}
		return o.Undecodable || (o.Error != nil && o.Error.Code == nipcash.ErrCodeInternal)
	}
	return false
}

// needsStatus builds the error for an item NeedsStatus holds.
func needsStatus(o RedeemOutcome, cause error) *NeedsStatusError {
	e := &NeedsStatusError{Cause: cause}
	if o.State == OutcomeError && !o.Undecodable && o.Error != nil {
		e.Code, e.Message = o.Error.Code, o.Error.Message
	}
	if e.Cause == nil {
		e.Cause = &NotServedError{Method: nipcash.MethodCashRedeem}
	}
	return e
}

// RedeemFollowUp is the read after a redeem that needs one: cash_status of the
// caller's own row (scope mine, with the redeem's credential), read through
// nipcash.RedeemProgressOf:
//
//	RedeemReleased  the row is unclaimed: the bill is live again; a new
//	                redeem needs a fresh invoice and proof
//	RedeemDone      the bill is gone: spent, with the tombstone's reason
//	                (result.Tombstone)
//	RedeemInFlight  the row is claimed: the caller's redeeming state, read
//	                again on its next status refresh; never resent, never
//	                reported spent or failed on the strength of the redeem
//
// A read that fails, or a mine answer that is not exactly the caller's row
// (nipcash.ErrMineWidened, LocalReason status_widened), returns RedeemInFlight
// with the error: nothing is decided, and the caller keeps the redeeming state.
func (c *Client) RedeemFollowUp(ctx context.Context, cred nipcash.Credential) (nipcash.RedeemProgress, *nipcash.CashStatusResult, error) {
	status, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil {
		return nipcash.RedeemInFlight, nil, err
	}
	if status.Tombstone != nil {
		return nipcash.RedeemProgressOf(nil, status.Tombstone), status, nil
	}
	row, err := nipcash.OwnRow(status.Recipients, cred, nipcash.ScopeMine)
	if err != nil {
		return nipcash.RedeemInFlight, status, err
	}
	return nipcash.RedeemProgressOf(&row, nil), status, nil
}
