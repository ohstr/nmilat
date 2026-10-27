package client

import (
	"context"
	"errors"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

// ErrCancelAnswer is a cancel answer that cannot be right, such as
// REQUEST_REUSED (a cancel request marks no request_id): a Hub bug, shown.
var ErrCancelAnswer = errors.New("nipcash/client: the Hub's answer to a cancel request is malformed")

// CancelWithdraw asks the Hub to cancel a payout broadcast but still
// unconfirmed 7 days after its sent_by (NIP-CASH §Cancelling a Payout). It is
// not a call: nothing is written to the journal, and asking again is harmless.
// Before sent_by + 7 days (from the call's quote) it is refused locally, nothing
// sent (*CancelRefusedError with Local). The answer is the payout's current
// state, checked as LookupWithdraw checks a done (still broadcast while the
// invalidation confirms, then cancelled with the re-minted bill), or a
// *CancelRefusedError; no answer is a *NotServedError: ask again later.
func (c *Client) CancelWithdraw(ctx context.Context, pc nipcash.PendingCall, cred nipcash.Credential) (*nipcash.Payout, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	s, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return s.cancelWithdraw(ctx, bill, pc, cred, time.Now().Unix())
}

func (s *BatchSession) cancelWithdraw(ctx context.Context, bill Bill, pc nipcash.PendingCall, cred nipcash.Credential, now int64) (*nipcash.Payout, error) {
	if pc.Quote != "" {
		q, err := nipcash.ParseWithdrawQuote(pc.Quote)
		if err != nil {
			return nil, err
		}
		if now < q.SentBy+nipcash.CancelRequestAfter {
			return nil, &CancelRefusedError{Code: nipcash.ErrCodeRestricted, Message: "a cancel request comes 7 days after sent_by", Local: true}
		}
	}
	outs, sendErr := s.WithdrawCancelMany(ctx, []BatchWithdrawCancel{{ID: "1", Bill: bill, Call: pc, Credential: cred}})
	if len(outs) == 0 {
		if sendErr == nil {
			sendErr = &NotServedError{Method: nipcash.MethodCashWithdraw}
		}
		return nil, sendErr
	}
	o := outs[0]
	switch {
	case o.Result != nil:
		if o.Result.Tx != "" && o.Result.Txid != "" && o.Result.Vout != nil {
			o.Result.TxErr = nipcash.VerifyPayoutTx(o.Result.Tx, o.Result.Txid, *o.Result.Vout, o.Result.Address, "", o.Result.PayoutMillis)
		}
		return o.Result, nil
	case o.State == OutcomeError && o.Error != nil && !o.Undecodable && o.Gone == nil:
		if o.Error.Code == nipcash.ErrCodeRequestReused {
			return nil, ErrCancelAnswer
		}
		return nil, &CancelRefusedError{Code: o.Error.Code, Message: o.Error.Message}
	case o.Undecodable || o.Gone != nil:
		return nil, ErrCancelAnswer
	}
	if sendErr != nil {
		return nil, sendErr
	}
	return nil, &NotServedError{Method: nipcash.MethodCashWithdraw}
}
