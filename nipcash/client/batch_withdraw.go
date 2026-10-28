package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// BatchWithdrawQuote asks one bill what an on-chain withdrawal of the caller's
// slice would pay (NIP-CASH §Quoting a Withdrawal). It moves nothing and
// carries no request_id.
type BatchWithdrawQuote struct {
	ID     string
	Bill   Bill
	Params nipcash.CashWithdrawQuoteParams
}

// WithdrawQuoteOutcome is one quote answer, parsed but not yet checked: run
// nipcash.VerifyQuoteAnswer before showing or using it.
type WithdrawQuoteOutcome struct {
	ItemOutcome
	Result *nipcash.CashWithdrawQuoteResult
}

// WithdrawQuoteMany asks for several quotes in one request.
func (s *BatchSession) WithdrawQuoteMany(ctx context.Context, items []BatchWithdrawQuote) ([]WithdrawQuoteOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	for i, it := range items {
		it := it
		builders = append(builders, itemBuilder{
			ID: itemID(it.ID, i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				if err := it.Bill.check(id, s.HubIdentity()); err != nil {
					return transport.Item{}, err
				}
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]WithdrawQuoteOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		qo := WithdrawQuoteOutcome{ItemOutcome: o}
		if o.Succeeded() {
			r, err := nipcash.ParseCashWithdrawQuoteResult(o.Result)
			if err != nil {
				qo.ItemOutcome = parseFailure(qo.ItemOutcome, err)
			} else {
				qo.Result = r
			}
		}
		out = append(out, qo)
	}
	return out, sendErr
}

// BatchWithdraw accepts one quote and ends the slice (NIP-CASH §Redeeming
// On-chain). Params.Quote is the quote nipcash.VerifyQuoteAnswer returned and
// the caller's user confirmed (its Address, PayoutMillis, FeeMillis() and
// AmountMillis); RequestID and Notify are generated when empty, and for a
// BySecret credential a fresh Remint target when nil.
type BatchWithdraw struct {
	ID     string
	Bill   Bill
	Params nipcash.CashWithdrawParams
}

// WithdrawOutcome is one withdrawal's answer. Result is set only for a reply
// that parsed as a queued payout whose receipt verified against the call;
// ReceiptErr says why a reply was not accepted (it wraps
// nipcash.ErrReceiptInvalid for a receipt that does not verify). Such an
// outcome needs a lookup: the call stays pending and its source is not spent.
type WithdrawOutcome struct {
	ItemOutcome
	Result     *nipcash.Payout
	ReceiptErr error
}

// ErrWithdrawReply is a reply to a fresh cash_withdraw that is not a queued
// payout.
var ErrWithdrawReply = errors.New("nipcash/client: a fresh withdrawal's reply is not a queued payout")

// prepareWithdraw fills a withdrawal's generated parts: request_id, notify and,
// for a BySecret credential, the re-mint target.
func prepareWithdraw(p nipcash.CashWithdrawParams, target string) (nipcash.CashWithdrawParams, nipcash.PendingCall, error) {
	var err error
	if p.RequestID == "" {
		if p.RequestID, err = nipcash.NewRequestID(); err != nil {
			return p, nipcash.PendingCall{}, err
		}
	}
	if p.Notify == "" {
		if p.Notify, err = nipCO.NewNotify(); err != nil {
			return p, nipcash.PendingCall{}, err
		}
	}
	pc, err := p.Pending(target)
	if errors.Is(err, nipcash.ErrRemintRequired) {
		if p.Remint, err = nipcash.NewCashTarget(); err != nil {
			return p, nipcash.PendingCall{}, err
		}
		pc, err = p.Pending(target)
	}
	return p, pc, err
}

// WithdrawMany places several withdrawals in one request. Each carries a
// request_id and is written ahead to j, as device's, with its envelope's exact
// deadline, its quote, address, notify and re-mint secret, before anything is
// published; a Journal implementing AcceptedRecorder is told the accepting
// relays. A reply is accepted only as a queued payout whose receipt verifies
// (else the outcome is undecodable, ReceiptErr set, and needs a lookup).
func (s *BatchSession) WithdrawMany(ctx context.Context, items []BatchWithdraw, j Journal, device string) ([]WithdrawOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	byID := make(map[string]BatchWithdraw, len(items))
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		if err := it.Bill.check(id, s.HubIdentity()); err != nil {
			return nil, err
		}
		if it.Params.Quote == nil || it.Params.Quote.Event == nil {
			return nil, fmt.Errorf("nipcash/client: item %q has no quote", id)
		}
		if h, err := it.Params.Quote.Event.HashID(); err != nil || fmt.Sprintf("%x", h) != it.Params.Quote.ID {
			return nil, fmt.Errorf("nipcash/client: item %q: the quote's id does not recompute", id)
		}
		params, pc, err := prepareWithdraw(it.Params, it.Bill.target)
		if err != nil {
			return nil, err
		}
		it.Params = params
		byID[id] = it
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return it.Params.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
			RequestID: it.Params.RequestID,
			Pending:   s.pendingAt(pc),
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{journal: j, device: device})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]WithdrawOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		wo := WithdrawOutcome{ItemOutcome: o}
		if o.Succeeded() {
			it := byID[o.ID]
			p, err := it.Params.ParseLookupResult(o.Result)
			switch {
			case err != nil:
				wo.ItemOutcome = parseFailure(wo.ItemOutcome, err)
				wo.ReceiptErr = err
			case p.State != nipcash.PayoutQueued:
				wo.ItemOutcome = parseFailure(wo.ItemOutcome, ErrWithdrawReply)
				wo.ReceiptErr = ErrWithdrawReply
			default:
				q := it.Params.Quote
				err = nipcash.VerifyWithdrawReceipt(p.Receipt, nipcash.ReceiptExpectation{HubXOnly: s.HubIdentity(), Target: it.Bill.target,
					QuoteID: q.ID, RequestID: it.Params.RequestID, Address: q.Address, PayoutMillis: q.PayoutMillis, SentBy: q.SentBy})
				if err == nil && (p.Address != q.Address || p.PayoutMillis != q.PayoutMillis || p.SentBy != q.SentBy || p.AmountMillis != q.AmountMillis) {
					err = fmt.Errorf("%w: the payout differs from the quote", nipcash.ErrReceiptInvalid)
				}
				if err != nil {
					wo.ItemOutcome = parseFailure(wo.ItemOutcome, err)
					wo.ReceiptErr = err
				} else {
					wo.Result = p
				}
			}
		}
		out = append(out, wo)
	}
	return out, sendErr
}

// CallError is the caller's error for one withdrawal outcome: nil for an
// accepted payout; *FinalError for BAD_REQUEST; else *IndeterminateError (look
// it up), with Cause the ReceiptErr for a reply that was not accepted.
func (o WithdrawOutcome) CallError(sendErr error) error {
	if o.Result != nil {
		return nil
	}
	if o.ReceiptErr != nil {
		if pc, ok := o.Pending(); ok {
			return &IndeterminateError{Call: pc, Cause: o.ReceiptErr}
		}
	}
	return oneCall(o.ItemOutcome, sendErr, nipcash.MethodCashWithdraw)
}

// BatchWithdrawLookup looks one withdrawal up (NIP-CASH §Withdrawals): a
// cash_lookup naming the bill, with the call's request_id and its deadline
// (now for a call recovered from withdraw_request_id, which has none), the item
// proof by Credential (the claim-proof signer), and for a cash-authorized call
// CashSecret only when set (send it only after an UNAUTHORIZED).
type BatchWithdrawLookup struct {
	ID         string
	Bill       Bill
	Call       nipcash.PendingCall
	Credential nipcash.Credential
	CashSecret string
}

// LookupWithdrawMany looks several withdrawals up in one request and returns
// one LookupOutcome per item, in order. A done's Result is the payout; check it
// with LookupWithdraw's rules (or Recover's).
func (s *BatchSession) LookupWithdrawMany(ctx context.Context, items []BatchWithdrawLookup) ([]LookupOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	ids := make([]string, len(items))
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		ids[i] = id
		if err := it.Bill.check(id, s.HubIdentity()); err != nil {
			return nil, err
		}
		if it.Call.Method != nipcash.MethodCashWithdraw {
			return nil, fmt.Errorf("nipcash/client: item %q is a %s call, not a withdrawal", id, it.Call.Method)
		}
		p := nipcash.CashLookupParams{Credential: it.Credential, Request: nipcash.CashLookupRequest{
			RequestID: it.Call.RequestID, Deadline: lookupDeadline(it.Call), CashSecret: it.CashSecret,
		}}
		if err := p.Request.Validate(); err != nil {
			return nil, err
		}
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return p.Item(id, it.Bill.target, it.Bill.connSecret, b)
			},
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if len(outcomes) == 0 && sendErr != nil && errors.Is(sendErr, ErrNotSent) {
		return nil, sendErr
	}
	byID := make(map[string]ItemOutcome, len(outcomes))
	for _, o := range outcomes {
		byID[o.ID] = o
	}
	out := make([]LookupOutcome, len(ids))
	for i, id := range ids {
		o, ok := byID[id]
		if !ok {
			out[i] = LookupOutcome{NotServed: true}
			continue
		}
		out[i] = lookupOutcomeOf(o)
	}
	return out, nil
}

// BatchWithdrawCancel is one cancel request (NIP-CASH §Cancelling a Payout): a
// cash_withdraw item naming the bill with {"cancel": true, "request_id"}, and
// the call's cash secret for a cash-authorized call. It is not a call: nothing
// is written ahead and sending it again is harmless.
type BatchWithdrawCancel struct {
	ID         string
	Bill       Bill
	Call       nipcash.PendingCall
	Credential nipcash.Credential
}

// WithdrawCancelOutcome is one cancel answer: the payout's current state (still
// broadcast while the invalidation confirms), its re-minted token decrypted
// with Credential under cancelled.
type WithdrawCancelOutcome struct {
	ItemOutcome
	Result *nipcash.Payout
}

// WithdrawCancelMany sends several cancel requests in one request.
func (s *BatchSession) WithdrawCancelMany(ctx context.Context, items []BatchWithdrawCancel) ([]WithdrawCancelOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	byID := make(map[string]BatchWithdrawCancel, len(items))
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		if err := it.Bill.check(id, s.HubIdentity()); err != nil {
			return nil, err
		}
		if it.Call.Method != nipcash.MethodCashWithdraw || !nipcash.ValidRequestID(it.Call.RequestID) {
			return nil, fmt.Errorf("nipcash/client: item %q does not name a withdrawal", id)
		}
		byID[id] = it
		req := nipcash.CashWithdrawCancelRequest{Cancel: true, RequestID: it.Call.RequestID, CashSecret: it.Call.SourceSecret}
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return nipcash.BuildItem(id, it.Bill.target, it.Bill.connSecret, nipcash.MethodCashWithdraw, req, it.Credential, b)
			},
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]WithdrawCancelOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		co := WithdrawCancelOutcome{ItemOutcome: o}
		if o.Succeeded() {
			it := byID[o.ID]
			// As a lookup's answer: the receipt, and a cancelled payout's
			// re-minted bill checked against this Hub and its wallet.
			p, err := s.checkPayout(withHub(it.Call, s.HubIdentity()), it.Credential, o.Result)
			if err != nil {
				co.ItemOutcome = parseFailure(co.ItemOutcome, err)
			} else {
				co.Result = p
			}
		}
		out = append(out, co)
	}
	return out, sendErr
}

// withHub is pc with its Hub identity set when it carries none.
func withHub(pc nipcash.PendingCall, hub string) nipcash.PendingCall {
	if pc.HubIdentity == "" {
		pc.HubIdentity = hub
	}
	return pc
}
