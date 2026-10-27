package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// LookupTransfer looks a transfer up on this client's bill. A bearer call (cred
// a BySecret) is looked up first without its cash secret, and again with it
// only after UNAUTHORIZED: the call committed, and the secret opens nothing.
func (c *Client) LookupTransfer(ctx context.Context, pc nipcash.PendingCall, cred nipcash.Credential) (LookupOutcome, error) {
	return c.lookupBill(ctx, pc, cred)
}

// LookupConsolidate looks a consolidate up on its first source, with that
// source's credential, as LookupTransfer.
func (c *Client) LookupConsolidate(ctx context.Context, pc nipcash.PendingCall, first nipcash.Credential) (LookupOutcome, error) {
	return c.lookupBill(ctx, pc, first)
}

func (c *Client) lookupBill(ctx context.Context, pc nipcash.PendingCall, cred nipcash.Credential) (LookupOutcome, error) {
	bill, err := c.bill()
	if err != nil {
		return LookupOutcome{}, err
	}
	s, err := c.billSession(ctx)
	if err != nil {
		return LookupOutcome{}, err
	}
	lo, err := s.lookup(ctx, bill, cred, pc, "")
	if err == nil && lo.Code == nipcash.ErrCodeUnauthorized && pc.SourceSecret != "" {
		return s.lookup(ctx, bill, cred, pc, pc.SourceSecret)
	}
	return lo, err
}

// lookup sends one cash_lookup item for pc and reads its answer: a coded
// refusal in Code, an omission or no reply NotServed, an answer that does not
// parse Malformed.
func (s *BatchSession) lookup(ctx context.Context, bill Bill, cred nipcash.Credential, pc nipcash.PendingCall, cashSecret string) (LookupOutcome, error) {
	p := nipcash.CashLookupParams{Credential: cred, Request: nipcash.CashLookupRequest{
		RequestID: pc.RequestID, Deadline: pc.Deadline, CashSecret: cashSecret,
	}}
	if err := p.Request.Validate(); err != nil {
		return LookupOutcome{}, err
	}
	outcomes, sendErr := s.sendBatch(ctx, []itemBuilder{{
		ID: "1",
		Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
			if err := bill.check(id, s.HubIdentity()); err != nil {
				return transport.Item{}, err
			}
			return p.Item(id, bill.target, bill.connSecret, b)
		},
	}}, sendOptions{})
	if len(outcomes) == 0 {
		if sendErr != nil && !errors.Is(sendErr, ErrNotSent) {
			return LookupOutcome{NotServed: true}, nil
		}
		if sendErr == nil {
			sendErr = errLookupNoOutcome
		}
		return LookupOutcome{}, sendErr
	}
	o := outcomes[0]
	switch o.State {
	case OutcomeResult:
		r, err := nipcash.ParseCashLookupResult(o.Result)
		if err != nil {
			return LookupOutcome{Malformed: true}, nil
		}
		return LookupOutcome{Status: r.Status, RetryAfter: r.RetryAfter, Result: r.Result}, nil
	case OutcomeError:
		if o.Undecodable || o.Error == nil {
			return LookupOutcome{Malformed: true}, nil
		}
		return LookupOutcome{Code: o.Error.Code}, nil
	}
	return LookupOutcome{NotServed: true}, nil
}
