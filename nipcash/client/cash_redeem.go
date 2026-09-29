package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashRedeem collects one recipient's exact slice by presenting a fresh Lightning
// invoice.
//
// Travels over the private transport, as every bill method does — it is the only
// transport that serves them (NIP-CASH §The Private Transport). The session is opened
// on first use and reused; a caller never sees it.
//
// A hub that returns no answer for this item is an ERROR here, not a nil result. An
// omission is information-free by design, so "the redeem may or may not have happened"
// is the honest report — and for a method that moves money it is the difference
// between asking and double-paying.
func (c *Client) CashRedeem(ctx context.Context, params nipcash.CashRedeemParams) (*nipcash.CashRedeemResult, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	outcomes, sendErr := session.RedeemMany(ctx, []BatchRedeem{{
		ID: "1", Target: c.WalletPubkey(), Params: params,
	}})
	if len(outcomes) == 0 {
		return nil, oneItemOutcome(OutcomeNotServed, nil, sendErr, nipcash.MethodCashRedeem)
	}
	o := outcomes[0]
	if err := oneItemOutcome(o.State, o.Error, sendErr, nipcash.MethodCashRedeem); err != nil {
		return nil, err
	}
	return o.Result, nil
}
