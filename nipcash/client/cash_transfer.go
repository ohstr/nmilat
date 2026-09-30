package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashTransfer reassigns an unredeemed slice's identity, or splits part of its value
// off into a new cash token — see nipcash.CashTransferResult's own doc comment for how
// to tell an in-place reassignment from a spun-off wallet apart in the response.
//
// Travels over the private transport. The spun-off wallet's token arrives encrypted to
// its new owner and is decrypted with params' own credential on the way back.
func (c *Client) CashTransfer(ctx context.Context, params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	outcomes, sendErr := session.TransferMany(ctx, []BatchTransfer{{
		ID: "1", Bill: bill, Params: params,
	}})
	if len(outcomes) == 0 {
		return nil, oneItemOutcome(OutcomeNotServed, nil, sendErr, nipcash.MethodCashTransfer)
	}
	o := outcomes[0]
	if err := oneItemOutcome(o.State, o.Error, sendErr, nipcash.MethodCashTransfer); err != nil {
		return nil, err
	}
	return o.Result, nil
}
