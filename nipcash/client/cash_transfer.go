package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashTransfer reassigns an unredeemed slice's identity, or splits part of its value
// off into a new cash token — see nipcash.CashTransferResult's own doc comment for how
// to tell an in-place reassignment from a spun-off wallet apart in the response.
//
// The call is written ahead to j, as device's, before it is sent. A BAD_REQUEST
// is a *FinalError (close the call); any other answer short of a result is an
// *IndeterminateError (look the call up); an error wrapping ErrNotSent means
// nothing was published (close the call as not sent).
//
// Travels over the private transport. The spun-off wallet's token arrives encrypted to
// its new owner and is decrypted with params' own credential on the way back.
func (c *Client) CashTransfer(ctx context.Context, params nipcash.CashTransferParams, j Journal, device string) (*nipcash.CashTransferResult, error) {
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
	}}, j, device)
	if len(outcomes) == 0 {
		if sendErr == nil {
			sendErr = &NotServedError{Method: nipcash.MethodCashTransfer}
		}
		return nil, sendErr
	}
	o := outcomes[0]
	if err := oneCall(o.ItemOutcome, sendErr, nipcash.MethodCashTransfer); err != nil {
		return nil, err
	}
	return o.Result, nil
}
