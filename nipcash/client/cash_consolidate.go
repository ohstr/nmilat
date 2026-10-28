package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashConsolidate combines several same-hub slices this node custodies into one new
// cash token. Sources need not belong to the calling connection — authorization is
// per-source, proved by each Source's own Credential.
//
// cred authorizes the CALL itself, separately from each source's own credential. On
// the standard transport that was implicit in the connection; the private transport
// authorizes per item, so it has to be said.
//
// The merged wallet's token arrives encrypted to its new owner and is decrypted on the
// way back.
func (c *Client) CashConsolidate(ctx context.Context, params nipcash.CashConsolidateParams, j Journal, device string) (*nipcash.CashConsolidateResult, error) {
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	outcomes, sendErr := session.ConsolidateMany(ctx, []BatchConsolidate{{
		ID: "1", Bill: bill, Params: params,
	}}, j, device)
	if len(outcomes) == 0 {
		if sendErr == nil {
			sendErr = &NotServedError{Method: nipcash.MethodCashConsolidate}
		}
		return nil, sendErr
	}
	o := outcomes[0]
	if err := oneCall(o.ItemOutcome, sendErr, nipcash.MethodCashConsolidate); err != nil {
		return nil, err
	}
	return o.Result, nil
}
