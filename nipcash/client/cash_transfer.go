package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashTransfer reassigns an unredeemed slice's identity, or splits part of
// its value off into a new cash token — see nipcash.CashTransferResult's
// own doc comment for how to tell an in-place reassignment from a spun-off
// wallet apart in the response. Called over a Cash Wallet connection.
func (c *Client) CashTransfer(ctx context.Context, params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
	req, err := params.Request(c.WalletPubkey())
	if err != nil {
		return nil, err
	}
	raw, err := rawCall(ctx, c, nipcash.MethodCashTransfer, req)
	if err != nil {
		return nil, err
	}
	return params.ParseResult(raw)
}
