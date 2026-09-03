package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashRedeem collects one recipient's exact slice by presenting a fresh
// Lightning invoice. Called over a Cash Wallet connection.
func (c *Client) CashRedeem(ctx context.Context, params nipcash.CashRedeemParams) (*nipcash.CashRedeemResult, error) {
	req, err := params.Request(c.WalletPubkey())
	if err != nil {
		return nil, err
	}
	return call[nipcash.CashRedeemResult](ctx, c, nipcash.MethodCashRedeem, req)
}
