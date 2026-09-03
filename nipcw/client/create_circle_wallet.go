package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcw"
)

// CreateCircleWallet self-service requests the caller's own Circle Wallet.
// Called over a Circle Wallet Hub connection.
func (c *Client) CreateCircleWallet(ctx context.Context, params nipcw.CreateCircleWalletParams) (*nipcw.CreateCircleWalletResponse, error) {
	req, err := params.Request(c.HubPubkey())
	if err != nil {
		return nil, err
	}
	raw, err := rawCall(ctx, c, nipcw.MethodCreateCircleWallet, req)
	if err != nil {
		return nil, err
	}
	return params.ParseResult(c.HubPubkey(), raw)
}
