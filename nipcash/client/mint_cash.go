package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// MintCash funds and mints cash tokens for one or more recipients. Called
// over a Cash Hub connection.
func (c *Client) MintCash(ctx context.Context, params nipcash.MintCashParams) (*nipcash.MintCashResult, error) {
	req, err := params.Request()
	if err != nil {
		return nil, err
	}
	return call[nipcash.MintCashResult](ctx, c, nipcash.MethodMintCash, req)
}
