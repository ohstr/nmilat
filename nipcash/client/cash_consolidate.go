package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashConsolidate combines several same-hub slices this node custodies into
// one new cash token. Sources need not belong to the calling connection —
// authorization is per-source, proved by each Source's own Credential.
func (c *Client) CashConsolidate(ctx context.Context, params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
	req, err := params.Request()
	if err != nil {
		return nil, err
	}
	raw, err := rawCall(ctx, c, nipcash.MethodCashConsolidate, req)
	if err != nil {
		return nil, err
	}
	return params.ParseResult(raw)
}
