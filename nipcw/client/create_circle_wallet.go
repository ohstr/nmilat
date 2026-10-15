package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcw"
)

// CreateCircleWallet self-service requests the caller's own Circle Wallet.
// Called over a Circle Wallet Hub connection.
//
// With params.Connection left zero, a fresh connection key is generated here
// and its secret appears only in the returned PairingURI. A caller that must not
// lose the secret if the reply is lost sets params.Connection itself and saves
// the secret first.
func (c *Client) CreateCircleWallet(ctx context.Context, params nipcw.CreateCircleWalletParams) (*nipcw.CreateCircleWalletResponse, error) {
	params, err := withConnectionKey(params)
	if err != nil {
		return nil, err
	}
	// The same params, and so the same key, build the request and parse the reply.
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

// withConnectionKey fills a zero params.Connection with a fresh key and leaves a
// caller-supplied one untouched.
func withConnectionKey(params nipcw.CreateCircleWalletParams) (nipcw.CreateCircleWalletParams, error) {
	if !params.Connection.IsZero() {
		return params, nil
	}
	key, err := nipcw.NewConnectionKey()
	if err != nil {
		return params, err
	}
	params.Connection = key
	return params, nil
}
