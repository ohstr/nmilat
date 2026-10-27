package client

import (
	"context"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// mintDeadline is how far ahead a mint's NIP-47 expiration is set here: within
// DeadlineWindow of the smallest horizon a Hub may announce.
const mintDeadline = 30 * time.Second

// MintCash mints cash over a Cash Hub connection. It fills a missing RequestID
// with a fresh one and sets the NIP-47 expiration the call requires. The result
// comes back with any error ParseResult found, since funds may be committed.
func (c *Client) MintCash(ctx context.Context, params nipcash.MintCashParams) (*nipcash.MintCashResult, error) {
	if params.RequestID == "" {
		rid, err := nipcash.NewRequestID()
		if err != nil {
			return nil, err
		}
		params.RequestID = rid
	}
	req, err := params.Request()
	if err != nil {
		return nil, err
	}
	resp, err := c.nwc.CallWithOptions(ctx, nipcash.MethodMintCash, req,
		nip47.WithExpiration(time.Now().Add(mintDeadline).Unix()))
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &relayclient.WalletError{Method: nipcash.MethodMintCash, Code: resp.Error.Code, Message: resp.Error.Message}
	}
	return params.ParseResult(resp.Result)
}
