package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrJoinNotSent means Join failed before any join request was sent, so no
// wallet was created and the join is safe to retry.
var ErrJoinNotSent = errors.New("nipcw/client: join not sent")

// JoinOptions tunes Join.
type JoinOptions struct{}

// JoinResult is a Join's wallet.
type JoinResult struct {
	*nipcw.CreateCircleWalletResponse
}

// Join requests the caller's own Circle Wallet over the private transport, the
// only one a join travels on (NIP-CW §Private Join). The node identity is read
// only from this connection's get_info. A Hub without a verified announcement
// gets no join: the error wraps ErrJoinNotSent.
func (c *Client) Join(ctx context.Context, params nipcw.CreateCircleWalletParams, _ JoinOptions) (*JoinResult, error) {
	if params.Connection.IsZero() {
		key, err := nipcw.NewConnectionKey()
		if err != nil {
			return nil, fmt.Errorf("%w: connection key: %w", ErrJoinNotSent, err)
		}
		params.Connection = key
	}
	info, err := c.nwc.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: get_info: %w", ErrJoinNotSent, err)
	}
	if info.CircleWallet == nil || info.CircleWallet.Identity == "" {
		return nil, fmt.Errorf("%w: the connection is not a Circle Wallet Hub", ErrJoinNotSent)
	}
	session, err := cashclient.OpenBatchSession(ctx, info.CircleWallet.Identity, c.pairing.RelayURLs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	hub, err := cashclient.BillFromParts(c.hubPubkey, c.pairing.Secret)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	j, err := params.Prepare(c.hubPubkey, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	outcomes, sendErr := session.CreateCircleWalletMany(ctx, []cashclient.BatchCircleJoin{{ID: "join", Hub: hub, Join: j}})
	if len(outcomes) == 0 && sendErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, sendErr)
	}
	if len(outcomes) != 1 {
		return nil, &cashclient.NotServedError{Method: nipcw.MethodCreateCircleWallet}
	}
	o := outcomes[0]
	switch {
	case o.Succeeded():
		return &JoinResult{CreateCircleWalletResponse: o.Result}, nil
	case o.State == cashclient.OutcomeError && o.Error != nil && !o.Undecodable:
		return nil, &relayclient.WalletError{Method: nipcw.MethodCreateCircleWallet, Code: o.Error.Code, Message: o.Error.Message}
	case sendErr != nil:
		return nil, sendErr
	default:
		return nil, &cashclient.NotServedError{Method: nipcw.MethodCreateCircleWallet}
	}
}
