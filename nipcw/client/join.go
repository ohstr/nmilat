package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nip47"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// ErrPrivateJoinUnavailable means JoinOptions.RequirePrivate was set and the
// join could not travel over the private transport, so nothing was sent.
var ErrPrivateJoinUnavailable = errors.New("nipcw/client: private join is unavailable")

// ErrJoinNotSent means Join failed before any join request was sent, so no
// wallet was created and the join is safe to retry.
var ErrJoinNotSent = errors.New("nipcw/client: join not sent")

// JoinOptions tunes Join.
type JoinOptions struct {
	// RequirePrivate refuses with ErrPrivateJoinUnavailable rather than join
	// over the shared Hub connection, where the requester's pubkey is visible
	// to every co-member and the join to every relay observer.
	RequirePrivate bool
}

// JoinResult is a Join's wallet and how the request travelled.
type JoinResult struct {
	*nipcw.CreateCircleWalletResponse
	// Private reports whether the join went over the private transport.
	Private bool
	// FallbackReason is set when the Hub offers Private Join but the join went
	// over the standard transport anyway. A client SHOULD tell the member the
	// join was not private (NIP-CW §Finding the Private Transport).
	FallbackReason error
}

// Join requests the caller's own Circle Wallet, over the private transport when
// the Hub offers it (NIP-CW §Private Join) and the standard one otherwise.
//
// The node identity is read only from this connection's get_info, whose reply
// the Hub connection key authenticates. If its announcement cannot be found or
// verified, Join falls back to the standard transport and says so in
// FallbackReason. Once a private request is sent it never falls back: a missing
// reply may mean the join ran.
//
// Refusals carry the standard join's codes either way (nipcw.ErrNotReady,
// ErrRestricted, ErrWalletExists, ErrRateLimited) as a *relayclient.WalletError.
// A private join the Hub did not answer is a *cashclient.NotServedError. A
// standard join that fails after a fallback also wraps the fallback reason, so
// errors.Is(err, cashclient.ErrNoAnnouncement) reports it was not private.
// Failures before any join is sent (get_info, generating the connection key)
// wrap ErrJoinNotSent along with their cause; failures after it never do.
// ErrPrivateJoinUnavailable also means nothing was sent.
//
// As with CreateCircleWallet, a zero params.Connection gets a fresh key whose
// secret appears only in the result; a caller that must survive a lost reply
// sets and saves its own.
func (c *Client) Join(ctx context.Context, params nipcw.CreateCircleWalletParams, opts JoinOptions) (*JoinResult, error) {
	params, err := withConnectionKey(params)
	if err != nil {
		return nil, fmt.Errorf("%w: connection key: %w", ErrJoinNotSent, err)
	}
	return join(ctx, c.nwc.GetInfo, opts,
		func(ctx context.Context, identity string) (*nipcw.CreateCircleWalletResponse, error) {
			return c.privateJoin(ctx, identity, params)
		},
		func(ctx context.Context) (*nipcw.CreateCircleWalletResponse, error) {
			return c.CreateCircleWallet(ctx, params)
		})
}

type joinFunc func(ctx context.Context) (*nipcw.CreateCircleWalletResponse, error)

type privateJoinFunc func(ctx context.Context, identity string) (*nipcw.CreateCircleWalletResponse, error)

// unavailableError marks a private join that failed before anything was sent,
// which is the only case Join may fall back from.
type unavailableError struct{ err error }

func (e *unavailableError) Error() string { return e.err.Error() }
func (e *unavailableError) Unwrap() error { return e.err }

// join is Join's transport choice, apart from the network so it can be tested.
func join(ctx context.Context, getInfo func(context.Context) (*nip47.GetInfoResult, error), opts JoinOptions, private privateJoinFunc, standard joinFunc) (*JoinResult, error) {
	result, err := getInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: get_info: %w", ErrJoinNotSent, err)
	}
	info := result.CircleWallet
	if info == nil || info.Identity == "" {
		if opts.RequirePrivate {
			return nil, fmt.Errorf("%w: the Hub does not offer it", ErrPrivateJoinUnavailable)
		}
		resp, err := standard(ctx)
		if err != nil {
			return nil, err
		}
		return &JoinResult{CreateCircleWalletResponse: resp}, nil
	}

	resp, err := private(ctx, info.Identity)
	if err == nil {
		return &JoinResult{CreateCircleWalletResponse: resp, Private: true}, nil
	}
	var unavailable *unavailableError
	if !errors.As(err, &unavailable) {
		return nil, err
	}
	if opts.RequirePrivate {
		return nil, fmt.Errorf("%w: %w", ErrPrivateJoinUnavailable, unavailable.err)
	}
	resp, err = standard(ctx)
	if err != nil {
		// Both wrapped, so errors.Is still finds why the join was not private.
		return nil, fmt.Errorf("%w (after private join was unavailable: %w)", err, unavailable.err)
	}
	return &JoinResult{CreateCircleWalletResponse: resp, FallbackReason: unavailable.err}, nil
}

// privateJoin sends one join over the private transport. Failures before the
// request is sent are wrapped in unavailableError.
func (c *Client) privateJoin(ctx context.Context, identity string, params nipcw.CreateCircleWalletParams) (*nipcw.CreateCircleWalletResponse, error) {
	session, err := cashclient.OpenBatchSession(ctx, identity, c.pairing.RelayURLs)
	if err != nil {
		return nil, &unavailableError{err: err}
	}
	hub, err := cashclient.BillFromParts(c.hubPubkey, c.pairing.Secret)
	if err != nil {
		return nil, &unavailableError{err: err}
	}
	outcomes, sendErr := session.CreateCircleWalletMany(ctx, []cashclient.BatchCircleJoin{{ID: "join", Hub: hub, Params: params}})
	if len(outcomes) == 0 && sendErr != nil {
		// No outcomes means the item was never packed, so nothing was sent.
		return nil, &unavailableError{err: sendErr}
	}
	if len(outcomes) != 1 {
		return nil, &cashclient.NotServedError{Method: nipcw.MethodCreateCircleWallet}
	}
	o := outcomes[0]
	switch {
	case o.Succeeded():
		return o.Result, nil
	case o.Undecodable:
		// The Hub ran the join, so this is not a refusal: the wallet may exist.
		return nil, fmt.Errorf("nipcw/client: the Hub answered the join but its reply could not be read, so the wallet may exist: %s", o.Error.Message)
	case o.State == cashclient.OutcomeError && o.Error != nil:
		return nil, &relayclient.WalletError{Method: nipcw.MethodCreateCircleWallet, Code: o.Error.Code, Message: o.Error.Message}
	case sendErr != nil:
		return nil, sendErr
	default:
		return nil, &cashclient.NotServedError{Method: nipcw.MethodCreateCircleWallet}
	}
}
