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

var (
	// ErrJoinNotSent means Join stopped before any join was sent, so no wallet was
	// made and the join is safe to retry (a journalled PendingJoin may be dropped).
	ErrJoinNotSent = errors.New("nipcw/client: join not sent")
	// ErrNoAnnouncement is a Hub whose kind-11190 announcement could not be found
	// or verified against its identity. Nothing is sent, never over the standard
	// transport either; the caller MAY try again later.
	ErrNoAnnouncement = fmt.Errorf("%w: no verified private-transport announcement", ErrJoinNotSent)
	// ErrNotAccepting is a Hub whose circle_wallet.accepting is false: the circle
	// is closed to joins. Nothing is sent; lookups still work.
	ErrNotAccepting = fmt.Errorf("%w: the Hub is not accepting joins", ErrJoinNotSent)
	// ErrRotationWarningRequired is a join to a Hub without rotation_delay_secs
	// and no JoinOptions.WarnNoRotation to warn the member first.
	ErrRotationWarningRequired = fmt.Errorf("%w: the Hub cannot rotate a lost connection, and no warning was given", ErrJoinNotSent)
	// ErrJoinDeclined is a member who declined WarnNoRotation's warning.
	ErrJoinDeclined = fmt.Errorf("%w: the member declined after the rotation warning", ErrJoinNotSent)
	// ErrOverHubLimit is a request over a limit get_info reports
	// (per_wallet_max_millis, per_wallet_max_receive_millis, min_budget_renewal,
	// max_exp_secs). The Hub would refuse it with LIMIT_EXCEEDED.
	ErrOverHubLimit = fmt.Errorf("%w: the request is over the Hub's reported limits", ErrJoinNotSent)
	// ErrNoJoinJournal is a Join without a JoinJournal: the secret and deadline
	// must be written ahead, or a lost reply loses the wallet.
	ErrNoJoinJournal = fmt.Errorf("%w: a join needs a journal", ErrJoinNotSent)
)

// JoinOptions tunes Join. Every join is private (NIP-CW §Private Join).
type JoinOptions struct {
	// WarnNoRotation warns the member, before a join to a Hub that cannot rotate
	// a lost connection, that losing the connection secret makes the balance
	// unreachable, and SHOULD offer a backup. It returns whether to go on.
	// Required for such a Hub: nil is ErrRotationWarningRequired.
	WarnNoRotation func(ctx context.Context) bool
}

// PendingJoin is what a join writes ahead before it is sent: enough to look it
// up and to hold the wallet when the reply is lost. ConnectionSecret never
// leaves the member.
type PendingJoin struct {
	HubPubkey, Pubkey, ConnectionPubkey, ConnectionSecret string
	Deadline                                              int64
}

// JoinJournal stores a PendingJoin durably before the join is sent.
type JoinJournal interface {
	WriteAhead(ctx context.Context, j PendingJoin) error
}

// JoinResult is a created wallet and the join that made it.
type JoinResult struct {
	*nipcw.CreateCircleWalletResponse
	Pending PendingJoin
}

// Wallet is the member's wallet connection: wallet_pubkey and relays from the
// details, and the secret the member kept.
func (r *JoinResult) Wallet() nipcw.WalletConnection {
	return nipcw.WalletConnection{WalletPubkey: r.WalletPubkey, Relays: r.Relays, Secret: r.Pending.ConnectionSecret}
}

// JoinIndeterminateError is a join that may have made the wallet: REQUEST_REUSED,
// an omission, no reply, or a reply that failed its checks. It is never a
// failure; look it up with LookupJoin.
type JoinIndeterminateError struct {
	Pending PendingJoin
	Code    string
	Cause   error
}

func (e *JoinIndeterminateError) Error() string {
	msg := "nipcw/client: the join's outcome is unknown; look it up"
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *JoinIndeterminateError) Unwrap() error { return e.Cause }

// Join requests the caller's own Circle Wallet over the private transport, the
// only one a join travels on. Before anything is written, in order:
//
//   - get_info passes the online check (Connect's) and describes a conforming
//     Hub, else ErrHubNonConforming;
//   - accepting is true, else ErrNotAccepting;
//   - the request is within the limits get_info reports, else ErrOverHubLimit;
//   - the Hub's announcement verifies against its identity, else
//     ErrNoAnnouncement;
//   - a Hub without rotation_delay_secs gets the member's WarnNoRotation first.
//
// Then the join is prepared (a fresh connection key when p.Connection is zero),
// written ahead to j with its secret and deadline, and sent. Every error above
// wraps ErrJoinNotSent.
//
// After sending, a refusal is a *relayclient.WalletError, final for that proof
// (BAD_REQUEST, UNAUTHORIZED, RESTRICTED, NOT_IMPLEMENTED, …): a retry is a new
// Join with a new proof. REQUEST_REUSED, an omission, no reply or a reply that
// fails its checks is a *JoinIndeterminateError.
func (c *Client) Join(ctx context.Context, p nipcw.CreateCircleWalletParams, o JoinOptions, j JoinJournal) (*JoinResult, error) {
	if j == nil {
		return nil, ErrNoJoinJournal
	}
	gi, err := c.info(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	cw := gi.CircleWallet
	if missing := cw.MissingAlways(); len(missing) > 0 {
		return nil, fmt.Errorf("%w: %w: circle_wallet lacks %v", ErrJoinNotSent, ErrHubNonConforming, missing)
	}
	if cw.AvailableMillis < 0 || cw.FeeReserve == nil || cw.Accepting == nil {
		return nil, fmt.Errorf("%w: %w: a negative available_millis or a null always field", ErrJoinNotSent, ErrHubNonConforming)
	}
	if !*cw.Accepting {
		return nil, ErrNotAccepting
	}
	if err := withinLimits(p, cw.PerWalletMaxMillis, cw.PerWalletMaxReceiveMillis, cw.MinBudgetRenewal, cw.MaxExpSecs); err != nil {
		return nil, err
	}
	session, err := c.batchSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoAnnouncement, err)
	}
	if cw.RotationDelaySecs == nil {
		if o.WarnNoRotation == nil {
			return nil, ErrRotationWarningRequired
		}
		if !o.WarnNoRotation(ctx) {
			return nil, ErrJoinDeclined
		}
	}
	if p.Connection.IsZero() {
		key, err := nipcw.NewConnectionKey()
		if err != nil {
			return nil, fmt.Errorf("%w: connection key: %w", ErrJoinNotSent, err)
		}
		p.Connection = key
	}
	hub, err := c.hubBill()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	prepared, err := p.Prepare(c.conn.Pubkey, time.Now())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, err)
	}
	pj := PendingJoin{HubPubkey: c.conn.Pubkey, Pubkey: prepared.Request.Pubkey, ConnectionPubkey: prepared.ConnectionPubkey,
		ConnectionSecret: p.Connection.Secret(), Deadline: prepared.Deadline}
	if err := j.WriteAhead(ctx, pj); err != nil {
		return nil, fmt.Errorf("%w: write ahead: %w", ErrJoinNotSent, err)
	}

	outcomes, sendErr := session.CreateCircleWalletMany(ctx, []cashclient.BatchCircleJoin{{ID: "join", Hub: hub, Join: prepared}})
	if len(outcomes) == 0 || outcomes[0].State == cashclient.OutcomeNotSent {
		// No outcome, or OutcomeNotSent: the item's envelope was never
		// published, so nothing was sent.
		if sendErr == nil {
			sendErr = errors.New("no outcome")
		}
		return nil, fmt.Errorf("%w: %w", ErrJoinNotSent, sendErr)
	}
	out := outcomes[0]
	switch {
	case out.Succeeded():
		return &JoinResult{CreateCircleWalletResponse: out.Result, Pending: pj}, nil
	case out.Undecodable:
		// The Hub answered, but not with this join's details: look it up.
		msg := ""
		if out.Error != nil {
			msg = out.Error.Message
		}
		return nil, &JoinIndeterminateError{Pending: pj, Cause: errors.New("the reply failed its checks: " + msg)}
	case out.State == cashclient.OutcomeError && out.Error != nil:
		if out.Error.Code == nipcw.ErrRequestReused {
			return nil, &JoinIndeterminateError{Pending: pj, Code: out.Error.Code}
		}
		return nil, &relayclient.WalletError{Method: nipcw.MethodCreateCircleWallet, Code: out.Error.Code, Message: out.Error.Message}
	default:
		return nil, &JoinIndeterminateError{Pending: pj, Cause: sendErr}
	}
}

// withinLimits is the client pre-check against the limits get_info reports (0 or
// "" when not reported). The Hub still decides: a refusal is handled anyway.
func withinLimits(p nipcw.CreateCircleWalletParams, maxAmount, maxReceive int64, floor string, maxExp int) error {
	switch {
	case maxAmount > 0 && p.MaxAmountMillis > uint64(maxAmount):
		return fmt.Errorf("%w: max_amount %d over per_wallet_max_millis %d", ErrOverHubLimit, p.MaxAmountMillis, maxAmount)
	case maxReceive > 0 && p.MaxReceiveMillis > uint64(maxReceive):
		return fmt.Errorf("%w: max_receive %d over per_wallet_max_receive_millis %d", ErrOverHubLimit, p.MaxReceiveMillis, maxReceive)
	case !nipcw.RenewalAtLeast(p.BudgetRenewal, floor):
		return fmt.Errorf("%w: budget_renewal %q tighter than min_budget_renewal %q", ErrOverHubLimit, p.BudgetRenewal, floor)
	case maxExp > 0 && p.Expiry > time.Duration(maxExp)*time.Second:
		return fmt.Errorf("%w: expiry over max_exp_secs %d", ErrOverHubLimit, maxExp)
	}
	return nil
}
