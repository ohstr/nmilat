package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashStatus asks a Cash Wallet what state it is in.
//
// It answers one of two ways: the roster of recipients — scoped per §Scoping the
// Roster — or, for a bill the Hub has already destroyed and is still inside its
// retention window, a tombstone (CashStatusResult.IsSpent).
//
// A timeout is NOT a third answer meaning "spent". Silence is indeterminate by
// construction — an unreachable Hub looks identical — so a caller MUST retry rather
// than report the bill gone.
//
// cred is required, unlike the connection-authorized call this replaced: the private
// transport authorizes per item, and it is also what identifies the caller well enough
// to scope the answer at all.
//
// scope may be left empty, which asks for the transport's default — ScopeMine, the
// caller's own row and nothing about their co-recipients. Pass nipcash.ScopeAll for the
// shared roster.
func (c *Client) CashStatus(ctx context.Context, cred nipcash.Credential, scope string) (*nipcash.CashStatusResult, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	outcomes, sendErr := session.StatusMany(ctx, []BatchStatus{{
		ID: "1", Target: c.WalletPubkey(), Credential: cred, Scope: scope,
	}})
	if len(outcomes) == 0 {
		return nil, oneItemOutcome(OutcomeNotServed, nil, sendErr, nipcash.MethodCashStatus)
	}
	o := outcomes[0]
	if err := oneItemOutcome(o.State, o.Error, sendErr, nipcash.MethodCashStatus); err != nil {
		return nil, err
	}
	return o.Result, nil
}
