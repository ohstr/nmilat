package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CashStatus asks a Cash Wallet what state it is in.
//
// It answers one of two ways: the full roster of recipients the bill was
// created for — a read-only, shared view, not scoped to the caller alone — or,
// for a bill the Hub has already destroyed and is still inside its retention
// window, a tombstone (CashStatusResult.IsSpent).
//
// A timeout is NOT a third answer meaning "spent". Silence is indeterminate by
// construction — an unreachable Hub looks identical — so a caller MUST retry
// rather than report the bill gone.
//
// Takes no params; MAY be called by any holder of the connection.
func (c *Client) CashStatus(ctx context.Context) (*nipcash.CashStatusResult, error) {
	return call[nipcash.CashStatusResult](ctx, c, nipcash.MethodCashStatus, struct{}{})
}

// ListRecipients is the former name of CashStatus.
//
// Deprecated: use CashStatus. It still calls the old wire method, so it keeps
// working against a Hub that has not been updated yet.
func (c *Client) ListRecipients(ctx context.Context) (*nipcash.CashStatusResult, error) {
	return call[nipcash.CashStatusResult](ctx, c, nipcash.MethodListRecipients, struct{}{})
}
