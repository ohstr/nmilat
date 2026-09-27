package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// ListRecipients returns the full roster of recipients this Cash Wallet was
// created for — a read-only, shared view, not scoped to the caller alone.
// Takes no params; MAY be called by any holder of the connection.
func (c *Client) ListRecipients(ctx context.Context) (*nipcash.CashStatusResult, error) {
	// Still sends the old wire method on purpose: MethodCashStatus is a
	// different string ("cash_status" vs "list_recipients"), so switching it
	// here would stop this client talking to a Hub that has not migrated. The
	// deprecation is kept for one release precisely so the two sides can move
	// independently, and which side moves first is a wire-compatibility
	// decision rather than a lint fix.
	//nolint:staticcheck // SA1019: deliberate during the compatibility window.
	return call[nipcash.CashStatusResult](ctx, c, nipcash.MethodListRecipients, struct{}{})
}
