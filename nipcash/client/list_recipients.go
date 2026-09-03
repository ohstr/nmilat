package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// ListRecipients returns the full roster of recipients this Cash Wallet was
// created for — a read-only, shared view, not scoped to the caller alone.
// Takes no params; MAY be called by any holder of the connection.
func (c *Client) ListRecipients(ctx context.Context) (*nipcash.ListRecipientsResult, error) {
	return call[nipcash.ListRecipientsResult](ctx, c, nipcash.MethodListRecipients, struct{}{})
}
