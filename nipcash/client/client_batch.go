package client

import "context"

// The *Many methods below are the batch API as a caller should meet it: on the Client
// they already hold, with no session to open, refresh or reason about.
//
// One envelope carries every item, which is the point. On the standard transport each
// request was p-tagged with its own bill's wallet pubkey, so redeeming forty bills
// published forty events seconds apart and tied them together for anyone watching a
// relay. Batched, that count and that timing correlation are gone.
//
// Every item must belong to the SAME hub as the bill this Client was dialled with —
// an envelope's items all bind to one hub, and one cannot be split across two. A
// caller holding bills from several hubs dials one Client per hub; that grouping stays
// with the caller because only it knows which bills it holds.

// StatusMany reads several bills in one request. The cheapest useful batch, and a good
// first call: it moves no money, so a mistake costs a round trip rather than funds.
func (c *Client) StatusMany(ctx context.Context, items []BatchStatus) ([]StatusOutcome, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.StatusMany(ctx, items)
}

// RedeemMany redeems several bills in one request.
//
// Each bill needs its own invoice — a redemption pays out to one, and a slice pays
// exactly once — so a caller generates as many invoices as bills.
//
// Read the outcome states carefully: this moves money. An OutcomeError is the hub
// declining and is safe to resend; an OutcomeNotServed is NOT, because the hub said
// nothing, which is indistinguishable from an item that executed and whose reply was
// lost. Ask (StatusMany) rather than retry.
func (c *Client) RedeemMany(ctx context.Context, items []BatchRedeem) ([]RedeemOutcome, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.RedeemMany(ctx, items)
}

// TransferMany transfers or splits several bills in one request.
func (c *Client) TransferMany(ctx context.Context, items []BatchTransfer) ([]TransferOutcome, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.TransferMany(ctx, items)
}

// ConsolidateMany performs several consolidations in one request.
//
// A consolidate item grows with its source count, so a batch of them can exceed one
// envelope far sooner than a batch of redemptions — the SDK splits across envelopes
// rather than refusing. A single consolidation whose sources alone exceed the hub's
// announced max_bytes cannot be split at all and returns ErrItemTooLarge: consolidate
// in stages.
func (c *Client) ConsolidateMany(ctx context.Context, items []BatchConsolidate) ([]ConsolidateOutcome, error) {
	session, err := c.billSession(ctx)
	if err != nil {
		return nil, err
	}
	return session.ConsolidateMany(ctx, items)
}
