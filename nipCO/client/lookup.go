package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
)

// Lookup reads an order (NIP-CO §Reading an Order): cash_lookup with the
// order's request_id and deadline, target the Order connection, the item proof
// by the buyer key (pc.BuyerKey, or derived from the cash secret) and the bill
// proof by the connection secret. A done is parsed into the order as it stands,
// every token decoded and its provenance checked against TLV 4; one that does
// not is Malformed, never unknown. Pass it to nipcash/client.Recover, which
// answers an order's done with ActionWait{Result}: the caller closes the call
// on Finished or EndedUnpaid.
func (c *OrderClient) Lookup(ctx context.Context, pc nipcash.PendingCall) (cashclient.LookupOutcome, *nipCO.Order, error) {
	bill, err := c.bill()
	if err != nil {
		return cashclient.LookupOutcome{}, nil, err
	}
	if pc.Target != c.conn.Pubkey {
		return cashclient.LookupOutcome{}, nil, fmt.Errorf("nipCO/client: the order was placed on %s, not this connection", pc.Target)
	}
	outs, err := c.session.LookupOrderMany(ctx, []cashclient.BatchOrderLookup{{ID: "1", Connection: bill, Call: pc}})
	if err != nil {
		return cashclient.LookupOutcome{}, nil, err
	}
	lo := outs[0]
	if lo.Status != nipcash.LookupDone {
		return lo, nil, nil
	}
	order, err := c.parseOrder(pc, lo.Result)
	if err != nil {
		return cashclient.LookupOutcome{Malformed: true}, nil, nil
	}
	return lo, order, nil
}

// LookupFunc adapts Lookup to nipcash/client.Recover's lookup argument.
func (c *OrderClient) LookupFunc() func(context.Context, nipcash.PendingCall) (cashclient.LookupOutcome, error) {
	return func(ctx context.Context, pc nipcash.PendingCall) (cashclient.LookupOutcome, error) {
		lo, _, err := c.Lookup(ctx, pc)
		return lo, err
	}
}

// parseOrder reads a done result against the written-ahead request: its kind
// and amount must match, and every token's provenance must name TLV 4.
func (c *OrderClient) parseOrder(pc nipcash.PendingCall, raw json.RawMessage) (*nipCO.Order, error) {
	var sent struct {
		Payment      string `json:"payment"`
		AmountMillis uint64 `json:"amount_millis"`
	}
	if len(pc.Params) > 0 {
		if err := json.Unmarshal(pc.Params, &sent); err != nil {
			return nil, err
		}
	}
	order, err := nipCO.CashOrderParams{Payment: sent.Payment, AmountMillis: sent.AmountMillis}.ParseLookupResult(raw)
	if err != nil {
		return nil, err
	}
	for i, b := range order.Bills {
		if b.Token.Tombstone != nil {
			continue
		}
		tok, err := nipcash.Decode(b.Token.Token)
		if err != nil {
			return nil, err
		}
		minter, ok := nipcash.VerifyProvenance(tok)
		if !ok {
			return nil, fmt.Errorf("%w: bill %d has no valid provenance", nipCO.ErrOrderReply, i)
		}
		if x, err := nipcash.MinterXOnly(minter); err != nil || x != c.conn.HubIdentity {
			return nil, fmt.Errorf("%w: bill %d was minted by another node", nipCO.ErrOrderReply, i)
		}
	}
	return order, nil
}

// OrderedBills are an order's live bills as batch bills, each marked Ordered.
func OrderedBills(o *nipCO.Order) ([]cashclient.Bill, error) {
	if o == nil {
		return nil, nil
	}
	var out []cashclient.Bill
	for _, b := range o.Bills {
		if b.Token.Tombstone != nil {
			continue
		}
		tok, err := nipcash.Decode(b.Token.Token)
		if err != nil {
			return nil, err
		}
		bill, err := cashclient.BillFor(tok)
		if err != nil {
			return nil, err
		}
		bill.Ordered = true
		out = append(out, bill)
	}
	return out, nil
}
