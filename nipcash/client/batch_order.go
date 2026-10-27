package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// BatchOrder places one order over an Order connection (NIP-CO §Placing an
// Order). nipCO/client builds it; a caller orders through that package.
type BatchOrder struct {
	ID string
	// Connection is the Order connection: BillFromParts(TLV 0, TLV 2). An order
	// has no bill, so its bill proof is signed with the connection's secret.
	Connection Bill
	// Params is the request. Params.RequestID and Params.Notify MUST be set.
	Params nipCO.CashOrderParams
	// BuyerKey signs the item proof: derived from the cash secret for a cash
	// recipient (nipCO.BuyerKeyFromSecret), else a fresh key (nipCO.NewBuyerKey).
	BuyerKey string
	// Chain is the connection's TLV 6, kept on the written-ahead call.
	Chain string
}

// OrderOutcome is one order's answer. Result is the parsed reply, set only when
// the item Succeeded and the reply parsed.
type OrderOutcome struct {
	ItemOutcome
	Result *nipCO.Order
}

// ErrOrderBuyerKey is an order whose buyer key is missing, or is not the key
// derived from its cash recipient's secret.
var ErrOrderBuyerKey = errors.New("nipcash/client: the order's buyer key is missing or does not match its cash secret")

// orderPending is the call written ahead for an order: request_id, target TLV
// 0, the amount, the cash secret (whose buyer key is derived from it) or the
// buyer key itself, notify, and the wire request as Params.
func orderPending(it BatchOrder) (nipcash.PendingCall, error) {
	req, err := it.Params.Request()
	if err != nil {
		return nipcash.PendingCall{}, err
	}
	if it.BuyerKey == "" {
		return nipcash.PendingCall{}, ErrOrderBuyerKey
	}
	raw, err := json.Marshal(req) // commitments only: an order request carries no secret
	if err != nil {
		return nipcash.PendingCall{}, err
	}
	pc := nipcash.PendingCall{RequestID: it.Params.RequestID, Method: nipcash.MethodCashOrder,
		Target: it.Connection.target, Amount: it.Params.AmountMillis, Notify: it.Params.Notify,
		Chain: it.Chain, Params: raw}
	if t, ok := it.Params.Recipient.(*nipcash.CashTarget); ok && t != nil {
		sk, _, err := nipCO.BuyerKeyFromSecret(t.Secret())
		if err != nil {
			return nipcash.PendingCall{}, err
		}
		if sk != it.BuyerKey {
			return nipcash.PendingCall{}, ErrOrderBuyerKey
		}
		pc.Secrets = []nipcash.PendingSecret{{Secret: t.Secret()}}
	} else {
		pc.BuyerKey = it.BuyerKey
	}
	return pc, nil
}

// CashOrderMany places one or more orders in one request. Every Order
// connection must belong to this session's Hub. Each order is written ahead to j,
// as device's, with its envelope's exact deadline, before anything is published;
// a Journal implementing AcceptedRecorder is told the relays that accepted it.
//
// A reply is parsed through its own params (an open order, no tombstone); one
// that does not parse is OutcomeError with Undecodable, and stays pending.
func (s *BatchSession) CashOrderMany(ctx context.Context, items []BatchOrder, j Journal, device string) ([]OrderOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	byID := make(map[string]BatchOrder, len(items))
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		if err := it.Connection.check(id, s.HubIdentity()); err != nil {
			return nil, err
		}
		pc, err := orderPending(it)
		if err != nil {
			return nil, err
		}
		byID[id] = it
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return it.Params.Item(id, it.Connection.target, it.Connection.connSecret, it.BuyerKey, b)
			},
			RequestID: it.Params.RequestID,
			Pending:   s.pendingAt(pc),
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{journal: j, device: device})
	if sendErr != nil && len(outcomes) == 0 {
		return nil, sendErr
	}
	out := make([]OrderOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		oo := OrderOutcome{ItemOutcome: o}
		if o.Succeeded() {
			order, err := byID[o.ID].Params.ParseResult(o.Result)
			if err != nil {
				oo.ItemOutcome = parseFailure(oo.ItemOutcome, err)
			} else {
				oo.Result = order
			}
		}
		out = append(out, oo)
	}
	return out, sendErr
}

// CallError is the caller's error for one order outcome: nil for a result,
// *FinalError for BAD_REQUEST, *IndeterminateError otherwise (look it up).
func (o OrderOutcome) CallError(sendErr error) error {
	return oneCall(o.ItemOutcome, sendErr, nipcash.MethodCashOrder)
}

// Pending is the call written ahead for this outcome's item, with its exact
// deadline; false when nothing was written.
func (o ItemOutcome) Pending() (nipcash.PendingCall, bool) {
	if o.pending == nil {
		return nipcash.PendingCall{}, false
	}
	return *o.pending, true
}

// BatchOrderLookup reads one order (NIP-CO §Reading an Order): a cash_lookup
// with the order's request_id and deadline, target the Order connection, the
// item proof by the buyer key and the bill proof by the connection secret.
type BatchOrderLookup struct {
	ID         string
	Connection Bill
	// Call is the order's written-ahead call: its BuyerKey, or the cash secret
	// in Secrets[0] the buyer key is derived from.
	Call nipcash.PendingCall
}

// OrderBuyerKey is the buyer key of a written-ahead order: its BuyerKey, else the
// key derived from its cash secret.
func OrderBuyerKey(pc nipcash.PendingCall) (string, error) {
	if pc.BuyerKey != "" {
		return pc.BuyerKey, nil
	}
	for _, sec := range pc.Secrets {
		if sec.Role == "" {
			sk, _, err := nipCO.BuyerKeyFromSecret(sec.Secret)
			return sk, err
		}
	}
	return "", ErrOrderBuyerKey
}

// LookupOrderMany looks several orders up in one request and returns one
// LookupOutcome per item, in order: a coded refusal in Code, an omission or no
// reply NotServed, an answer that does not parse Malformed.
func (s *BatchSession) LookupOrderMany(ctx context.Context, items []BatchOrderLookup) ([]LookupOutcome, error) {
	builders := make([]itemBuilder, 0, len(items))
	ids := make([]string, len(items))
	for i, it := range items {
		it := it
		id := itemID(it.ID, i)
		ids[i] = id
		if err := it.Connection.check(id, s.HubIdentity()); err != nil {
			return nil, err
		}
		if it.Call.Method != nipcash.MethodCashOrder {
			return nil, fmt.Errorf("nipcash/client: item %q is a %s call, not an order", id, it.Call.Method)
		}
		key, err := OrderBuyerKey(it.Call)
		if err != nil {
			return nil, err
		}
		p := nipcash.CashLookupParams{Credential: nipcash.BySigning(key), Request: nipcash.CashLookupRequest{
			RequestID: it.Call.RequestID, Deadline: it.Call.Deadline,
		}}
		if err := p.Request.Validate(); err != nil {
			return nil, err
		}
		builders = append(builders, itemBuilder{
			ID: id,
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return p.Item(id, it.Connection.target, it.Connection.connSecret, b)
			},
		})
	}
	outcomes, sendErr := s.sendBatch(ctx, builders, sendOptions{})
	byID := make(map[string]ItemOutcome, len(outcomes))
	for _, o := range outcomes {
		byID[o.ID] = o
	}
	if len(outcomes) == 0 && sendErr != nil && errors.Is(sendErr, ErrNotSent) {
		return nil, sendErr
	}
	out := make([]LookupOutcome, len(ids))
	for i, id := range ids {
		o, ok := byID[id]
		if !ok {
			out[i] = LookupOutcome{NotServed: true}
			continue
		}
		out[i] = lookupOutcomeOf(o)
	}
	return out, nil
}
