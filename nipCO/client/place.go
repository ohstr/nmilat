package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
)

// ErrBuyerKeyIsRecipient is a fresh buyer key equal to the recipient's pubkey: a
// buyer key is never the recipient's Nostr key.
var ErrBuyerKeyIsRecipient = errors.New("nipCO/client: the buyer key would be the recipient's key")

// Place places one order (NIP-CO §Client Behavior, steps 2 and 3). It re-reads
// the terms first (ErrOrderNotSold when they sell nothing of p.Payment, nothing
// written); generates notify and request_id when empty; takes the buyer key from
// the cash recipient's secret (use nipCO.NewCashOrderTarget), or a fresh key for
// a pubkey or connection_key recipient; writes the call ahead to j, as device's,
// with its exact deadline; and sends it on the private transport only. A Journal
// implementing nipcash/client.AcceptedRecorder is told the accepting relays.
//
// The reply is an open order with an invoice for exactly pay_millis, or an
// address checked as a segwit
// address of the Hub's network and chain (else ErrOrderReplyInvalid inside an
// *IndeterminateError: the call stays pending and nothing is shown to pay). A
// reply whose confirmations or pay_millis differ from what the terms read before
// placing give sets Order.TermsChanged: shown from the reply, flagged, never
// refused. BAD_REQUEST is a *FinalError; any other answer short of an order an
// *IndeterminateError (look it up with Lookup).
func (c *OrderClient) Place(ctx context.Context, p nipCO.CashOrderParams, j cashclient.Journal, device string) (*nipCO.Order, error) {
	if j == nil {
		return nil, cashclient.ErrNoJournal
	}
	terms, err := c.Terms(ctx)
	if err != nil {
		return nil, err
	}
	k := terms.Kind(p.Payment)
	if terms.SellsNothing() || (k == nil && (p.Payment == nipCO.PaymentLightning || p.Payment == nipCO.PaymentOnchain)) {
		return nil, ErrOrderNotSold
	}
	if p.Notify == "" {
		if p.Notify, err = nipCO.NewNotify(); err != nil {
			return nil, err
		}
	}
	if p.RequestID == "" {
		if p.RequestID, err = nipcash.NewRequestID(); err != nil {
			return nil, err
		}
	}
	req, err := p.Request()
	if err != nil {
		return nil, err
	}
	var buyerKey string
	if t, ok := p.Recipient.(*nipcash.CashTarget); ok && t != nil {
		if buyerKey, _, err = nipCO.BuyerKeyFromSecret(t.Secret()); err != nil {
			return nil, err
		}
	} else {
		var pk string
		if buyerKey, pk, err = nipCO.NewBuyerKey(); err != nil {
			return nil, err
		}
		if req.Recipient.IdentityValue == pk {
			return nil, ErrBuyerKeyIsRecipient
		}
	}
	_, wantPay, err := nipCO.OrderFee(p.Payment, *k, p.AmountMillis)
	if err != nil {
		return nil, err
	}
	var wantConf uint32
	if p.Payment == nipCO.PaymentOnchain {
		if wantConf, err = nipCO.ConfirmationsFor(k.Confirmations, wantPay); err != nil {
			return nil, err
		}
	}
	bill, err := c.bill()
	if err != nil {
		return nil, err
	}
	outs, sendErr := c.session.CashOrderMany(ctx, []cashclient.BatchOrder{{
		ID: "1", Connection: bill, Params: p, BuyerKey: buyerKey, Chain: c.conn.Chain,
	}}, j, device)
	if len(outs) == 0 {
		if sendErr == nil {
			sendErr = fmt.Errorf("nipCO/client: the order got no outcome")
		}
		return nil, sendErr
	}
	o := outs[0]
	if len(o.Accepted) > 0 {
		c.mu.Lock()
		c.accepted[p.Notify] = append([]string(nil), o.Accepted...)
		c.mu.Unlock()
	}
	if o.Result == nil {
		return nil, o.CallError(sendErr)
	}
	order := o.Result
	if order.Payment == nipCO.PaymentLightning {
		if err := checkOrderInvoice(order); err != nil {
			pc, _ := o.Pending()
			return nil, &cashclient.IndeterminateError{Call: pc, Cause: err}
		}
	}
	if order.Payment == nipCO.PaymentOnchain {
		addr, err := orderAddress(order.Address, c.conn.Chain, c.Network())
		if err != nil {
			pc, _ := o.Pending()
			return nil, &cashclient.IndeterminateError{Call: pc, Cause: err}
		}
		order.Address = addr
		if order.Confirmations != wantConf {
			order.TermsChanged = true
		}
	}
	if order.PayMillis != wantPay {
		order.TermsChanged = true
	}
	return order, nil
}
