package client

import "github.com/ohstr/nmilat/nipCO"

// Finished reports an order its client may stop reading (NIP-CO §Client
// Behavior, step 5): Lightning at minted or expired, on-chain at expired or
// closed. A closed on-chain order may still gain bills; let the user read it
// again later.
func Finished(o *nipCO.Order) bool {
	if o == nil {
		return false
	}
	if o.Payment == nipCO.PaymentLightning {
		return o.State == nipCO.OrderMinted || o.State == nipCO.OrderExpired
	}
	return o.State == nipCO.OrderExpired || o.State == nipCO.OrderClosed
}

// EndedUnpaid reports an order its reply holder reads as ended unpaid,
// whatever its lookup answers: now is past pay_by, the client never saw it paid,
// minted or closed (sawProgress), and it shows no bill. Evaluate it only once a
// lookup sent after pay_by was answered: an omitted lookup, or one answered
// REQUEST_REUSED, ends nothing.
func EndedUnpaid(o *nipCO.Order, sawProgress bool, now int64) bool {
	if o == nil || sawProgress || now <= o.PayBy || len(o.Bills) > 0 {
		return false
	}
	switch o.State {
	case nipCO.OrderPaid, nipCO.OrderMinted, nipCO.OrderClosed:
		return false
	}
	return true
}
