package client

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

const orderTerms = `{"lightning": {"min_millis": 1, "max_millis": 1000000000, "fee_base": 1000, "fee_ppm": 1000, "window": 3600}}`

func orderItem(t *testing.T, conn Bill) BatchOrder {
	t.Helper()
	target, err := nipCO.NewCashOrderTarget()
	if err != nil {
		t.Fatal(err)
	}
	sk, _, err := nipCO.BuyerKeyFromSecret(target.Secret())
	if err != nil {
		t.Fatal(err)
	}
	notify, _ := nipCO.NewNotify()
	rid, _ := nipcash.NewRequestID()
	return BatchOrder{Connection: conn, BuyerKey: sk, Chain: cashtest.FakeChain, Params: nipCO.CashOrderParams{
		Recipient: target, AmountMillis: 21_000_000, Payment: nipCO.PaymentLightning, Notify: notify, RequestID: rid}}
}

// CashOrderMany places several orders in one request, writes each ahead and
// reports the accepting relays per request_id; LookupOrderMany reads them back.
func TestCashOrderMany_AndLookupOrderMany(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	book := hub.ServeOrders(t, orderTerms)
	conn, err := nipCO.DecodeOrderConnection(book.OrderConnection(t))
	if err != nil {
		t.Fatal(err)
	}
	bill, err := BillFromParts(conn.Pubkey, conn.Secret)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := OpenBatchSession(ctx, conn.HubIdentity, conn.Relays)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BillCallsUsable(); err != nil {
		t.Fatal(err)
	}

	bad := orderItem(t, bill)
	bad.BuyerKey = orderItem(t, bill).BuyerKey
	j := newTestJournal()
	if _, err := s.CashOrderMany(ctx, []BatchOrder{bad}, j, "d"); !errors.Is(err, ErrOrderBuyerKey) || len(j.all()) != 0 {
		t.Fatalf("mismatched buyer key: %v", err)
	}
	bad.BuyerKey = ""
	if _, err := s.CashOrderMany(ctx, []BatchOrder{bad}, j, "d"); !errors.Is(err, ErrOrderBuyerKey) {
		t.Fatalf("no buyer key: %v", err)
	}

	items := []BatchOrder{orderItem(t, bill), orderItem(t, bill)}
	outs, err := s.CashOrderMany(ctx, items, j, "d")
	if err != nil || len(outs) != 2 {
		t.Fatalf("CashOrderMany: %v (%d)", err, len(outs))
	}
	var lookups []BatchOrderLookup
	for i, o := range outs {
		if o.Result == nil || o.Result.PayMillis != 21_022_000 || len(o.Accepted) == 0 || o.CallError(nil) != nil {
			t.Fatalf("outcome %d = %+v", i, o)
		}
		pc, ok := o.Pending()
		if !ok || pc.RequestID != items[i].Params.RequestID || pc.Notify != items[i].Params.Notify {
			t.Fatalf("pending %d = %+v", i, pc)
		}
		if got := j.accepted[pc.RequestID]; len(got) == 0 {
			t.Errorf("RecordAccepted not told %s: %v", pc.RequestID, j.accepted)
		}
		if key, err := OrderBuyerKey(pc); err != nil || key != items[i].BuyerKey {
			t.Errorf("OrderBuyerKey = %s %v", key, err)
		}
		lookups = append(lookups, BatchOrderLookup{Connection: bill, Call: pc})
	}
	los, err := s.LookupOrderMany(ctx, lookups)
	if err != nil || len(los) != 2 {
		t.Fatalf("LookupOrderMany: %v", err)
	}
	for i, lo := range los {
		if lo.Status != nipcash.LookupDone || len(lo.Result) == 0 {
			t.Errorf("lookup %d = %+v", i, lo)
		}
	}
	notOrder := lookups[0]
	notOrder.Call.Method = nipcash.MethodCashTransfer
	if _, err := s.LookupOrderMany(ctx, []BatchOrderLookup{notOrder}); err == nil {
		t.Error("a transfer looked up as an order")
	}
}
