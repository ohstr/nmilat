package nipCP

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

func orderEntry(t *testing.T, cashSecret, orderKey string) Entry {
	t.Helper()
	notify, _ := nipCO.NewNotify()
	pc := call(nipcash.MethodCashOrder, 21000)
	pc.Notify, pc.BuyerKey = notify, orderKey
	if cashSecret != "" {
		pc.Secrets = []nipcash.PendingSecret{{Secret: cashSecret}}
	}
	e, err := PendingEntry(pc)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func order(payment string, st nipCO.OrderState, bills ...nipCO.OrderBill) *nipCO.Order {
	return &nipCO.Order{State: st, Payment: payment, AmountMillis: 21000, PayMillis: 21000, PayBy: 1760003600, Bills: bills}
}

func obill(w, token string) nipCO.OrderBill {
	return nipCO.OrderBill{WalletPubkey: w, Token: nipcash.TokenOrTombstone{Token: token}, AmountMillis: 21000, PaidMillis: 21000}
}

// T15-23: ApplyOrder's bill entries (K-POCKET-5).
func TestApplyOrderBills(t *testing.T) {
	fixClock(t, 1760000000)
	s := secret(t)
	e := orderEntry(t, s, "")
	o := order(nipCO.PaymentLightning, nipCO.OrderMinted, obill(hx('5', 64), "satscash1b"))
	writes, done, err := ApplyOrder(e, o, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || writes[0].Cash != "satscash1b" || writes[0].Secrets[0].Secret != s || writes[0].State != StateLive ||
		writes[0].ExpiresAt != nil || writes[0].Identity.Type != IdentityCash || writes[0].Amount != 21000 {
		t.Fatalf("writes %+v", writes)
	}
	if done == nil || done.State != StateDone || done.Rev != 2 || done.Secrets[0].Secret != s || done.RequestID != e.RequestID || done.Target != e.Target || done.Notify != e.Notify {
		t.Fatalf("done %+v", done)
	}
	// The same bill in a later answer: nothing new.
	writes, _, err = ApplyOrder(e, o, true, OrderHeld(append([]Entry{e}, writes...)))
	if err != nil || len(writes) != 0 {
		t.Fatalf("held bill re-added: %+v %v", writes, err)
	}
	// A gift (keeps false): no bill entry, done still written.
	writes, done, err = ApplyOrder(e, o, false)
	if err != nil || len(writes) != 0 || done == nil {
		t.Fatalf("gift: %+v %+v %v", writes, done, err)
	}
	// An order_key order for the user's own identity: its bill entry.
	bk, _, _ := nipCO.NewBuyerKey()
	pe := orderEntry(t, "", bk)
	user := EntryIdentity{Type: IdentityPubkey, Value: hx('a', 64)}
	if _, _, err := ApplyOrder(pe, o, true); !errors.Is(err, ErrOrderIdentity) {
		t.Fatalf("kept pubkey order without identity: %v", err)
	}
	writes, done, err = ApplyOrder(pe, o, true, OrderIdentity(user))
	if err != nil || len(writes) != 1 || writes[0].Identity != user || len(writes[0].Secrets) != 0 || done.OrderKey != bk {
		t.Fatalf("own order: %+v %+v %v", writes, done, err)
	}
	// A tombstone bill: its mapped final state, no cash.
	tb := nipCO.OrderBill{WalletPubkey: hx('6', 64), Token: nipcash.TokenOrTombstone{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: "expired"}}, AmountMillis: 21000}
	writes, _, err = ApplyOrder(e, order(nipCO.PaymentLightning, nipCO.OrderMinted, tb), true)
	if err != nil || len(writes) != 1 || writes[0].Cash != "" || writes[0].State != StateExpired || len(writes[0].Secrets) != 0 {
		t.Fatalf("tombstone bill: %+v %v", writes, err)
	}
	if _, _, err := ApplyOrder(pendingEntry(hx('2', 32)), o, true); !errors.Is(err, ErrNotPending) {
		t.Fatal("ApplyOrder on a non-order entry")
	}
}

// T15-24: the close rule (K-POCKET-5).
func TestApplyOrderClose(t *testing.T) {
	fixClock(t, 1760000000)
	s := secret(t)
	e := orderEntry(t, s, "")
	for _, c := range []struct {
		payment string
		st      nipCO.OrderState
		done    bool
	}{
		{nipCO.PaymentLightning, nipCO.OrderOpen, false},
		{nipCO.PaymentLightning, nipCO.OrderPaid, false},
		{nipCO.PaymentLightning, nipCO.OrderMinted, true},
		{nipCO.PaymentLightning, nipCO.OrderExpired, true},
		{nipCO.PaymentOnchain, nipCO.OrderMinted, false},
		{nipCO.PaymentOnchain, nipCO.OrderExpired, true},
		{nipCO.PaymentOnchain, nipCO.OrderClosed, true},
	} {
		_, done, err := ApplyOrder(e, order(c.payment, c.st), true)
		if err != nil || (done != nil) != c.done {
			t.Errorf("%s %s: done %v, err %v", c.payment, c.st, done, err)
		}
		if done != nil && (done.Rev != e.Rev+1 || done.Secrets[0].Secret != s) {
			t.Errorf("%s %s: %+v", c.payment, c.st, done)
		}
	}
	// Ended unpaid: closed only when the caller asks with its evidence.
	open := order(nipCO.PaymentOnchain, nipCO.OrderOpen)
	if _, done, _ := ApplyOrder(e, open, true, OrderEndedUnpaid(false, open.PayBy+1)); done == nil {
		t.Fatal("ended unpaid not closed")
	}
	if _, done, _ := ApplyOrder(e, open, true, OrderEndedUnpaid(true, open.PayBy+1)); done != nil {
		t.Fatal("closed an order seen paid")
	}
	// A closed on-chain order read again gains a bill: its entry, no second done.
	closed := WithState(e, StateDone, 1760000100)
	later := order(nipCO.PaymentOnchain, nipCO.OrderClosed, obill(hx('7', 64), "satscash1late"))
	later.Bills[0].Outpoint = hx('1', 64) + ":0"
	writes, done, err := ApplyOrder(closed, later, true)
	if err != nil || len(writes) != 1 || done != nil {
		t.Fatalf("late bill: %+v %+v %v", writes, done, err)
	}
	// With the pocket's entries, done goes at the next rev seen.
	_, done, _ = ApplyOrder(e, order(nipCO.PaymentLightning, nipCO.OrderMinted), true, OrderHeld([]Entry{{W: e.W, Rev: 4, RawState: "x"}}))
	if done.Rev != 5 {
		t.Fatalf("done rev %d", done.Rev)
	}
}
