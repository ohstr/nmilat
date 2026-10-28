package client

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// The E-ORD and E-ORDC tests: nipCO/client against the fake Hub's orders, its
// payer and chain (internal/cashtest), end to end over the in-process relays.

// orderEnv is a fake Hub selling under fakeTerms whose next cash_order item can
// be made to suffer a fault, or to run a hook first.
type orderEnv struct {
	hub   *cashtest.FakeHub
	book  *cashtest.OrderBook
	fault atomic.Pointer[cashtest.Fault]
	hook  atomic.Pointer[func()]
}

func newOrderEnv(t *testing.T) *orderEnv {
	t.Helper()
	e := &orderEnv{}
	e.hub = cashtest.NewFakeHub(t, cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
		if c.Item.Method != nipcash.MethodCashOrder {
			return cashtest.FaultNone
		}
		if h := e.hook.Swap(nil); h != nil {
			(*h)()
		}
		if f := e.fault.Swap(nil); f != nil {
			return *f
		}
		return cashtest.FaultNone
	}))
	e.book = e.hub.ServeOrders(t, fakeTerms)
	return e
}

// advanceTo moves the book's clock to unix time at.
func (e *orderEnv) advanceTo(at int64) { e.book.Advance(time.Unix(at, 0).Sub(e.book.Now())) }

func (e *orderEnv) faultNext(f cashtest.Fault) { e.fault.Store(&f) }
func (e *orderEnv) beforeNext(f func())        { e.hook.Store(&f) }

// dropKind withholds every event of kind from the relays' subscribers while on.
func (e *orderEnv) dropKind(kind int, on bool) {
	for _, r := range e.hub.Relays {
		if on {
			r.Drop(func(ev *nip01.Event) bool { return ev.Kind == kind })
		} else {
			r.Drop(nil)
		}
	}
}

// call is the call written ahead under id.
func (j *journal) call(t *testing.T, id string) nipcash.PendingCall {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, ok := j.calls[id]
	if !ok {
		t.Fatalf("%s was not written ahead", id)
	}
	var pc nipcash.PendingCall
	if err := json.Unmarshal(raw, &pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func shortContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

// indeterminate places p expecting no verified reply.
func indeterminate(t *testing.T, c *OrderClient, p nipCO.CashOrderParams, j *journal) *cashclient.IndeterminateError {
	t.Helper()
	ctx, cancel := shortContext()
	defer cancel()
	_, err := c.Place(ctx, p, j, "dev")
	var ie *cashclient.IndeterminateError
	if !errors.As(err, &ie) {
		t.Fatalf("Place: %v, want an IndeterminateError", err)
	}
	return ie
}

func lookup(t *testing.T, c *OrderClient, pc nipcash.PendingCall) (cashclient.LookupOutcome, *nipCO.Order) {
	t.Helper()
	ctx, cancel := testContext(t)
	defer cancel()
	lo, o, err := c.Lookup(ctx, pc)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return lo, o
}

// E-ORD-01: Lightning order to a cash recipient: Connect verifies the string
// and the announcement against TLV 4; Place writes the secret, notify, id and
// deadline ahead and gets an open order with an invoice for pay_millis; the
// invoice is paid, a notice arrives, Lookup reads minted with one ordered bill
// of amount_millis minted by TLV 4; the order is finished.
func TestEORD01_LightningCash(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	if !c.Verified() {
		t.Fatal("the string does not verify")
	}
	p, target := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	order, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	pc := j.only(t)
	if len(pc.Secrets) != 1 || pc.Secrets[0].Secret != target.Secret() || !nipCO.ValidNotify(pc.Notify) ||
		pc.Deadline == 0 || !nipcash.ValidRequestID(pc.RequestID) {
		t.Fatalf("written ahead: %+v", pc)
	}
	_, pay, _ := nipCO.OrderFee(nipCO.PaymentLightning, nipCO.KindTerms{FeeBase: 1000, FeePpm: 1000}, 21_000_000)
	if order.State != nipCO.OrderOpen || order.PayMillis != pay || nipCO.CheckOrderInvoice(order) != nil {
		t.Fatalf("order = %+v", order)
	}
	signals, err := c.Watch(ctx, pc.Notify, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	e.book.PayInvoice(t, order.Invoice, order.PayMillis)
	select {
	case <-signals:
	case <-time.After(10 * time.Second):
		t.Fatal("no notice")
	}
	lo, got := lookup(t, c, pc)
	if lo.Status != nipcash.LookupDone || got == nil || got.State != nipCO.OrderMinted || len(got.Bills) != 1 ||
		got.Bills[0].AmountMillis != 21_000_000 || got.Bills[0].PaidMillis != pay {
		t.Fatalf("after payment: %+v %+v", lo, got)
	}
	bills, err := OrderedBills(got)
	if err != nil || len(bills) != 1 || !bills[0].Ordered {
		t.Fatalf("OrderedBills: %+v %v", bills, err)
	}
	if !Finished(got) {
		t.Error("a minted Lightning order is finished")
	}
}

// E-ORD-02: the reply is lost after placement: indeterminate; Lookup reads it
// open; paid later it is minted, and a second read gives the same tokens.
func TestEORD02_ReplyLost(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	e.faultNext(cashtest.FaultCommitThenDropReply)
	pc := indeterminate(t, c, p, newJournal()).Call
	lo, o := lookup(t, c, pc)
	if lo.Status != nipcash.LookupDone || o == nil || o.State != nipCO.OrderOpen {
		t.Fatalf("lookup of the lost reply: %+v %+v", lo, o)
	}
	e.book.PayInvoice(t, o.Invoice, o.PayMillis)
	_, a := lookup(t, c, pc)
	_, b := lookup(t, c, pc)
	if a == nil || a.State != nipCO.OrderMinted || len(a.Bills) != 1 || len(b.Bills) != 1 ||
		a.Bills[0].Token.Token != b.Bills[0].Token.Token {
		t.Fatalf("after payment: %+v / %+v", a, b)
	}
}

// E-ORD-03: the order never arrives: pending until its deadline, then unknown;
// Recover asks for confirmation (nothing sent), and Replace{Confirmed} places
// it under the derived id with the same secret and a fresh notify: open.
func TestEORD03_NeverArrives(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, target := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	e.faultNext(cashtest.FaultDropBeforeCommit)
	j := newJournal()
	pc := indeterminate(t, c, p, j).Call
	if lo, _ := lookup(t, c, pc); lo.Status != nipcash.LookupPending {
		t.Fatalf("before the deadline: %+v", lo)
	}
	e.advanceTo(pc.Deadline + 2)
	sent := len(e.hub.Envelopes())
	act, err := cashclient.Recover(ctx, pc, c.LookupFunc(), "dev", e.book.Now())
	if err != nil || act.Kind != cashclient.ActionConfirmReplace {
		t.Fatalf("Recover = %+v %v, want ActionConfirmReplace", act, err)
	}
	if n := len(e.hub.Envelopes()); n != sent+1 { // the lookup only
		t.Errorf("Recover sent %d envelopes", n-sent)
	}
	if _, err := cashclient.Replace(ctx, pc, j, cashclient.ReplaceOptions{}, nil); !errors.Is(err, cashclient.ErrReplaceNeedsConfirmation) {
		t.Errorf("Replace unconfirmed: %v", err)
	}
	var placed *nipCO.Order
	_, err = cashclient.Replace(ctx, pc, j, cashclient.ReplaceOptions{Confirmed: true},
		func(ctx context.Context, next nipcash.PendingCall) error {
			var err error
			placed, err = c.Place(ctx, nipCO.CashOrderParams{Recipient: target, AmountMillis: next.Amount,
				Payment: nipCO.PaymentLightning, Notify: next.Notify, RequestID: next.RequestID}, j, "dev")
			return err
		})
	if err != nil || placed == nil || placed.State != nipCO.OrderOpen {
		t.Fatalf("Replace: %+v %v", placed, err)
	}
	derived, _ := nipcash.DerivedRequestID(pc.RequestID)
	next := j.call(t, derived)
	if next.DerivedFrom != pc.RequestID || next.Notify == pc.Notify || len(next.Secrets) != 1 ||
		next.Secrets[0].Secret != target.Secret() {
		t.Errorf("derived call: %+v", next)
	}
}

// E-ORD-04: an unpaid Lightning order: while every lookup after pay_by goes
// unanswered the order stays open (lookup_unanswered surfaced, never ended);
// the first answer after pay_by is expired with no bill, so it ended unpaid.
func TestEORD04_LightningUnpaid(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	held, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	pc.PayBy = held.PayBy
	e.book.Advance(3601 * time.Second)
	e.dropKind(transport.KindPrivateResponse, true)
	sctx, scancel := shortContext()
	act, err := cashclient.Recover(sctx, pc, c.LookupFunc(), "dev", e.book.Now())
	scancel()
	if err != nil || act.Kind != cashclient.ActionShow || act.Reason != "lookup_unanswered" {
		t.Fatalf("unanswered after pay_by: %+v %v", act, err)
	}
	e.dropKind(transport.KindPrivateResponse, false)
	lo, o := lookup(t, c, pc)
	if lo.Status != nipcash.LookupDone || o == nil || o.State != nipCO.OrderExpired || len(o.Bills) != 0 {
		t.Fatalf("after pay_by: %+v %+v", lo, o)
	}
	if !EndedUnpaid(held, false, e.book.Now().Unix()) || !Finished(o) {
		t.Error("an unpaid Lightning order past pay_by ended unpaid")
	}
}

// E-ORD-05: an invoice paid with more than pay_millis mints received −
// fee_millis.
func TestEORD05_Overpaid(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	o, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	e.book.PayInvoice(t, o.Invoice, o.PayMillis+1_000_000)
	_, got := lookup(t, c, j.only(t))
	if got == nil || len(got.Bills) != 1 || got.Bills[0].AmountMillis != o.PayMillis+1_000_000-o.FeeMillis {
		t.Fatalf("overpaid: %+v", got)
	}
}

// E-ORD-06: a pubkey recipient: a random buyer key is written ahead and signs
// the lookup; a lookup by another key is UNAUTHORIZED.
func TestEORD06_PubkeyRecipient(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	_, pk := cashtest.Keypair(t)
	j := newJournal()
	if _, err := c.Place(ctx, nipCO.CashOrderParams{Recipient: nipcash.Pubkey(pk), AmountMillis: 5_000_000,
		Payment: nipCO.PaymentLightning}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	if pc.BuyerKey == "" || len(pc.Secrets) != 0 {
		t.Fatalf("written ahead: %+v", pc)
	}
	if lo, o := lookup(t, c, pc); lo.Status != nipcash.LookupDone || o == nil {
		t.Fatalf("lookup by the buyer key: %+v", lo)
	}
	other := pc
	other.BuyerKey, _ = cashtest.Keypair(t)
	if lo, _ := lookup(t, c, other); lo.Code != nipcash.ErrCodeUnauthorized {
		t.Errorf("lookup by another key: %+v", lo)
	}
}

// E-ORD-07: a connection retired as the order arrives, and an amount over
// max_millis, are RESTRICTED: indeterminate, looked up unknown once the
// deadline passed, then closed as refused, never re-placed.
func TestEORD07_Restricted(t *testing.T) {
	for _, name := range []string{"retired", "over max_millis"} {
		t.Run(name, func(t *testing.T) {
			e := newOrderEnv(t)
			ctx, cancel := testContext(t)
			defer cancel()
			c := connect(t, ctx, e.book)
			amount := uint64(21_000_000)
			if name == "retired" {
				e.beforeNext(e.book.Retire)
			} else {
				amount = 1_000_001_000
			}
			p, _ := cashOrder(t, nipCO.PaymentLightning, amount)
			ie := indeterminate(t, c, p, newJournal())
			pc := ie.Call
			if ie.Code != nipcash.ErrCodeRestricted || pc.LastCode != nipcash.ErrCodeRestricted {
				t.Fatalf("refusal: %+v", ie)
			}
			e.advanceTo(pc.Deadline + 2)
			if lo, _ := lookup(t, c, pc); lo.Status != nipcash.LookupUnknown {
				t.Fatalf("lookup: %+v, want unknown", lo)
			}
			act, err := cashclient.Recover(ctx, pc, c.LookupFunc(), "dev", e.book.Now())
			if err != nil || act.Kind != cashclient.ActionCloseRefused || act.Reason != nipcash.ErrCodeRestricted {
				t.Fatalf("Recover = %+v %v, want CloseRefused{RESTRICTED}", act, err)
			}
			if n := e.book.Orders(); n != 0 {
				t.Errorf("%d orders placed", n)
			}
		})
	}
}

// E-ORD-08: every notice is dropped by the relays: Watch never signals, and
// polling Lookup still finds the order minted.
func TestEORD08_NoticesDropped(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	e.dropKind(nipCO.KindOrderNotice, true)
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	o, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	signals, err := c.Watch(ctx, pc.Notify, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	e.book.PayInvoice(t, o.Invoice, o.PayMillis)
	select {
	case <-signals:
		t.Fatal("a dropped notice signalled")
	case <-time.After(500 * time.Millisecond):
	}
	if _, got := lookup(t, c, pc); got == nil || got.State != nipCO.OrderMinted {
		t.Fatalf("polled: %+v", got)
	}
}

// E-ORD-09: a Lightning order paid one second before pay_by, every lookup
// after pay_by unanswered for two minutes: the order stays open
// (lookup_unanswered); once the relays answer again it is done, minted, its
// bill ordered. A held-reply order answered unknown before pay_by is shown
// (lookup_unknown), never offered for re-placement.
func TestEORD09_PaidAtTheWire(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	held, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	pc.PayBy = held.PayBy
	e.advanceTo(held.PayBy - 1)
	e.book.PayInvoice(t, held.Invoice, held.PayMillis)
	e.book.Advance(2 * time.Second)
	e.dropKind(transport.KindPrivateResponse, true)
	for range 2 {
		sctx, scancel := shortContext()
		act, err := cashclient.Recover(sctx, pc, c.LookupFunc(), "dev", e.book.Now())
		scancel()
		if err != nil || act.Kind != cashclient.ActionShow || act.Reason != "lookup_unanswered" {
			t.Fatalf("unanswered: %+v %v", act, err)
		}
		e.book.Advance(time.Minute)
	}
	e.dropKind(transport.KindPrivateResponse, false)
	lo, o := lookup(t, c, pc)
	if lo.Status != nipcash.LookupDone || o == nil || o.State != nipCO.OrderMinted || len(o.Bills) != 1 {
		t.Fatalf("once answered: %+v %+v", lo, o)
	}
	if bills, err := OrderedBills(o); err != nil || len(bills) != 1 || !bills[0].Ordered {
		t.Errorf("OrderedBills: %+v %v", bills, err)
	}

	// A held reply whose lookup answers unknown before pay_by.
	ghost := pc
	ghost.RequestID, _ = nipcash.NewRequestID()
	ghost.Deadline = e.book.Now().Unix() - 1
	ghost.PayBy = e.book.Now().Unix() + 3600
	act, err := cashclient.Recover(ctx, ghost, c.LookupFunc(), "dev", e.book.Now())
	if err != nil || act.Kind != cashclient.ActionShow || act.Reason != "lookup_unknown" {
		t.Errorf("held reply, unknown before pay_by: %+v %v", act, err)
	}
}

// E-ORDC-01: an on-chain order paid with two outputs, then a third after
// pay_by: each output minted at its tier, 9,937,000 from each 10,000,000; the
// order closed at pay_by, and the late output adds a third bill; the closed
// order reads the same again.
func TestEORDC01_OnchainOutputs(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	o, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	if o.FeeMillis != 63_000 || o.Confirmations != 1 {
		t.Fatalf("order = %+v", o)
	}
	a := e.book.PayAddress(t, o.Address, 10_000_000)
	b := e.book.PayAddress(t, o.Address, 10_000_000)
	if _, got := lookup(t, c, pc); got.State != nipCO.OrderPaid || len(got.Bills) != 0 {
		t.Fatalf("unconfirmed: %s with %d bills", got.State, len(got.Bills))
	}
	e.book.Mine(1)
	_, got := lookup(t, c, pc)
	if got.State != nipCO.OrderMinted || len(got.Bills) != 2 {
		t.Fatalf("confirmed: %+v", got)
	}
	for _, bill := range got.Bills {
		if bill.AmountMillis != 9_937_000 || bill.PaidMillis != 10_000_000 || (bill.Outpoint != a && bill.Outpoint != b) {
			t.Errorf("bill %+v", bill)
		}
	}
	e.book.Advance(86401 * time.Second)
	if _, got := lookup(t, c, pc); got.State != nipCO.OrderClosed || !Finished(got) {
		t.Fatalf("after pay_by: %s", got.State)
	}
	late := e.book.PayAddress(t, o.Address, 10_000_000)
	e.book.Mine(1)
	_, got = lookup(t, c, pc)
	if got.State != nipCO.OrderClosed || len(got.Bills) != 3 || got.Bills[2].Outpoint != late {
		t.Fatalf("late output: %+v", got)
	}
	if _, again := lookup(t, c, pc); len(again.Bills) != 3 || again.Bills[0].Token.Token != got.Bills[0].Token.Token {
		t.Error("the closed order reads differently")
	}
}

// E-ORDC-02: an on-chain order with nothing paid: at pay_by it ended unpaid
// and the Hub drops it (max(pay_by, deadline + H)); a payment after that mints
// nothing.
func TestEORDC02_OnchainUnpaid(t *testing.T) {
	e := newOrderEnv(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, e.book)
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	held, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	pc.PayBy = held.PayBy
	e.book.Advance(86401 * time.Second)
	lo, o := lookup(t, c, pc)
	if o != nil && o.State != nipCO.OrderExpired {
		t.Fatalf("at pay_by: %+v", o)
	}
	if o == nil && lo.Status != nipcash.LookupExpired && lo.Status != nipcash.LookupUnknown {
		t.Fatalf("at pay_by: %+v", lo)
	}
	if !EndedUnpaid(held, false, e.book.Now().Unix()) {
		t.Error("an unpaid on-chain order past pay_by ended unpaid")
	}
	if e.book.Orders() != 0 {
		t.Error("the Hub kept the unpaid order")
	}
	e.book.PayAddress(t, held.Address, held.PayMillis)
	e.book.Mine(6)
	if lo, o := lookup(t, c, pc); o != nil || lo.Status == nipcash.LookupDone {
		t.Errorf("a payment after deletion: %+v %+v", lo, o)
	}
}
