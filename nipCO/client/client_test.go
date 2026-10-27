package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
)

const fakeTerms = `{
  "lightning": {"min_millis": 1000000, "max_millis": 1000000000, "fee_base": 1000, "fee_ppm": 1000, "window": 3600},
  "onchain": {"min_millis": 10000000, "max_millis": 1000000000, "fee_base": 21000, "fee_ppm": 2000, "window": 86400,
    "confirmations": [{"up_to_millis": 100000000, "n": 1}, {"up_to_millis": 1000000000, "n": 3}, {"n": 6}]},
  "bill": {"redeem_fee_base": 0, "redeem_fee_ppm": 5000, "min_transfer_millis": 1000}
}`

// journal is a Journal and AcceptedRecorder double that stores calls as JSON and
// reads them back.
type journal struct {
	mu       sync.Mutex
	calls    map[string][]byte
	accepted map[string][]string
}

func newJournal() *journal {
	return &journal{calls: map[string][]byte{}, accepted: map[string][]string{}}
}

func (j *journal) WriteAhead(_ context.Context, calls []nipcash.PendingCall) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, pc := range calls {
		raw, err := json.Marshal(pc)
		if err != nil {
			return err
		}
		j.calls[pc.RequestID] = raw
	}
	return nil
}
func (j *journal) RecordDerived(context.Context, string, int64) error  { return nil }
func (j *journal) DerivedPlaced(context.Context, string) (bool, error) { return false, nil }
func (j *journal) RecordAccepted(_ context.Context, id string, relays []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.accepted[id] = relays
	return nil
}

func (j *journal) only(t *testing.T) nipcash.PendingCall {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.calls) != 1 {
		t.Fatalf("%d calls written, want 1", len(j.calls))
	}
	for _, raw := range j.calls {
		var pc nipcash.PendingCall
		if err := json.Unmarshal(raw, &pc); err != nil {
			t.Fatal(err)
		}
		return pc
	}
	return nipcash.PendingCall{}
}

func (j *journal) count() int { j.mu.Lock(); defer j.mu.Unlock(); return len(j.calls) }

func testContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if d, ok := t.Deadline(); ok {
		return context.WithDeadline(context.Background(), d.Add(-10*time.Second))
	}
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

func orderHub(t *testing.T, opts ...cashtest.Option) (*cashtest.FakeHub, *cashtest.OrderBook) {
	t.Helper()
	hub := cashtest.NewFakeHub(t, opts...)
	return hub, hub.ServeOrders(t, fakeTerms)
}

func connect(t *testing.T, ctx context.Context, book *cashtest.OrderBook) *OrderClient {
	t.Helper()
	c, err := Connect(ctx, book.OrderConnection(t), Options{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func cashOrder(t *testing.T, payment string, amount uint64) (nipCO.CashOrderParams, *nipcash.CashTarget) {
	t.Helper()
	target, err := nipCO.NewCashOrderTarget()
	if err != nil {
		t.Fatal(err)
	}
	return nipCO.CashOrderParams{Recipient: target, AmountMillis: amount, Payment: payment}, target
}

// T20-17, T20-18, T20-19, T20-24: connect, place, look up, watch, end to end.
func TestOrder_EndToEnd(t *testing.T) {
	hub, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	if !c.Verified() {
		t.Error("the fake's string does not verify")
	}
	p, target := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	j := newJournal()
	order, err := c.Place(ctx, p, j, "dev")
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	if order.State != nipCO.OrderOpen || order.FeeMillis != 22_000 || order.PayMillis != 21_022_000 ||
		order.Invoice == "" || order.TermsChanged {
		t.Fatalf("order = %+v", order)
	}
	pc := j.only(t)
	if pc.Method != nipcash.MethodCashOrder || pc.Target != c.Connection().Pubkey || pc.Amount != 21_000_000 ||
		pc.Device != "dev" || pc.HubIdentity != hub.NodeXOnly() || !nipCO.ValidNotify(pc.Notify) ||
		len(pc.Secrets) != 1 || pc.Secrets[0].Secret != target.Secret() || pc.BuyerKey != "" || pc.Deadline == 0 ||
		pc.Chain != cashtest.FakeChain {
		t.Fatalf("written call = %+v", pc)
	}
	if strings.Contains(string(pc.Params), target.Secret()) {
		t.Error("Params carry the cash secret")
	}
	// T20-24: the journal heard the accepting relays, keyed by request_id.
	if rs := j.accepted[pc.RequestID]; len(rs) != 1 {
		t.Errorf("accepted relays = %v", j.accepted)
	}
	if got := c.WatchRelays(pc.Notify, nil); len(got) == 0 || got[0] != j.accepted[pc.RequestID][0] {
		t.Errorf("WatchRelays(nil) = %v", got)
	}
	if got := c.WatchRelays(pc.Notify, []string{"wss://elsewhere.example"}); got[0] != "wss://elsewhere.example" {
		t.Errorf("WatchRelays(accepted) = %v", got)
	}

	// T20-18: only get_info travelled on 23194.
	if book.NWCCalls("cash_order") != 0 || book.NWCCalls("cash_lookup") != 0 || book.NWCCalls("get_info") < 2 {
		t.Errorf("23194 calls: get_info %d, cash_order %d", book.NWCCalls("get_info"), book.NWCCalls("cash_order"))
	}
	for _, e := range hub.Envelopes() {
		for _, it := range e.Items {
			if it.Target != c.Connection().Pubkey {
				t.Errorf("item targets %s", it.Target)
			}
		}
	}

	// T20-19: a lookup before payment is the open order.
	lo, got, err := c.Lookup(ctx, pc)
	if err != nil || lo.Status != nipcash.LookupDone || got == nil || got.State != nipCO.OrderOpen {
		t.Fatalf("lookup: %+v %+v %v", lo, got, err)
	}

	// Watch, then pay: a notice signals; the order itself comes from Lookup.
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	signals, err := c.Watch(wctx, pc.Notify, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the subscriptions reach the relays
	book.PayInvoice(t, pc.RequestID, 21_022_000)
	select {
	case <-signals:
	case <-time.After(10 * time.Second):
		t.Fatal("no notice signal")
	}
	lo, got, err = c.Lookup(ctx, pc)
	if err != nil || got == nil || got.State != nipCO.OrderMinted || len(got.Bills) != 1 || got.Bills[0].AmountMillis != 21_000_000 {
		t.Fatalf("lookup after payment: %+v %+v %v", lo, got, err)
	}
	if !Finished(got) {
		t.Error("a minted Lightning order is finished")
	}
	bills, err := OrderedBills(got)
	if err != nil || len(bills) != 1 || !bills[0].Ordered {
		t.Fatalf("OrderedBills: %+v %v", bills, err)
	}
	act, err := cashclient.Recover(ctx, pc, c.LookupFunc(), "dev", time.Now())
	if err != nil || act.Kind != cashclient.ActionWait || len(act.Result) == 0 {
		t.Errorf("Recover = %+v %v", act, err)
	}

	// The same request_id again is REQUEST_REUSED: pending, never a failure.
	if _, err := c.Place(ctx, nipCO.CashOrderParams{Recipient: target, AmountMillis: 21_000_000,
		Payment: nipCO.PaymentLightning, RequestID: pc.RequestID}, newJournal(), "dev"); err == nil {
		t.Error("a reused request_id placed again")
	} else {
		var ie *cashclient.IndeterminateError
		if !errors.As(err, &ie) || !ie.Call.SawReused {
			t.Errorf("reused: %v", err)
		}
	}
	// An identity recipient gets a fresh buyer key, written ahead.
	_, pk := cashtest.Keypair(t)
	j2 := newJournal()
	if _, err := c.Place(ctx, nipCO.CashOrderParams{Recipient: nipcash.Pubkey(pk), AmountMillis: 5_000_000,
		Payment: nipCO.PaymentLightning}, j2, "dev"); err != nil {
		t.Fatalf("pubkey order: %v", err)
	}
	pc2 := j2.only(t)
	if pc2.BuyerKey == "" || len(pc2.Secrets) != 0 {
		t.Fatalf("pubkey order call = %+v", pc2)
	}
	if lo, got, err := c.Lookup(ctx, pc2); err != nil || got == nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("pubkey order lookup: %+v %v", lo, err)
	}
	// Another buyer key is UNAUTHORIZED.
	forged := pc2
	forged.BuyerKey, _ = cashtest.Keypair(t)
	if lo, _, err := c.Lookup(ctx, forged); err != nil || lo.Code != nipcash.ErrCodeUnauthorized {
		t.Errorf("forged lookup: %+v %v", lo, err)
	}
	// An id the Hub never saw is pending until its deadline, then unknown.
	unknown := pc2
	unknown.RequestID, _ = nipcash.NewRequestID()
	if lo, _, err := c.Lookup(ctx, unknown); err != nil || lo.Status != nipcash.LookupPending {
		t.Errorf("unknown lookup before its deadline: %+v %v", lo, err)
	}
	unknown.Deadline = book.Now().Unix() - 1
	if lo, _, err := c.Lookup(ctx, unknown); err != nil || lo.Status != nipcash.LookupUnknown {
		t.Errorf("unknown lookup: %+v %v", lo, err)
	}
}

// T20-17, T20-26 (K-ONL-1): the online check through Connect, and an
// announcement that cannot be found for TLV 4.
func TestConnect_OnlineCheck(t *testing.T) {
	hub, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	node := hub.NodeXOnly()
	_, other := cashtest.Keypair(t)
	for _, c := range []struct {
		pubkey, chain string
		want          error
	}{
		{node, cashtest.FakeChain, nil},
		{strings.ToUpper(node), cashtest.FakeChain, nil},
		{"02" + node, cashtest.FakeChain, nil},
		{"03" + node, cashtest.FakeChain, nil},
		{other, cashtest.FakeChain, nipcash.ErrHubIdentityMismatch},
		{"04" + node, cashtest.FakeChain, nipcash.ErrHubIdentityMismatch},
		{node, "Bitcoin", nipcash.ErrChainMismatch},
		{node, "", nipcash.ErrChainMismatch},
	} {
		book.SetInfoIdentity(c.pubkey, c.chain)
		oc, err := Connect(ctx, book.OrderConnection(t), Options{})
		if !errors.Is(err, c.want) {
			t.Errorf("pubkey %s chain %q: %v, want %v", c.pubkey, c.chain, err, c.want)
		}
		if err == nil {
			oc.Close()
		}
	}
}

// T20-17: H 59 → ErrHubUnusable, nothing written.
func TestConnect_HubUnusable(t *testing.T) {
	hub, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	ev := hub.Announcement()
	ev.CreatedAt++
	for _, tag := range ev.Tags {
		if len(tag) >= 3 && tag[0] == "limit" && tag[1] == transport.LimitMaxRequestAge {
			tag[2] = "59"
		}
	}
	if err := ev.Sign(hub.NodePriv); err != nil {
		t.Fatal(err)
	}
	for _, r := range hub.Relays {
		if ok, msg := r.Publish(ev); !ok {
			t.Fatal(msg)
		}
	}
	if _, err := Connect(ctx, book.OrderConnection(t), Options{}); !errors.Is(err, cashclient.ErrHubUnusable) {
		t.Fatalf("err = %v, want ErrHubUnusable", err)
	}
}

// T20-17: Place re-reads the terms and uses the new fee.
func TestPlace_ReReadsTerms(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	book.SetTerms(strings.Replace(fakeTerms, `"fee_base": 1000,`, `"fee_base": 5000,`, 1))
	p, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	order, err := c.Place(ctx, p, newJournal(), "dev")
	if err != nil || order.FeeMillis != 26_000 || order.TermsChanged {
		t.Fatalf("order = %+v %v", order, err)
	}
}

// T20-27: a retired connection answers {} at once; Place refuses locally and
// writes nothing; an earlier order is still looked up.
func TestRetired(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	if _, err := c.Place(ctx, p, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.only(t)
	book.Retire()
	terms, err := c.Terms(ctx)
	if err != nil || !terms.SellsNothing() {
		t.Fatalf("retired terms: %+v %v", terms, err)
	}
	j2 := newJournal()
	p2, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	if _, err := c.Place(ctx, p2, j2, "dev"); !errors.Is(err, ErrOrderNotSold) || j2.count() != 0 {
		t.Fatalf("retired Place: %v, %d written", err, j2.count())
	}
	if lo, got, err := c.Lookup(ctx, pc); err != nil || got == nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup on a retired connection: %+v %v", lo, err)
	}
}

// T20-28: terms that change between the read and the reply set TermsChanged; the
// call stays pending; ParseLookupResult never sets it.
func TestPlace_TermsChanged(t *testing.T) {
	two := `{"onchain": {"min_millis": 1000, "max_millis": 1000000000, "fee_base": 0, "fee_ppm": 0, "window": 86400,
	  "confirmations": [{"up_to_millis": 100000000, "n": 1}, {"n": 3}]}}`
	hub := cashtest.NewFakeHub(t)
	book := hub.ServeOrders(t, two)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 50_000_000)
	order, err := c.Place(ctx, p, newJournal(), "dev")
	if err != nil || order.Confirmations != 1 || order.TermsChanged {
		t.Fatalf("unchanged: %+v %v", order, err)
	}
	book.BeforeReply(func() {
		book.SetTerms(strings.Replace(two, `"up_to_millis": 100000000`, `"up_to_millis": 10000000`, 1))
	})
	j := newJournal()
	p2, _ := cashOrder(t, nipCO.PaymentOnchain, 50_000_000)
	order, err = c.Place(ctx, p2, j, "dev")
	if err != nil || order.Confirmations != 3 || !order.TermsChanged {
		t.Fatalf("changed: %+v %v", order, err)
	}
	if !strings.HasPrefix(order.Address, cashtest.FakeAddressHRP+"1") {
		t.Errorf("address %s", order.Address)
	}
	_, got, err := c.Lookup(ctx, j.only(t))
	if err != nil || got == nil || got.TermsChanged {
		t.Fatalf("lookup: %+v %v", got, err)
	}
}

// T20-27: nothing sold of the kind asked → ErrOrderNotSold, nothing written.
func TestPlace_KindNotSold(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	book := hub.ServeOrders(t, `{"lightning": {"min_millis": 1, "max_millis": 1000000000, "fee_base": 0, "fee_ppm": 0, "window": 60}}`)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	if _, err := c.Place(ctx, p, j, "dev"); !errors.Is(err, ErrOrderNotSold) || j.count() != 0 {
		t.Fatalf("%v, %d written", err, j.count())
	}
}

// T20-22: no error carries a cash secret, a buyer key, notify or a request_id.
func TestNoSecretsInErrors(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	target, _ := nipCO.NewCashOrderTarget()
	sk, _, _ := nipCO.BuyerKeyFromSecret(target.Secret())
	notify, _ := nipCO.NewNotify()
	rid, _ := nipcash.NewRequestID()
	var errs []error
	for _, p := range []nipCO.CashOrderParams{
		{Recipient: target, AmountMillis: 0, Payment: nipCO.PaymentLightning, Notify: notify, RequestID: rid},
		{Recipient: target, AmountMillis: 21_000_500, Payment: nipCO.PaymentOnchain, Notify: notify, RequestID: rid},
		{Recipient: target, AmountMillis: 1, Payment: nipCO.PaymentLightning, Notify: notify, RequestID: rid}, // RESTRICTED
	} {
		_, err := c.Place(ctx, p, newJournal(), "dev")
		errs = append(errs, err)
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("case %d placed", i)
			continue
		}
		for _, s := range []string{target.Secret(), sk, notify} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("case %d: error %q carries a secret", i, err)
			}
		}
	}
}

// T20-29: an on-chain reply whose address is of another network → the call
// pending, ErrOrderReplyInvalid, nothing to pay; an uppercase one is lowercased.
func TestPlace_InvalidAddress(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)
	book.SetAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	order, err := c.Place(ctx, p, j, "dev")
	var ie *cashclient.IndeterminateError
	if order != nil || !errors.Is(err, ErrOrderReplyInvalid) || !errors.As(err, &ie) || ie.Call.RequestID != j.only(t).RequestID {
		t.Fatalf("order %+v, err %v", order, err)
	}
	book.SetAddress("BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080")
	p2, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	order, err = c.Place(ctx, p2, newJournal(), "dev")
	if err != nil || order.Address != "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080" {
		t.Fatalf("uppercase: %+v %v", order, err)
	}
}

// An order read back with cash_lookup gets the same checks as a direct reply:
// an on-chain address of another network, or an invoice that does not expire
// at pay_by, makes the lookup Malformed, never a done order.
func TestLookup_ChecksInvoiceAndAddress(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	c := connect(t, ctx, book)

	book.SetAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
	p, _ := cashOrder(t, nipCO.PaymentOnchain, 21_000_000)
	j := newJournal()
	if _, err := c.Place(ctx, p, j, "dev"); !errors.Is(err, ErrOrderReplyInvalid) {
		t.Fatalf("Place: %v, want ErrOrderReplyInvalid", err)
	}
	lo, got, err := c.Lookup(ctx, j.only(t))
	if err != nil || !lo.Malformed || got != nil {
		t.Fatalf("on-chain lookup with another network's address: %+v %+v %v", lo, got, err)
	}

	ln, _ := cashOrder(t, nipCO.PaymentLightning, 21_000_000)
	jl := newJournal()
	if _, err := c.Place(ctx, ln, jl, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := jl.only(t)
	order, ok := book.Order(pc.RequestID)
	if !ok {
		t.Fatal("the fake lost the order")
	}
	raw, err := json.Marshal(order)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.parseOrder(pc, raw); err != nil {
		t.Fatalf("the stored order: %v", err)
	}
	order.PayBy++
	raw, _ = json.Marshal(order)
	if _, err := c.parseOrder(pc, raw); !errors.Is(err, ErrOrderReplyInvalid) {
		t.Fatalf("pay_by not the invoice expiry: %v, want ErrOrderReplyInvalid", err)
	}
}
