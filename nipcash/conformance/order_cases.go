package conformance

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// CT-ORD-04 (CASH-RID-05, C5): a bad item proof is UNAUTHORIZED and leaves the
// request_id unused (the same id with a good proof is placed); a request with
// a good proof refused after step 1 has its id used (REQUEST_REUSED on resend).
// The refusal is step 2's when the Hub leaves a payment kind unsold, else step
// 4's (max_millis + 1): both come after the id is marked.
func ctOrd04(t *testing.T, s *suite) {
	k := s.orderKit(t)
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	p, m := k.request(t, payment, k.amount(t, payment), false)
	raw, _ := json.Marshal(m)
	res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		it := orderItem(t, s, k.oc, nipcash.MethodCashOrder, raw, p.buyer, false, nonce, notAfter)
		hash, _ := transport.CanonicalParamsHash(raw)
		// An item proof over another nonce: it does not verify for this item.
		bad, err := transport.BuildItemProof(p.buyer, transport.ProofBinding{Target: k.oc.Pubkey, HubXOnly: s.nodeXOnly,
			Method: nipcash.MethodCashOrder, ParamsHash: hash, Nonce: mustNonce(t), NotAfter: notAfter})
		if err != nil {
			t.Fatal(err)
		}
		it.Proof = bad
		return it
	})
	if code := resultCode(res); code != nipcash.ErrCodeUnauthorized {
		t.Fatalf("bad item proof: %v, want UNAUTHORIZED", res)
	}
	if k.send(t, p, m); p.order == nil {
		t.Fatalf("the same request_id with a good proof: %v, want placed", p.res)
	}

	q, m2 := k.request(t, payment, k.amount(t, payment), false)
	refused := maps.Clone(m2)
	switch {
	case k.terms.Lightning == nil:
		refused["payment"] = nipCO.PaymentLightning
	case k.terms.Onchain == nil:
		refused["payment"] = nipCO.PaymentOnchain
	default:
		refused["amount_millis"] = k.kind(t, payment).MaxMillis + 1000
	}
	if res := k.send(t, q, refused); resultCode(res) != nipcash.ErrCodeRestricted {
		t.Fatalf("refused order: %v, want RESTRICTED", res)
	}
	if res := k.send(t, q, m2); resultCode(res) != nipcash.ErrCodeRequestReused {
		t.Errorf("resend of a refused order's id: %v, want REQUEST_REUSED", res)
	}
}

// CT-ORD-05 (CO-PLACE-01, CO-CONN-03): a retired connection (when the suite
// can add one to retire), a kind not offered, min_millis − 1, max_millis + 1
// and an untrusted recipient IA are RESTRICTED, and leave no order: its lookup
// is never done, and no notice comes on its notify.
func ctOrd05(t *testing.T, s *suite) {
	k := s.orderKit(t)
	notify, _ := nipCO.NewNotify()
	notices := s.listenKind(t, nipCO.KindOrderNotice, notify)
	var refused []*placed
	try := func(name string, oc nipCO.OrderConnection, payment string, amount uint64, mut func(map[string]any)) {
		t.Helper()
		p, m := k.request(t, payment, amount, false)
		p.oc, m["notify"], p.notify = oc, notify, notify
		if mut != nil {
			mut(m)
		}
		if res := k.send(t, p, m); resultCode(res) != nipcash.ErrCodeRestricted {
			t.Errorf("%s: %v, want RESTRICTED", name, res)
		}
		refused = append(refused, p)
	}
	for _, payment := range []string{nipCO.PaymentLightning, nipCO.PaymentOnchain} {
		kt := k.terms.Kind(payment)
		if kt == nil {
			try(payment+" not offered", k.oc, payment, 21_000_000, nil)
			continue
		}
		if kt.MinMillis > 1000 {
			try(payment+" min_millis − 1000", k.oc, payment, kt.MinMillis-1000, nil)
		}
		try(payment+" max_millis + 1000", k.oc, payment, kt.MaxMillis+1000, nil)
	}
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	_, ia := keypair(t)
	_, ck := keypair(t)
	s.h.TrustIA(t, ia, false)
	try("untrusted IA", k.oc, payment, k.amount(t, payment), func(m map[string]any) {
		m["recipient"] = map[string]any{"identity_type": "connection_key", "identity_value": ck, "ia_pubkey": ia}
	})
	if adder, ok := s.h.(OrderConnectionAdder); ok {
		oc2, err := nipCO.DecodeOrderConnection(adder.AddOrderConnection(t))
		if err != nil {
			t.Fatalf("the added connection: %v", err)
		}
		k.payer().RetireOrderConnection(t, oc2.Pubkey)
		try("retired connection", oc2, payment, k.amount(t, payment), nil)
	} else {
		t.Log("the Hub cannot add an Order connection: the retired refusal is CT-ORD-14's")
	}
	for _, p := range refused {
		if st, _ := k.readStatus(t, p); st == nipcash.LookupDone {
			t.Errorf("a refused order (%d by %s) exists", p.amount, p.payment)
		}
	}
	if got := notices.wait(1, s.quiet()); len(got) > 0 {
		t.Errorf("%d notices for refused orders", len(got))
	}
}

// CT-ORD-06 (CO-LIM-01): orders of max_millis are placed until the open-order
// ceiling of their kind, and the next is QUOTA_EXCEEDED; with Clocked, the
// room returns once the open orders expire. A Hub whose ceiling holds more than
// 40 such orders is not filled (skipped).
func ctOrd06(t *testing.T, s *suite) {
	k := s.orderKit(t)
	var longest uint64
	for _, payment := range []string{nipCO.PaymentLightning, nipCO.PaymentOnchain} {
		kt := k.terms.Kind(payment)
		if kt == nil {
			continue
		}
		longest = max(longest, kt.Window)
		filled := false
		for range 40 {
			p, m := k.request(t, payment, kt.MaxMillis, false)
			res := k.send(t, p, m)
			if p.order != nil {
				continue
			}
			if code := resultCode(res); code != nipcash.ErrCodeQuotaExceeded {
				t.Fatalf("%s order while filling: %v", payment, res)
			}
			filled = true
			break
		}
		if !filled {
			t.Skipf("40 open %s orders of max_millis fit under the Hub's ceiling", payment)
		}
	}
	c, ok := s.h.(Clocked)
	if !ok {
		t.Log("the Hub is not Clocked: room after expiry not checked")
		return
	}
	c.Advance(t, time.Duration(longest+1)*time.Second)
	for _, payment := range []string{nipCO.PaymentLightning, nipCO.PaymentOnchain} {
		if kt := k.terms.Kind(payment); kt != nil {
			p, m := k.request(t, payment, kt.MaxMillis, false)
			if res := k.send(t, p, m); p.order == nil {
				t.Errorf("%s order after the open ones expired: %v", payment, res)
			}
		}
	}
}

// CT-ORD-07 (CO-RESP-01, CO-LN-01): the reply's fee_millis and pay_millis follow
// the order fee; a Lightning invoice is for exactly pay_millis, never
// amountless, expires at pay_by, and two orders of one amount get two invoices
// with distinct payment hashes; an on-chain reply carries whole base units, the
// tier of pay_millis and an address of the Hub's network.
func ctOrd07(t *testing.T, s *suite) {
	k := s.orderKit(t)
	for _, payment := range []string{nipCO.PaymentLightning, nipCO.PaymentOnchain} {
		kt := k.terms.Kind(payment)
		if kt == nil {
			continue
		}
		amount := k.amount(t, payment)
		before := time.Now().Unix()
		a, b := k.place(t, payment, amount), k.place(t, payment, amount)
		fee, pay, err := nipCO.OrderFee(payment, *kt, amount)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []*placed{a, b} {
			o := p.order
			if o.FeeMillis != fee || o.PayMillis != pay || o.AmountMillis != amount {
				t.Errorf("%s reply fee %d pay %d, want %d %d", payment, o.FeeMillis, o.PayMillis, fee, pay)
			}
			if o.PayBy < before+int64(kt.Window)-120 {
				t.Errorf("%s pay_by %d is not placement + window %d", payment, o.PayBy, kt.Window)
			}
		}
		if payment == nipCO.PaymentLightning {
			for _, p := range []*placed{a, b} {
				if err := nipCO.CheckOrderInvoice(p.order); err != nil {
					t.Errorf("invoice: %v", err)
				}
				ts, exp, ok := bolt11Times(p.order.Invoice)
				if !ok || ts+exp != p.order.PayBy {
					t.Errorf("the invoice expires at %d+%d, pay_by is %d", ts, exp, p.order.PayBy)
				}
			}
			if paymentHash(t, a.order.Invoice) == paymentHash(t, b.order.Invoice) {
				t.Error("two orders share a payment hash")
			}
			continue
		}
		n, _ := nipCO.ConfirmationsFor(kt.Confirmations, pay)
		if pay%1000 != 0 || a.order.Confirmations != n {
			t.Errorf("on-chain pay %d, confirmations %d (want %d)", pay, a.order.Confirmations, n)
		}
		if _, _, err := nipcash.DecodeWitnessAddress(a.order.Address, s.hrp(t)); err != nil {
			t.Errorf("address %s: %v", a.order.Address, err)
		}
		if a.order.Address == b.order.Address {
			t.Error("two orders share an address")
		}
	}
}

// statusOf is the cash_status of an order bill held through secret (a cash
// recipient) or key (a pubkey recipient).
func (s *suite) statusOf(t *testing.T, b nipCO.OrderBill, secret, key string) (holder, *nipcash.CashStatusResult) {
	t.Helper()
	s.wdSession(t)
	tok, err := nipcash.Decode(b.Token.Token)
	if err != nil {
		t.Fatal(err)
	}
	h := s.holderOf(t, tok)
	h.amount = b.AmountMillis
	if secret != "" {
		h.secret, h.cred = secret, nipcash.BySecret(secret)
	} else {
		h.priv, h.cred = key, nipcash.BySigning(key)
	}
	return h, s.status(t, h, nipcash.ScopeMine)
}

// CT-ORD-08 (CO-MINT-01): an exact payment is minted without any lookup (a
// notice arrives first): one bill of amount_millis from pay_millis, with no
// expiry, the bill terms the order was placed under in cash_status, and
// provenance by TLV 4.
func ctOrd08(t *testing.T, s *suite) {
	k := s.orderKit(t)
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	p := k.place(t, payment, k.amount(t, payment))
	notices := s.listenKind(t, nipCO.KindOrderNotice, p.notify)
	k.pay(t, p, p.order.PayMillis)
	if payment == nipCO.PaymentOnchain {
		k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	}
	if len(notices.wait(1, 15*s.quiet())) == 0 {
		t.Error("no notice before any lookup")
	}
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 })
	if o.State != nipCO.OrderMinted || len(o.Bills) != 1 || o.Bills[0].AmountMillis != p.amount ||
		o.Bills[0].PaidMillis != p.order.PayMillis {
		t.Fatalf("order after an exact payment: %+v", o)
	}
	_, st := s.statusOf(t, o.Bills[0], p.secret, "")
	if len(st.Recipients) != 1 {
		t.Fatalf("cash_status rows: %+v", st.Recipients)
	}
	row := st.Recipients[0]
	if !row.ExpiresAt.Never() || row.Claimed || row.AmountMillis != p.amount {
		t.Errorf("ordered bill row: %+v", row)
	}
	bt := k.terms.Bill
	if fee, _, err := nipcash.RedeemFee(p.amount, bt.RedeemFeeBase, bt.RedeemFeePpm); err != nil ||
		row.RedeemFeeMillis != fee || row.MinTransferMillis != bt.MinTransferMillis {
		t.Errorf("bill terms in cash_status: fee %d min %d, the order's terms say %+v", row.RedeemFeeMillis,
			row.MinTransferMillis, bt)
	}
}

// CT-ORD-09 (CO-LN-01): an invoice paid with more than pay_millis mints the
// larger amount, received − fee_millis.
func ctOrd09(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentLightning)
	p := k.place(t, nipCO.PaymentLightning, k.amount(t, nipCO.PaymentLightning))
	paid := p.order.PayMillis + 5_000_000
	k.pay(t, p, paid)
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 })
	if sum(o.Bills) != paid-p.order.FeeMillis || o.Bills[0].PaidMillis != paid {
		t.Errorf("overpaid order bills: %+v, want %d in all", o.Bills, paid-p.order.FeeMillis)
	}
}

// CT-ORD-10 (CO-MINT-01): with the signer broken at settlement the order is
// paid and holds no bill; once it is fixed the Hub retries and mints it, once.
func ctOrd10(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentLightning)
	f := s.h.(Faulty)
	p := k.place(t, nipCO.PaymentLightning, k.amount(t, nipCO.PaymentLightning))
	f.InjectFault(t, FaultBreakSigner)
	cleared := false
	defer func() {
		if !cleared {
			f.InjectFault(t, FaultNone)
		}
	}()
	k.pay(t, p, p.order.PayMillis)
	if res := k.lookupRaw(t, p, p.buyer); resultCode(res) == "" && res != nil {
		var lr struct {
			Result json.RawMessage `json:"result"`
		}
		_ = json.Unmarshal(res["result"], &lr)
		if o, err := (nipCO.CashOrderParams{}).ParseLookupResult(lr.Result); err == nil &&
			(o.State != nipCO.OrderPaid || len(o.Bills) != 0) {
			t.Errorf("with the signer broken: %s with %d bills, want paid with none", o.State, len(o.Bills))
		}
	} else {
		t.Logf("lookup with the signer broken: %v", res)
	}
	f.InjectFault(t, FaultNone)
	cleared = true
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 })
	if o.State != nipCO.OrderMinted || len(o.Bills) != 1 {
		t.Fatalf("after the signer is fixed: %s with %d bills", o.State, len(o.Bills))
	}
	if again := k.read(t, p); len(again.Bills) != 1 || again.Bills[0].Token.Token != o.Bills[0].Token.Token {
		t.Errorf("minted more than once: %+v", again.Bills)
	}
}

// CT-ORD-11 (CO-LN-01, CO-STATE-01): an unpaid Lightning order is expired after
// pay_by.
func ctOrd11(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentLightning)
	p := k.place(t, nipCO.PaymentLightning, k.amount(t, nipCO.PaymentLightning))
	s.advance(t, time.Duration(kt.Window+1)*time.Second)
	st, o := k.readStatus(t, p)
	if o != nil && (o.State != nipCO.OrderExpired || len(o.Bills) != 0) {
		t.Errorf("an unpaid Lightning order after pay_by: %s with %d bills", o.State, len(o.Bills))
	}
	if o == nil && st != nipcash.LookupExpired && st != nipcash.LookupUnknown {
		t.Errorf("lookup of a dropped unpaid order: %s", st)
	}
}

// CT-ORD-12 (CO-READ-01): a lookup done is the order as it stands, not a copy
// of the reply: open, then minted with its bill; two reads give byte-identical
// tokens.
func ctOrd12(t *testing.T, s *suite) {
	k := s.orderKit(t)
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	p := k.place(t, payment, k.amount(t, payment))
	if o := k.read(t, p); o.State != nipCO.OrderOpen || len(o.Bills) != 0 {
		t.Errorf("before payment: %s with %d bills", o.State, len(o.Bills))
	}
	k.pay(t, p, p.order.PayMillis)
	if payment == nipCO.PaymentOnchain {
		k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	}
	a := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 })
	b := k.read(t, p)
	if a.State != nipCO.OrderMinted || len(a.Bills) != 1 || len(b.Bills) != 1 || a.Bills[0].Token.Token != b.Bills[0].Token.Token {
		t.Errorf("two reads: %+v / %+v", a.Bills, b.Bills)
	}
}

// CT-ORD-13 (CO-READ-01, CASH-LK-10): a lookup whose item proof is by another
// key is UNAUTHORIZED; one whose bill proof is not by the connection secret is
// omitted.
func ctOrd13(t *testing.T, s *suite) {
	k := s.orderKit(t)
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	p := k.place(t, payment, k.amount(t, payment))
	other, _ := keypair(t)
	if res := k.lookupRaw(t, p, other); resultCode(res) != nipcash.ErrCodeUnauthorized {
		t.Errorf("lookup by another key: %v, want UNAUTHORIZED", res)
	}
	forged := *p
	forged.oc.Secret = mustKey(t)
	if res := k.lookupRaw(t, &forged, p.buyer); res != nil {
		t.Errorf("lookup with a bill proof by another secret was answered: %v", res)
	}
}

// CT-ORD-15 (CO-NOTE-01): every change of an order publishes a notice: kind
// 23189, a fresh key each, one ["p", notify] tag, empty content, on the relay
// the order arrived on. An on-chain order shows two changes (paid, then
// minted); a Lightning one at least one.
func ctOrd15(t *testing.T, s *suite) {
	k := s.orderKit(t)
	payment := nipCO.PaymentOnchain
	if k.terms.Onchain == nil {
		payment = nipCO.PaymentLightning
	}
	p := k.place(t, payment, k.amount(t, payment))
	notices := s.listenKind(t, nipCO.KindOrderNotice, p.notify)
	want := 1
	k.pay(t, p, p.order.PayMillis)
	if payment == nipCO.PaymentOnchain {
		want = 2
		if len(notices.wait(1, 15*s.quiet())) == 0 {
			t.Error("no notice once the payment was seen")
		}
		k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	}
	got := notices.wait(want, 15*s.quiet())
	if len(got) < want {
		t.Fatalf("%d notices, want %d", len(got), want)
	}
	keys := map[string]bool{}
	for _, h := range got {
		ev := h.ev
		if ev.Kind != nipCO.KindOrderNotice || ev.Content != "" || len(ev.Tags) != 1 || len(ev.Tags[0]) != 2 ||
			ev.Tags[0][0] != "p" || ev.Tags[0][1] != p.notify || !nipCO.IsOrderNotice(ev, p.notify) {
			t.Errorf("notice %+v", ev)
		}
		if h.relay != 0 {
			t.Logf("a notice on relay %d (the order arrived on relay 0; others are allowed)", h.relay)
		}
		if keys[ev.PubKey] || ev.PubKey == s.nodeXOnly || ev.PubKey == k.oc.Pubkey {
			t.Errorf("notice key %s reused or a Hub key", ev.PubKey)
		}
		keys[ev.PubKey] = true
	}
	if !slices.ContainsFunc(got, func(h heard) bool { return h.relay == 0 }) {
		t.Error("no notice on the relay the order arrived on")
	}
}

// CT-ORD-16 (CO-PLACE-01): placing an order moves no funds: the Hub's balance
// is unchanged.
func ctOrd16(t *testing.T, s *suite) {
	k := s.orderKit(t)
	a := s.h.(Admin)
	before := a.Balance(t)
	for _, payment := range []string{nipCO.PaymentLightning, nipCO.PaymentOnchain} {
		if k.terms.Kind(payment) != nil {
			k.place(t, payment, k.amount(t, payment))
		}
	}
	if after := a.Balance(t); after != before {
		t.Errorf("balance %d after placing, %d before", after, before)
	}
}

// CT-LK-14 (CASH-ORD-01): an order lookup done is the current state: after a
// second on-chain payment it carries both bills, the first token byte-identical
// across reads.
func ctLk14(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	first := k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	a := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, first)) > 0 })
	second := k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	b := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, second)) > 0 })
	if len(billsOf(a, first)) != 1 || len(billsOf(b, first)) != 1 || len(billsOf(b, second)) != 1 {
		t.Fatalf("bills: first read %+v, second read %+v", a.Bills, b.Bills)
	}
	if billsOf(a, first)[0].Token.Token != billsOf(b, first)[0].Token.Token {
		t.Error("the first bill's token changed between reads")
	}
}

// CT-ORDC-01 (CO-ON-01): a fresh address per order: 20 orders, 20 addresses.
func ctOrdc01(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	seen := map[string]bool{}
	for range 20 {
		p := k.place(t, nipCO.PaymentOnchain, kt.MinMillis)
		if seen[p.order.Address] {
			t.Fatalf("address %s given out twice", p.order.Address)
		}
		seen[p.order.Address] = true
	}
}

// CT-ORDC-02 (CO-ON-01, CO-TERM-02): each output is minted at the tier of its
// own value, none before its tier and none at 0 confirmations.
func ctOrdc02(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	type out struct {
		op string
		n  int
	}
	var outs []out
	var prev uint64
	for _, tier := range kt.Confirmations {
		v := prev + 1_000_000
		if tier.UpToMillis != nil {
			v = *tier.UpToMillis / 1000 * 1000
		}
		if v <= p.order.FeeMillis || v <= prev {
			continue
		}
		outs = append(outs, out{k.pay(t, p, v), k.tier(t, v)})
		if tier.UpToMillis != nil {
			prev = *tier.UpToMillis
		}
	}
	if o := k.read(t, p); len(o.Bills) != 0 {
		t.Fatalf("minted at 0 confirmations: %+v", o.Bills)
	}
	var ns []int
	for _, x := range outs {
		ns = append(ns, x.n)
	}
	slices.Sort(ns)
	depth := 0
	for _, n := range slices.Compact(ns) {
		k.payer().Mine(t, n-depth)
		depth = n
		o := k.await(t, p, func(o *nipCO.Order) bool {
			for _, x := range outs {
				if x.n <= depth && len(billsOf(o, x.op)) == 0 {
					return false
				}
			}
			return true
		})
		for _, x := range outs {
			if got := len(billsOf(o, x.op)) > 0; got != (x.n <= depth) {
				t.Errorf("at depth %d the output needing %d is minted: %v", depth, x.n, got)
			}
		}
	}
}

// CT-ORDC-03 (CO-MINT-01): K-OMINT-1..4: exact, under-, over- and two payments
// each mint received − fee_millis.
func ctOrdc03(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentOnchain)
	amount := k.amount(t, nipCO.PaymentOnchain)
	type paid struct {
		p     *placed
		ops   []string
		value uint64
	}
	var all []paid
	deepest := 0
	for _, delta := range []int64{0, -1_000_000, 3_937_000, 1} {
		p := k.place(t, nipCO.PaymentOnchain, amount)
		x := paid{p: p}
		if delta == 1 { // two outputs of half
			x.value = p.order.PayMillis / 2 / 1000 * 1000
			x.ops = []string{k.pay(t, p, x.value), k.pay(t, p, x.value)}
		} else {
			x.value = uint64(int64(p.order.PayMillis) + delta)
			x.ops = []string{k.pay(t, p, x.value)}
		}
		deepest = max(deepest, k.tier(t, x.value))
		all = append(all, x)
	}
	k.payer().Mine(t, deepest)
	for _, x := range all {
		o := k.await(t, x.p, func(o *nipCO.Order) bool { return len(o.Bills) >= len(x.ops) })
		for _, op := range x.ops {
			bills := billsOf(o, op)
			if len(bills) != 1 || bills[0].AmountMillis != x.value-o.FeeMillis || bills[0].PaidMillis != x.value {
				t.Errorf("payment of %d (fee %d): bills %+v", x.value, o.FeeMillis, bills)
			}
		}
	}
}

// CT-ORDC-04 (K-OMINT-5): an output of at most fee_millis mints nothing.
func ctOrdc04(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	v := p.order.FeeMillis / 1000 * 1000
	if v == 0 {
		t.Skip("fee_millis is below one base unit")
	}
	k.pay(t, p, v)
	k.pay(t, p, 50_000)
	k.payer().Mine(t, k.tier(t, v))
	time.Sleep(s.quiet() / 4)
	if o := k.read(t, p); len(o.Bills) != 0 {
		t.Errorf("outputs of at most fee_millis minted %+v", o.Bills)
	}
}

// CT-ORDC-05 (CO-ON-01, CO-STATE-01): after pay_by an order that saw a payment
// is closed, and a later payment is still minted: the closed order gains the
// bill.
func ctOrdc05(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	first := k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, first)) > 0 })
	s.advance(t, time.Duration(kt.Window+1)*time.Second)
	if o := k.read(t, p); o.State != nipCO.OrderClosed {
		t.Errorf("after pay_by with a payment seen: %s, want closed", o.State)
	}
	late := k.pay(t, p, 10_000_000)
	k.payer().Mine(t, k.tier(t, 10_000_000))
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, late)) > 0 })
	if bills := billsOf(o, late); len(bills) != 1 || bills[0].AmountMillis != 10_000_000-o.FeeMillis || o.State != nipCO.OrderClosed {
		t.Errorf("late payment: %s, bills %+v", o.State, bills)
	}
}

// CT-ORDC-06 (CO-ON-01): an on-chain order that saw nothing by pay_by is
// expired, then gone by max(pay_by, deadline + H); a payment after that mints
// nothing.
func ctOrdc06(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	s.advance(t, time.Duration(kt.Window+1)*time.Second)
	if st, o := k.readStatus(t, p); o != nil && o.State != nipCO.OrderExpired {
		t.Errorf("unpaid at pay_by: %s, want expired or gone (%s)", o.State, st)
	}
	s.advance(t, time.Duration(s.limits.MaxRequestAgeSeconds+1)*time.Second)
	if st, o := k.readStatus(t, p); o != nil {
		t.Errorf("unpaid order still kept past max(pay_by, deadline + H): %s %s", st, o.State)
	}
	k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	time.Sleep(s.quiet() / 4)
	if _, o := k.readStatus(t, p); o != nil {
		t.Errorf("a payment to a deleted order made it %s with %d bills", o.State, len(o.Bills))
	}
}

// CT-ORDC-07 (CO-ON-01): a reorganisation removing a payment before it is
// minted leaves it unminted; one removing it after leaves the bill standing.
func ctOrdc07(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	// Before: an output whose tier needs more than one confirmation.
	var deep uint64
	for _, tier := range kt.Confirmations {
		if tier.N > 1 && tier.UpToMillis != nil {
			deep = *tier.UpToMillis / 1000 * 1000
			break
		}
	}
	if deep > 0 {
		p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
		op := k.pay(t, p, deep)
		k.payer().Mine(t, 1)
		k.payer().Reorg(t, 1)
		if o := k.read(t, p); len(billsOf(o, op)) != 0 {
			t.Errorf("a payment reorganised out before its tier was minted: %+v", o.Bills)
		}
	} else {
		t.Log("every tier needs one confirmation: the before-mint half is not reachable")
	}
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	n := k.tier(t, p.order.PayMillis)
	op := k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, n)
	minted := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, op)) > 0 })
	k.payer().Reorg(t, n)
	k.payer().Mine(t, n)
	after := k.read(t, p)
	if b := billsOf(after, op); len(b) != 1 || len(billsOf(minted, op)) != 1 || b[0].Token.Token != billsOf(minted, op)[0].Token.Token {
		t.Errorf("a minted bill after its payment was reorganised out: %+v", after.Bills)
	}
}

// CT-ORDC-08 (CO-MINT-01): one outpoint is minted once across repeated chain
// events and, when the Hub is a Restarter, a restart.
func ctOrdc08(t *testing.T, s *suite) {
	k := s.orderKit(t)
	k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	n := k.tier(t, p.order.PayMillis)
	op := k.pay(t, p, p.order.PayMillis)
	k.payer().Mine(t, n)
	first := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, op)) > 0 })
	k.payer().Mine(t, 3)
	k.payer().Reorg(t, 1)
	k.payer().Mine(t, 2)
	if r, ok := s.h.(Restarter); ok {
		r.Restart(t)
		k.payer().Mine(t, 1)
	} else {
		t.Log("the Hub is not a Restarter: restart not exercised")
	}
	o := k.read(t, p)
	if b := billsOf(o, op); len(b) != 1 || b[0].Token.Token != billsOf(first, op)[0].Token.Token {
		t.Errorf("outpoint %s minted as %+v", op, b)
	}
}

// CT-ORDC-09 (CO-MINT-01, K-SPLIT-1): one output bringing in more than
// max_millis + fee_millis is minted as bills of exactly max_millis, then the
// rest: with max_millis 10^9, 2.5 × 10^9 + fee gives 10^9, 10^9, 5 × 10^8.
func ctOrdc09(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	v := 2*kt.MaxMillis + kt.MaxMillis/2/1000*1000 + p.order.FeeMillis
	op := k.pay(t, p, v)
	k.payer().Mine(t, k.tier(t, v))
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, op)) > 0 })
	want := nipCO.MintSplit(v, p.order.FeeMillis, kt.MaxMillis)
	bills := billsOf(o, op)
	if len(bills) != len(want) {
		t.Fatalf("%d bills, want %v", len(bills), want)
	}
	for i, b := range bills {
		if b.AmountMillis != want[i] || b.PaidMillis != v {
			t.Errorf("bill %d: %d of %d, want %d", i, b.AmountMillis, b.PaidMillis, want[i])
		}
	}
}

// CT-ORDC-10 (CO-ON-01, CO-STATE-01): an output only in the mempool at pay_by
// keeps the order, closed, not deleted; it is minted once it reaches its tier.
func ctOrdc10(t *testing.T, s *suite) {
	k := s.orderKit(t)
	kt := k.kind(t, nipCO.PaymentOnchain)
	p := k.place(t, nipCO.PaymentOnchain, k.amount(t, nipCO.PaymentOnchain))
	op := k.pay(t, p, p.order.PayMillis)
	s.advance(t, time.Duration(int64(kt.Window)+s.limits.MaxRequestAgeSeconds+1)*time.Second)
	if o := k.read(t, p); o.State != nipCO.OrderClosed || len(o.Bills) != 0 {
		t.Errorf("unconfirmed at pay_by: %s with %d bills, want closed with none", o.State, len(o.Bills))
	}
	k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(billsOf(o, op)) > 0 })
	if len(billsOf(o, op)) != 1 || o.State != nipCO.OrderClosed {
		t.Errorf("after confirmation: %s, bills %+v", o.State, o.Bills)
	}
}

// orderedBill places and pays a Lightning (else on-chain) order to a fresh
// pubkey recipient of amount, and returns its bill as a holder.
func (k *orderKit) orderedBill(t *testing.T, amount uint64) holder {
	t.Helper()
	payment := nipCO.PaymentLightning
	if k.terms.Lightning == nil {
		payment = nipCO.PaymentOnchain
	}
	p := k.placePubkey(t, payment, amount)
	k.pay(t, p, p.order.PayMillis)
	if payment == nipCO.PaymentOnchain {
		k.payer().Mine(t, k.tier(t, p.order.PayMillis))
	}
	o := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 })
	if len(o.Bills) != 1 {
		t.Fatalf("ordered bill: %+v", o.Bills)
	}
	h, _ := k.s.statusOf(t, o.Bills[0], "", p.recipientKey)
	return h
}

// liveOrdered checks that h's row is unclaimed and never expires.
func (s *suite) liveOrdered(t *testing.T, name string, h holder) {
	t.Helper()
	st := s.status(t, h, nipcash.ScopeMine)
	if len(st.Recipients) != 1 || st.Recipients[0].Claimed || !st.Recipients[0].ExpiresAt.Never() {
		t.Errorf("%s: rows %+v, want one unclaimed row that never expires", name, st.Recipients)
	}
}

// transferOrdered transfers h (split when split > 0) to a fresh pubkey and
// returns the result and the new holder.
func (s *suite) transferOrdered(t *testing.T, h holder, split uint64) (*nipcash.CashTransferResult, holder) {
	t.Helper()
	priv, to := keypair(t)
	p := nipcash.CashTransferParams{Credential: h.cred, To: nipcash.Pubkey(to), CurrentAmount: h.amount}
	if split > 0 {
		p.SplitAmount = &split
	}
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wd.session.TransferMany(ctx, []client.BatchTransfer{{ID: "1", Bill: h.bill, Params: p}}, newMemJournal(), "conformance")
	if err != nil || len(outs) != 1 || outs[0].Result == nil {
		t.Fatalf("transfer of an ordered slice: %v %+v", err, outs)
	}
	return outs[0].Result, holder{priv: priv, cred: nipcash.BySigning(priv)}
}

// CT-OSL-01 (CASH-OSL-01): an ordered slice's split carves an ordered new
// wallet and an ordered remainder, and a full transfer of one keeps the mark;
// none of them expires, also long after (with Clocked).
func ctOsl01(t *testing.T, s *suite) {
	k := s.orderKit(t)
	h := k.orderedBill(t, k.amount(t, nipCO.PaymentLightning))
	res, to := s.transferOrdered(t, h, h.amount/2)
	if res.NewWalletToken == "" || res.RemainderWalletToken == "" {
		t.Fatalf("split result: %+v", res)
	}
	carved := s.holderFromToken(t, res.NewWalletToken, to, res.AmountMillis)
	rest := s.holderFromToken(t, res.RemainderWalletToken, h, h.amount-res.AmountMillis)
	s.liveOrdered(t, "split", carved)
	s.liveOrdered(t, "remainder", rest)
	full, to2 := s.transferOrdered(t, carved, 0)
	moved := carved
	if full.NewWalletToken != "" {
		moved = s.holderFromToken(t, full.NewWalletToken, to2, carved.amount)
	} else {
		moved.priv, moved.cred = to2.priv, to2.cred
	}
	s.liveOrdered(t, "full transfer", moved)
	if _, ok := s.h.(Clocked); ok {
		s.advance(t, 400*24*time.Hour)
		s.liveOrdered(t, "remainder after 400 days", rest)
		s.liveOrdered(t, "full transfer after 400 days", moved)
	}
}

// holderFromToken is the holder of token's one slice, held by key's credential.
func (s *suite) holderFromToken(t *testing.T, token string, key holder, amount uint64) holder {
	t.Helper()
	tok, err := nipcash.Decode(token)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	h := s.holderOf(t, tok)
	h.priv, h.cred, h.amount = key.priv, key.cred, amount
	return h
}

// consolidate merges hs into a fresh pubkey's wallet; it skips when the Hub
// does not serve cash_consolidate.
func (s *suite) consolidate(t *testing.T, hs ...holder) (client.ConsolidateOutcome, holder) {
	t.Helper()
	priv, to := keypair(t)
	var sources []nipcash.Source
	for _, h := range hs {
		sources = append(sources, nipcash.From(h.bill.Target(), h.amount, h.cred))
	}
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wd.session.ConsolidateMany(ctx, []client.BatchConsolidate{{ID: "1", Bill: hs[0].bill,
		Params: nipcash.CashConsolidateParams{Sources: sources, To: nipcash.Pubkey(to)}}}, newMemJournal(), "conformance")
	if err != nil || len(outs) != 1 {
		t.Fatalf("consolidate: %v %+v", err, outs)
	}
	if e := outs[0].Error; e != nil && e.Code == nipcash.ErrCodeNotImplemented {
		t.Skip("the Hub does not serve cash_consolidate")
	}
	return outs[0], holder{priv: priv, cred: nipcash.BySigning(priv)}
}

// CT-OSL-02 (CASH-OSL-01): a consolidate of ordered sources only is ordered.
func ctOsl02(t *testing.T, s *suite) {
	k := s.orderKit(t)
	amount := k.amount(t, nipCO.PaymentLightning)
	a, b := k.orderedBill(t, amount), k.orderedBill(t, amount)
	out, to := s.consolidate(t, a, b)
	if out.Result == nil {
		t.Fatalf("consolidate of ordered sources: %+v", out.ItemOutcome)
	}
	merged := s.holderFromToken(t, out.Result.NewWalletToken, to, out.Result.AmountMillis)
	if !out.Result.ExpiresAt.Never() {
		t.Errorf("the merged wallet expires at %+v", out.Result.ExpiresAt)
	}
	s.liveOrdered(t, "merged", merged)
}

// CT-OSL-03 (CASH-OSL-01): an in-place reassignment (a full transfer of a
// bill's only slice) keeps the mark: the slice still never expires, and with
// Admin its owner still cannot delete the wallet.
func ctOsl03(t *testing.T, s *suite) {
	k := s.orderKit(t)
	h := k.orderedBill(t, k.amount(t, nipCO.PaymentLightning))
	res, to := s.transferOrdered(t, h, 0)
	moved := h
	if res.NewWalletToken != "" {
		t.Logf("the Hub carved a new wallet for a one-slice full transfer")
		moved = s.holderFromToken(t, res.NewWalletToken, to, h.amount)
	} else {
		moved.priv, moved.cred = to.priv, to.cred
	}
	s.liveOrdered(t, "reassigned", moved)
	if a, ok := s.h.(Admin); ok {
		a.DeleteBill(t, moved.bill.Target())
		s.liveOrdered(t, "reassigned, after the owner's delete", moved)
	}
}

// CT-OSL-04 (CASH-OSL-02): ordered and non-ordered sources are never
// consolidated together: RESTRICTED.
func ctOsl04(t *testing.T, s *suite) {
	k := s.orderKit(t)
	amount := k.amount(t, nipCO.PaymentLightning)
	a := k.orderedBill(t, amount)
	plain := s.pubkeyBill(t, amount, 0)
	out, _ := s.consolidate(t, a, plain)
	if out.Error == nil || out.Error.Code != nipcash.ErrCodeRestricted {
		t.Errorf("mixed consolidate: %+v, want RESTRICTED", out.ItemOutcome)
	}
}

// CT-OSL-05 (CASH-OSL-03): the owner can neither delete a wallet holding an
// unclaimed ordered slice nor remove that slice.
func ctOsl05(t *testing.T, s *suite) {
	k := s.orderKit(t)
	h := k.orderedBill(t, k.amount(t, nipCO.PaymentLightning))
	s.h.(Admin).DeleteBill(t, h.bill.Target())
	s.liveOrdered(t, "after the owner's delete", h)
	r, ok := s.h.(SliceRemover)
	if !ok {
		t.Log("the Hub is not a SliceRemover: removal not checked")
		return
	}
	if err := r.RemoveSlice(t, h.bill.Target(), "pubkey", xonlyOf(t, h.priv)); err == nil {
		t.Error("the owner removed an ordered slice")
	}
	s.liveOrdered(t, "after the owner's removal", h)
}

func xonlyOf(t *testing.T, priv string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
