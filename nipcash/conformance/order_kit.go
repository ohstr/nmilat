package conformance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// OrderConnectionAdder is an optional OrderPayer whose operator can give the
// Hub another Order connection (CT-ORD-05's retired connection, CT-ORD-14).
type OrderConnectionAdder interface {
	// AddOrderConnection returns the new connection's signed cashorder1 string.
	AddOrderConnection(t testing.TB) string
}

// Restarter is an optional Hub the suite can restart: what the Hub persisted
// survives, nothing else does (CT-ORDC-08).
type Restarter interface {
	Restart(t testing.TB)
}

// orderKit is what an order case knows: the Order connection and its terms.
type orderKit struct {
	s     *suite
	oc    nipCO.OrderConnection
	terms *nipCO.Terms
}

func (s *suite) orderKit(t *testing.T) *orderKit {
	t.Helper()
	oc, nwc := orderConn(t, s)
	info, _ := orderInfo(t, nwc)
	terms, err := nipCO.ParseOrderInfo(info["cash_order"])
	if err != nil {
		t.Fatalf("cash_order terms: %v", err)
	}
	if terms.SellsNothing() {
		t.Skip("the Order connection sells nothing")
	}
	return &orderKit{s: s, oc: oc, terms: terms}
}

// kind is the terms of payment, skipping the case when it is not sold.
func (k *orderKit) kind(t *testing.T, payment string) *nipCO.KindTerms {
	t.Helper()
	kt := k.terms.Kind(payment)
	if kt == nil {
		t.Skipf("the Hub does not sell %s", payment)
	}
	return kt
}

// amount is an order amount within payment's bounds: 21,000,000 millis (the
// spec's example) when it fits, else the minimum.
func (k *orderKit) amount(t *testing.T, payment string) uint64 {
	t.Helper()
	kt := k.kind(t, payment)
	if a := uint64(21_000_000); a >= kt.MinMillis && a <= kt.MaxMillis {
		return a
	}
	return kt.MinMillis
}

func (k *orderKit) payer() OrderPayer { return k.s.h.(OrderPayer) }

// placed is one order the suite sent: what its buyer keeps.
type placed struct {
	rid, buyer, notify string
	payment            string
	amount             uint64
	deadline           int64
	// secret is a cash recipient's secret; recipientKey a pubkey recipient's.
	secret, recipientKey string
	oc                   nipCO.OrderConnection
	res                  map[string]json.RawMessage
	order                *nipCO.Order
}

// request is a cash_order request to a cash recipient, or with pubkey to a
// fresh pubkey recipient, and the buyer's record of it.
func (k *orderKit) request(t *testing.T, payment string, amount uint64, pubkey bool) (*placed, map[string]any) {
	t.Helper()
	p := &placed{payment: payment, amount: amount, oc: k.oc}
	p.buyer, _ = keypair(t)
	p.rid, _ = nipcash.NewRequestID()
	p.notify, _ = nipCO.NewNotify()
	recipient := map[string]any{}
	if pubkey {
		var pub string
		p.recipientKey, pub = keypair(t)
		recipient["identity_type"], recipient["identity_value"] = "pubkey", pub
	} else {
		target, err := nipCO.NewCashOrderTarget()
		if err != nil {
			t.Fatal(err)
		}
		p.secret = target.Secret()
		recipient["identity_type"], recipient["identity_value"] = "cash", target.Commitment()
	}
	return p, map[string]any{"recipient": recipient, "amount_millis": amount, "payment": payment,
		"notify": p.notify, "request_id": p.rid}
}

// send sends m as p's cash_order on p's connection with p's buyer key and
// keeps the result; the order is parsed when there is one.
func (k *orderKit) send(t *testing.T, p *placed, m map[string]any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p.res = k.s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		p.deadline = notAfter
		return orderItem(t, k.s, p.oc, nipcash.MethodCashOrder, raw, p.buyer, false, nonce, notAfter)
	})
	if p.res != nil && p.res["error"] == nil {
		o, err := nipCO.CashOrderParams{Payment: p.payment, AmountMillis: p.amount}.ParseResult(p.res["result"])
		if err != nil {
			t.Fatalf("the order reply does not parse: %v (%s)", err, p.res["result"])
		}
		p.order = o
	}
	return p.res
}

// place places an order to a cash recipient and fails the case unless it is
// placed.
func (k *orderKit) place(t *testing.T, payment string, amount uint64) *placed {
	t.Helper()
	p, m := k.request(t, payment, amount, false)
	if res := k.send(t, p, m); p.order == nil {
		t.Fatalf("order of %d by %s not placed: %v", amount, payment, res)
	}
	return p
}

// placePubkey places an order to a fresh pubkey recipient.
func (k *orderKit) placePubkey(t *testing.T, payment string, amount uint64) *placed {
	t.Helper()
	p, m := k.request(t, payment, amount, true)
	if res := k.send(t, p, m); p.order == nil {
		t.Fatalf("order of %d by %s not placed: %v", amount, payment, res)
	}
	return p
}

// lookupRaw sends p's cash_lookup with signer's item proof.
func (k *orderKit) lookupRaw(t *testing.T, p *placed, signer string) map[string]json.RawMessage {
	t.Helper()
	lr, _ := json.Marshal(nipcash.CashLookupRequest{RequestID: p.rid, Deadline: p.deadline})
	return k.s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return orderItem(t, k.s, p.oc, nipcash.MethodCashLookup, lr, signer, false, nonce, notAfter)
	})
}

// readStatus is p's lookup: its status, and the order when done (parsed, every
// token's provenance verified against TLV 4).
func (k *orderKit) readStatus(t *testing.T, p *placed) (nipcash.LookupStatus, *nipCO.Order) {
	t.Helper()
	res := k.lookupRaw(t, p, p.buyer)
	var lr struct {
		Status nipcash.LookupStatus `json:"status"`
		Result json.RawMessage      `json:"result"`
	}
	if res == nil || res["error"] != nil || json.Unmarshal(res["result"], &lr) != nil || lr.Status == "" {
		t.Fatalf("lookup of %s: %v", p.rid, res)
	}
	if lr.Status != nipcash.LookupDone {
		return lr.Status, nil
	}
	o, err := nipCO.CashOrderParams{Payment: p.payment, AmountMillis: p.amount}.ParseLookupResult(lr.Result)
	if err != nil {
		t.Fatalf("lookup of %s: %v (%s)", p.rid, err, lr.Result)
	}
	for i, b := range o.Bills {
		if b.Token.Tombstone != nil {
			continue
		}
		tok, err := nipcash.Decode(b.Token.Token)
		if err != nil {
			t.Fatalf("bill %d: %v", i, err)
		}
		minter, ok := nipcash.VerifyProvenance(tok)
		if x, err := nipcash.MinterXOnly(minter); !ok || err != nil || x != k.oc.HubIdentity {
			t.Errorf("bill %d is not minted by the Hub identity (TLV 4)", i)
		}
	}
	return lr.Status, o
}

// read is p's order as it stands, failing the case unless the lookup is done.
func (k *orderKit) read(t *testing.T, p *placed) *nipCO.Order {
	t.Helper()
	st, o := k.readStatus(t, p)
	if o == nil {
		t.Fatalf("lookup of %s: %s, want done", p.rid, st)
	}
	return o
}

// await reads p until cond holds, giving a Hub that mints in the background
// time to; the last read is returned either way.
func (k *orderKit) await(t *testing.T, p *placed, cond func(*nipCO.Order) bool) *nipCO.Order {
	t.Helper()
	deadline := time.Now().Add(15 * k.s.quiet())
	for {
		o := k.read(t, p)
		if cond(o) || time.Now().After(deadline) {
			return o
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// pay pays p: its invoice, or one output to its address; it returns the
// outpoint of an on-chain payment.
func (k *orderKit) pay(t *testing.T, p *placed, millis uint64) string {
	t.Helper()
	if p.order.Payment == nipCO.PaymentLightning {
		k.payer().PayInvoice(t, p.order.Invoice, millis)
		return ""
	}
	return k.payer().PayAddress(t, p.order.Address, millis)
}

// tier is the confirmations an on-chain output of value needs.
func (k *orderKit) tier(t *testing.T, value uint64) int {
	t.Helper()
	n, err := nipCO.ConfirmationsFor(k.kind(t, nipCO.PaymentOnchain).Confirmations, value)
	if err != nil {
		t.Fatalf("tiers: %v", err)
	}
	return int(max(n, 1))
}

// billsOf are o's bills minted from outpoint.
func billsOf(o *nipCO.Order, outpoint string) []nipCO.OrderBill {
	var out []nipCO.OrderBill
	for _, b := range o.Bills {
		if b.Outpoint == outpoint {
			out = append(out, b)
		}
	}
	return out
}

func sum(bills []nipCO.OrderBill) uint64 {
	var n uint64
	for _, b := range bills {
		n += b.AmountMillis
	}
	return n
}

// bolt11Times reads a BOLT11 invoice's timestamp and expiry (3600 when it has
// no x field).
func bolt11Times(inv string) (timestamp, expiry int64, ok bool) {
	_, words, err := bech32.DecodeNoLimit(inv)
	if err != nil || len(words) < 7+104 {
		return 0, 0, false
	}
	for _, w := range words[:7] {
		timestamp = timestamp<<5 | int64(w)
	}
	expiry = 3600
	fields := words[7 : len(words)-104]
	for len(fields) >= 3 {
		typ, n := fields[0], int(fields[1])<<5|int(fields[2])
		if len(fields) < 3+n {
			return 0, 0, false
		}
		if typ == 6 { // x
			expiry = 0
			for _, w := range fields[3 : 3+n] {
				expiry = expiry<<5 | int64(w)
			}
		}
		fields = fields[3+n:]
	}
	return timestamp, expiry, true
}

// paymentHash is a BOLT11 invoice's payment hash.
func paymentHash(t *testing.T, inv string) string {
	t.Helper()
	_, words, err := bech32.DecodeNoLimit(inv)
	if err != nil || len(words) < 7+104 {
		t.Fatalf("invoice: %v", err)
	}
	fields := words[7 : len(words)-104]
	for len(fields) >= 3 {
		typ, n := fields[0], int(fields[1])<<5|int(fields[2])
		if len(fields) < 3+n {
			break
		}
		if typ == 1 { // p
			b, err := bech32.ConvertBits(fields[3:3+n], 5, 8, false)
			if err == nil {
				return string(b)
			}
		}
		fields = fields[3+n:]
	}
	t.Fatalf("invoice %s has no payment hash", inv)
	return ""
}
