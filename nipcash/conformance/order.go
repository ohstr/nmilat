package conformance

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// orderCases are the NIP-CO cases a Hub implementing OrderPayer runs, with the
// order lookup (CT-LK-14) and ordered-slice (CT-OSL) cases. CT-ORD-14 retires
// the connection, so it runs last.
var orderCases = []ctCase{
	{id: "CT-ORD-01", needs: []need{needOrder}, run: ctOrd01},
	{id: "CT-ORD-02", needs: []need{needOrder}, run: ctOrd02},
	{id: "CT-ORD-03", needs: []need{needOrder}, run: ctOrd03},
	{id: "CT-ORD-04", needs: []need{needOrder}, run: ctOrd04},
	{id: "CT-ORD-05", needs: []need{needOrder}, run: ctOrd05},
	{id: "CT-ORD-06", needs: []need{needOrder}, run: ctOrd06},
	{id: "CT-ORD-07", needs: []need{needOrder}, run: ctOrd07},
	{id: "CT-ORD-08", needs: []need{needOrder}, run: ctOrd08},
	{id: "CT-ORD-09", needs: []need{needOrder}, run: ctOrd09},
	{id: "CT-ORD-10", needs: []need{needOrder, needFaulty}, run: ctOrd10},
	{id: "CT-ORD-11", needs: []need{needOrder, needClock}, run: ctOrd11},
	{id: "CT-ORD-12", needs: []need{needOrder}, run: ctOrd12},
	{id: "CT-ORD-13", needs: []need{needOrder}, run: ctOrd13},
	{id: "CT-ORD-15", needs: []need{needOrder}, run: ctOrd15},
	{id: "CT-ORD-16", needs: []need{needOrder, needAdmin}, run: ctOrd16},
	{id: "CT-LK-14", needs: []need{needOrder}, run: ctLk14},
	{id: "CT-ORDC-01", needs: []need{needOrder}, run: ctOrdc01},
	{id: "CT-ORDC-02", needs: []need{needOrder}, run: ctOrdc02},
	{id: "CT-ORDC-03", needs: []need{needOrder}, run: ctOrdc03},
	{id: "CT-ORDC-04", needs: []need{needOrder}, run: ctOrdc04},
	{id: "CT-ORDC-05", needs: []need{needOrder, needClock}, run: ctOrdc05},
	{id: "CT-ORDC-06", needs: []need{needOrder, needClock}, run: ctOrdc06},
	{id: "CT-ORDC-07", needs: []need{needOrder}, run: ctOrdc07},
	{id: "CT-ORDC-08", needs: []need{needOrder}, run: ctOrdc08},
	{id: "CT-ORDC-09", needs: []need{needOrder}, run: ctOrdc09},
	{id: "CT-ORDC-10", needs: []need{needOrder, needClock}, run: ctOrdc10},
	{id: "CT-OSL-01", needs: []need{needOrder}, run: ctOsl01},
	{id: "CT-OSL-02", needs: []need{needOrder}, run: ctOsl02},
	{id: "CT-OSL-03", needs: []need{needOrder}, run: ctOsl03},
	{id: "CT-OSL-04", needs: []need{needOrder}, run: ctOsl04},
	{id: "CT-OSL-05", needs: []need{needOrder, needAdmin}, run: ctOsl05},
	{id: "CT-ORD-14", needs: []need{needOrder}, run: ctOrd14},
}

// orderConn decodes the Hub's Order connection and opens its kind-23194 side.
func orderConn(t *testing.T, s *suite) (nipCO.OrderConnection, *relayclient.NWCClient) {
	t.Helper()
	oc, err := nipCO.DecodeOrderConnection(s.h.(OrderPayer).OrderConnection(t))
	if err != nil {
		t.Fatalf("the Hub's cashorder1 string does not decode: %v", err)
	}
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{
		WalletPubkey: oc.Pubkey, RelayURLs: oc.Relays, Secret: oc.Secret,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("open the Order connection: %v", err)
	}
	t.Cleanup(nwc.Close)
	return oc, nwc
}

func orderInfo(t *testing.T, nwc *relayclient.NWCClient) (map[string]json.RawMessage, json.RawMessage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := nwc.Call(ctx, nip47.MethodGetInfo, nil)
	if err != nil || resp.Error != nil {
		t.Fatalf("get_info on the Order connection: %v %+v", err, resp)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &m); err != nil {
		t.Fatalf("get_info: %v", err)
	}
	return m, resp.Result
}

// CT-ORD-01 (CO-CONN-02, CO-TERM-01, CASH-SRV-03): get_info lists only get_info,
// names cash_lookup and cash_order as private, pubkey = TLV 4, network and
// chain, valid terms; every other method on 23194, cash_order included, is
// NOT_IMPLEMENTED.
func ctOrd01(t *testing.T, s *suite) {
	oc, nwc := orderConn(t, s)
	if err := oc.Verify(); err != nil {
		t.Errorf("cashorder1 does not verify: %v", err)
	}
	info, raw := orderInfo(t, nwc)
	var gi nip47.GetInfoResult
	_ = json.Unmarshal(raw, &gi)
	if !slices.Equal(gi.Methods, []string{"get_info"}) {
		t.Errorf("methods = %v, want [get_info]", gi.Methods)
	}
	for _, m := range []string{"cash_lookup", "cash_order"} {
		if !slices.Contains(gi.PrivateMethods, m) {
			t.Errorf("private_methods %v lacks %s", gi.PrivateMethods, m)
		}
	}
	if err := (nipcash.OnlineCheck{HubIdentity: oc.HubIdentity, Chain: oc.Chain}).Check(gi.Pubkey, gi.Chain); err != nil {
		t.Errorf("online check: %v", err)
	}
	if !nip47.ValidNetwork(gi.Network) {
		t.Errorf("network %q", gi.Network)
	}
	terms, err := nipCO.ParseOrderInfo(info["cash_order"])
	if err != nil || len(info["cash_order"]) == 0 {
		t.Fatalf("cash_order terms: %v", err)
	}
	if err := terms.Validate(0); err != nil {
		t.Errorf("terms: %v", err)
	}
	for _, method := range []string{"cash_order", "cash_lookup", "cash_status", "mint_cash", "pay_invoice"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := nwc.Call(ctx, method, map[string]any{})
		cancel()
		if err != nil || resp.Error == nil || resp.Error.Code != "NOT_IMPLEMENTED" {
			t.Errorf("%s on 23194: %v %+v, want NOT_IMPLEMENTED", method, err, resp)
		}
	}
}

// orderItem builds a cash_order (or cash_lookup) item on the Order connection:
// the bill proof by its secret, the item proof by buyer unless noProof.
func orderItem(t *testing.T, s *suite, oc nipCO.OrderConnection, method string, params json.RawMessage, buyer string,
	noProof bool, nonce string, notAfter int64) transport.Item {
	t.Helper()
	hash, err := transport.CanonicalParamsHash(params)
	if err != nil {
		t.Fatal(err)
	}
	binding := transport.ProofBinding{Target: oc.Pubkey, HubXOnly: s.nodeXOnly, Method: method,
		ParamsHash: hash, Nonce: nonce, NotAfter: notAfter}
	billProof, err := transport.BuildBillProof(oc.Secret, binding)
	if err != nil {
		t.Fatal(err)
	}
	it := transport.Item{ID: "1", Target: oc.Pubkey, Method: method, Params: params, BillProof: billProof}
	if !noProof {
		if it.Proof, err = transport.BuildItemProof(buyer, binding); err != nil {
			t.Fatal(err)
		}
	}
	return it
}

// sendOne publishes one envelope carrying the item build makes and returns the
// item's result object, or nil when it was omitted.
func (s *suite) sendOne(t *testing.T, build func(nonce string, notAfter int64) transport.Item) map[string]json.RawMessage {
	t.Helper()
	e, nonce, replyTo, notAfter := s.newEnvelope(t)
	e["items"] = []transport.Item{build(nonce, notAfter)}
	l := s.listen(t, replyTo)
	r := s.wrap(t, e, "")
	s.publish(t, 0, r.ev)
	got := l.wait(1, s.quiet())
	if len(got) == 0 {
		t.Fatalf("no reply to the envelope")
	}
	var results []map[string]json.RawMessage
	if err := json.Unmarshal(r.open(t, got[0].ev)["results"], &results); err != nil {
		t.Fatalf("results: %v", err)
	}
	if len(results) == 0 {
		return nil
	}
	return results[0]
}

func resultCode(res map[string]json.RawMessage) string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(res["error"], &e)
	return e.Code
}

func orderRequest(t *testing.T, mut func(map[string]any)) json.RawMessage {
	t.Helper()
	target, err := nipCO.NewCashOrderTarget()
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := nipcash.NewRequestID()
	notify, _ := nipCO.NewNotify()
	m := map[string]any{
		"recipient":     map[string]any{"identity_type": "cash", "identity_value": target.Commitment()},
		"amount_millis": 21000000, "payment": "lightning", "notify": notify, "request_id": rid,
	}
	if mut != nil {
		mut(m)
	}
	raw, _ := json.Marshal(m)
	return raw
}

// CT-ORD-02 (CASH-SRV-03, CO-PLACE-01): cash_order is served on the private
// transport against the Order connection; against an unknown key it is omitted.
func ctOrd02(t *testing.T, s *suite) {
	oc, _ := orderConn(t, s)
	buyer, _ := keypair(t)
	res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return orderItem(t, s, oc, nipcash.MethodCashOrder, orderRequest(t, nil), buyer, false, nonce, notAfter)
	})
	if res == nil || res["error"] != nil {
		t.Fatalf("order not served: %v", res)
	}
	var order nipCO.Order
	if err := json.Unmarshal(res["result"], &order); err != nil || order.State != nipCO.OrderOpen {
		t.Errorf("order = %s (%v)", res["result"], err)
	}
	unknown := oc
	_, unknown.Pubkey = keypair(t)
	if res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return orderItem(t, s, unknown, nipcash.MethodCashOrder, orderRequest(t, nil), buyer, false, nonce, notAfter)
	}); res != nil {
		t.Errorf("an order to an unknown key was answered: %v", res)
	}
}

// CT-ORD-03 (CO-REQ-04, CO-PLACE-01): forbidden keys, an on-chain amount not a
// multiple of 1000 (on a Hub selling on-chain: else step 2 refuses first), a bad notify or payment, and a missing proof are
// BAD_REQUEST.
func ctOrd03(t *testing.T, s *suite) {
	oc, nwc := orderConn(t, s)
	info, _ := orderInfo(t, nwc)
	terms, err := nipCO.ParseOrderInfo(info["cash_order"])
	if err != nil {
		t.Fatal(err)
	}
	buyer, _ := keypair(t)
	cases := map[string]func(map[string]any){
		"recipients":          func(m map[string]any) { m["recipients"] = []any{} },
		"expiry":              func(m map[string]any) { m["expiry"] = 60 },
		"cash_secret":         func(m map[string]any) { m["cash_secret"] = strings.Repeat("ab", 32) },
		"idempotency_key":     func(m map[string]any) { m["idempotency_key"] = "x" },
		"min_transfer_millis": func(m map[string]any) { m["min_transfer_millis"] = 1 },
		"on-chain 21000500":   func(m map[string]any) { m["payment"], m["amount_millis"] = "onchain", 21000500 },
		"notify upper":        func(m map[string]any) { m["notify"] = strings.ToUpper(m["notify"].(string)) },
		"payment card":        func(m map[string]any) { m["payment"] = "card" },
	}
	if terms.Onchain == nil {
		delete(cases, "on-chain 21000500")
	}
	for name, mut := range cases {
		res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
			return orderItem(t, s, oc, nipcash.MethodCashOrder, orderRequest(t, mut), buyer, false, nonce, notAfter)
		})
		if code := resultCode(res); code != nipcash.ErrCodeBadRequest {
			t.Errorf("%s: %v, want BAD_REQUEST", name, res)
		}
	}
	res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return orderItem(t, s, oc, nipcash.MethodCashOrder, orderRequest(t, nil), buyer, true, nonce, notAfter)
	})
	if code := resultCode(res); code != nipcash.ErrCodeBadRequest {
		t.Errorf("no proof: %v, want BAD_REQUEST", res)
	}
}

// CT-ORD-14 (CO-CONN-03, CO-S-03): once retired, get_info answers
// "cash_order": {} at once, a new order is RESTRICTED, an order placed before
// is still looked up and its payment still minted; a second connection of the
// same Hub (OrderConnectionAdder) still serves orders.
func ctOrd14(t *testing.T, s *suite) {
	oc, nwc := orderConn(t, s)
	buyer, _ := keypair(t)
	req := orderRequest(t, nil)
	var deadline int64
	if res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		deadline = notAfter
		return orderItem(t, s, oc, nipcash.MethodCashOrder, req, buyer, false, nonce, notAfter)
	}); res == nil || res["error"] != nil {
		t.Fatalf("order before retirement: %v", res)
	}
	s.h.(OrderPayer).RetireOrderConnection(t, oc.Pubkey)
	info, _ := orderInfo(t, nwc)
	terms, err := nipCO.ParseOrderInfo(info["cash_order"])
	if err != nil || !terms.SellsNothing() || strings.TrimSpace(string(info["cash_order"])) != "{}" {
		t.Errorf(`retired get_info cash_order = %s, want {}`, info["cash_order"])
	}
	if res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return orderItem(t, s, oc, nipcash.MethodCashOrder, orderRequest(t, nil), buyer, false, nonce, notAfter)
	}); resultCode(res) != nipcash.ErrCodeRestricted {
		t.Errorf("order on a retired connection: %v, want RESTRICTED", res)
	}
	var sent struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(req, &sent)
	res := s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		lr, _ := json.Marshal(nipcash.CashLookupRequest{RequestID: sent.RequestID, Deadline: deadline})
		return orderItem(t, s, oc, nipcash.MethodCashLookup, lr, buyer, false, nonce, notAfter)
	})
	var lr nipcash.CashLookupResult
	if res == nil || json.Unmarshal(res["result"], &lr) != nil || lr.Status == "" {
		t.Fatalf("lookup on a retired connection: %v", res)
	}
	if lr.Status != nipcash.LookupDone {
		t.Errorf("lookup status %s, want done", lr.Status)
	}
	var before nipCO.Order
	if err := json.Unmarshal(lr.Result, &before); err != nil {
		t.Fatalf("the order placed before retirement: %v", err)
	}
	p := &placed{rid: sent.RequestID, buyer: buyer, payment: before.Payment, amount: before.AmountMillis,
		deadline: deadline, oc: oc, order: &before}
	k := &orderKit{s: s, oc: oc}
	k.pay(t, p, before.PayMillis)
	if o := k.await(t, p, func(o *nipCO.Order) bool { return len(o.Bills) > 0 }); len(o.Bills) != 1 {
		t.Errorf("a payment to an order placed before retirement: %s with %d bills", o.State, len(o.Bills))
	}
	adder, ok := s.h.(OrderConnectionAdder)
	if !ok {
		t.Log("the Hub cannot add an Order connection: the second-connection half is not run")
		return
	}
	oc2, err := nipCO.DecodeOrderConnection(adder.AddOrderConnection(t))
	if err != nil {
		t.Fatalf("the added connection: %v", err)
	}
	k2 := &orderKit{s: s, oc: oc2}
	q, m := k2.request(t, before.Payment, before.AmountMillis, false)
	if res := k2.send(t, q, m); q.order == nil {
		t.Errorf("an order on a second connection of the Hub: %v", res)
	}
}
