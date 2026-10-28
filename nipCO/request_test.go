package nipCO

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

const (
	testNotify = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testRID    = "00112233445566778899aabbccddeeff"
	key2       = "0000000000000000000000000000000000000000000000000000000000000002"
)

func secret0to1f() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return hex.EncodeToString(b)
}

func cashParams(t *testing.T) (CashOrderParams, *nipcash.CashTarget) {
	t.Helper()
	target, err := nipcash.CashTargetFromSecret(secret0to1f())
	if err != nil {
		t.Fatal(err)
	}
	return CashOrderParams{Recipient: target, AmountMillis: 21_000_000, Payment: PaymentLightning,
		Notify: testNotify, RequestID: testRID}, target
}

// T20-07: CashOrderParams.Request.
func TestT20_07_Request(t *testing.T) {
	p, target := cashParams(t)
	req, err := p.Request()
	if err != nil {
		t.Fatal(err)
	}
	if req.Recipient.IdentityType != "cash" || req.Recipient.IdentityValue != target.Commitment() ||
		req.Recipient.IdentityValue != "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd" {
		t.Fatalf("recipient = %+v", req.Recipient)
	}
	raw, _ := json.Marshal(req)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "amount_millis,notify,payment,recipient,request_id" {
		t.Fatalf("keys = %v", keys)
	}
	if bytes.Contains(m["recipient"], []byte("amount")) || bytes.Contains(raw, []byte(secret0to1f())) {
		t.Fatalf("recipient = %s", m["recipient"])
	}
	ck, err := nipcash.ResolvedConnectionKey(nipIC.ConnectionKey(strings.Repeat("ab", 32)), "x", "")
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*CashOrderParams){
		"amount 0":        func(p *CashOrderParams) { p.AmountMillis = 0 },
		"on-chain 500":    func(p *CashOrderParams) { p.Payment, p.AmountMillis = PaymentOnchain, 21_000_500 },
		"payment bitcoin": func(p *CashOrderParams) { p.Payment = "bitcoin" },
		"notify upper":    func(p *CashOrderParams) { p.Notify = strings.ToUpper(testNotify) },
		"notify 63":       func(p *CashOrderParams) { p.Notify = testNotify[:63] },
		"no request_id":   func(p *CashOrderParams) { p.RequestID = "" },
		"nil recipient":   func(p *CashOrderParams) { p.Recipient = nil },
		"CK without IA":   func(p *CashOrderParams) { p.Recipient = ck },
	} {
		q := p
		mut(&q)
		if _, err := q.Request(); !errors.Is(err, ErrOrderRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// T20-08: the item: target TLV 0, item proof by the buyer key, bill proof by
// the TLV 2 secret, both with d, h and m; no proofless item.
func TestT20_08_Item(t *testing.T) {
	p, target := cashParams(t)
	sk, pk, err := BuyerKeyFromSecret(target.Secret())
	if err != nil {
		t.Fatal(err)
	}
	b := nipcash.ItemBinding{HubXOnly: kcoIdentity, Nonce: strings.Repeat("ab", 16), NotAfter: time.Now().Unix() + 60}
	item, err := p.Item("1", kcoPubkey, kcoSecret(), sk, b)
	if err != nil {
		t.Fatal(err)
	}
	if item.Target != kcoPubkey || item.Method != nipcash.MethodCashOrder || item.Proof == nil || item.BillProof == nil {
		t.Fatalf("item = %+v", item)
	}
	connPub, _ := utils.GetPublicKey(kcoSecret())
	now := time.Now()
	want := transportBinding(t, item, b)
	if signer, err := transport.VerifyItemProof(item.Proof, want, now); err != nil || signer != pk {
		t.Errorf("item proof: %s %v, want %s", signer, err, pk)
	}
	if signer, err := transport.VerifyBillProof(item.BillProof, want, now); err != nil || signer != connPub {
		t.Errorf("bill proof: %s %v, want %s", signer, err, connPub)
	}
	for _, raw := range []json.RawMessage{item.Proof, item.BillProof} {
		var ev nip01.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, tg := range ev.Tags {
			if len(tg) >= 2 {
				got[tg[0]] = tg[1]
			}
		}
		if got["d"] != kcoPubkey || got["h"] != kcoIdentity || got["m"] != "cash_order" {
			t.Errorf("tags = %v", ev.Tags)
		}
	}
	if _, err := p.Item("1", kcoPubkey, kcoSecret(), "", b); !errors.Is(err, ErrNoBuyerKey) {
		t.Errorf("proofless: %v", err)
	}
}

func transportBinding(t *testing.T, item transport.Item, b nipcash.ItemBinding) transport.ProofBinding {
	t.Helper()
	h, err := transport.CanonicalParamsHash(item.Params)
	if err != nil {
		t.Fatal(err)
	}
	return transport.ProofBinding{Target: item.Target, HubXOnly: b.HubXOnly, Method: item.Method, ParamsHash: h,
		Nonce: b.Nonce, NotAfter: b.NotAfter}
}

const specRequest = `{"recipient":{"identity_type":"cash","identity_value":"630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"},` +
	`"amount_millis":21000000,"payment":"lightning","notify":"` + testNotify + `","request_id":"` + testRID + `"}`

// T20-09: ParseCashOrderRequest.
func TestT20_09_ParseCashOrderRequest(t *testing.T) {
	req, err := ParseCashOrderRequest(json.RawMessage(specRequest))
	if err != nil || req.AmountMillis != 21_000_000 || req.Recipient.IdentityType != "cash" {
		t.Fatalf("spec request: %+v %v", req, err)
	}
	set := func(key, val string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(specRequest), &m)
		m[key] = json.RawMessage(val)
		out, _ := json.Marshal(m)
		return string(out)
	}
	for name, raw := range map[string]string{
		"recipients":          set("recipients", `[]`),
		"expiry":              set("expiry", `60`),
		"cash_secret":         set("cash_secret", `"`+secret0to1f()+`"`),
		"idempotency_key":     set("idempotency_key", `"x"`),
		"min_transfer_millis": set("min_transfer_millis", `1`),
		"on-chain 21000500":   strings.Replace(set("payment", `"onchain"`), "21000000", "21000500", 1),
		"notify upper":        set("notify", `"`+strings.ToUpper(testNotify)+`"`),
		"payment card":        set("payment", `"card"`),
		"recipient bearer":    set("recipient", `{"identity_type":"bearer","identity_value":"`+strings.Repeat("ab", 32)+`"}`),
		"ck without ia":       set("recipient", `{"identity_type":"connection_key","identity_value":"`+strings.Repeat("ab", 32)+`"}`),
		"cash with ia":        set("recipient", `{"identity_type":"cash","identity_value":"`+strings.Repeat("ab", 32)+`","ia_pubkey":"`+strings.Repeat("ab", 32)+`"}`),
		"amount 1.5":          set("amount_millis", `1.5`),
		"amount 0":            set("amount_millis", `0`),
		"bad request_id":      set("request_id", `"xyz"`),
	} {
		req, err := ParseCashOrderRequest(json.RawMessage(raw))
		var oe *OrderError
		if !errors.As(err, &oe) || oe.Code != nipcash.ErrCodeBadRequest || oe.Step != 3 {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if req == nil {
			t.Errorf("%s: the request was not returned", name)
		}
	}
	if req, err := ParseCashOrderRequest(json.RawMessage(`[1]`)); err == nil || req != nil {
		t.Errorf("non-object: %v %v", req, err)
	}
	if req, err := ParseCashOrderRequest(json.RawMessage(set("payment", `5`))); err == nil || req != nil {
		t.Errorf("wrongly typed: %v %v", req, err)
	}
}

func placeReq(t *testing.T, raw string) *CashOrderRequest {
	t.Helper()
	req, _ := ParseCashOrderRequest(json.RawMessage(raw))
	if req == nil {
		t.Fatalf("no request from %s", raw)
	}
	return req
}

func codeStep(err error) (string, int) {
	var oe *OrderError
	if errors.As(err, &oe) {
		return oe.Code, oe.Step
	}
	if err != nil {
		return "other", 0
	}
	return "", 0
}

// T20-10: CheckPlacement in NIP-CO step order.
func TestT20_10_CheckPlacement(t *testing.T) {
	terms := *specTerms(t)
	in := PlacementInput{Terms: terms, IATrusted: true, OpenCeiling: 5_000_000_000, OpenOnchainCeiling: 3, LightningReceivable: true}
	good := placeReq(t, specRequest)
	amount := func(a string) *CashOrderRequest {
		return placeReq(t, strings.Replace(specRequest, "21000000", a, 1))
	}
	onchain := func(a string) *CashOrderRequest {
		return placeReq(t, strings.Replace(strings.Replace(specRequest, "21000000", a, 1), `"lightning"`, `"onchain"`, 1))
	}
	defect := placeReq(t, strings.Replace(specRequest, testNotify, strings.ToUpper(testNotify), 1))
	with := func(f func(*PlacementInput)) PlacementInput { x := in; f(&x); return x }
	noLN := with(func(p *PlacementInput) { p.Terms.Lightning = nil })
	cases := []struct {
		name string
		req  *CashOrderRequest
		in   PlacementInput
		code string
		step int
	}{
		{"ok", good, in, "", 0},
		{"retired + over max", amount("2000000000"), with(func(p *PlacementInput) { p.Retired = true }), "RESTRICTED", 2},
		{"kind not offered", good, noLN, "RESTRICTED", 2},
		{"defect on retired", defect, with(func(p *PlacementInput) { p.Retired = true }), "RESTRICTED", 2},
		{"min-1", amount("999999"), in, "RESTRICTED", 4},
		{"max+1", amount("1000000001"), in, "RESTRICTED", 4},
		{"defect + untrusted", defect, with(func(p *PlacementInput) { p.IATrusted = false }), "BAD_REQUEST", 3},
		{"untrusted + over max", amount("2000000000"), with(func(p *PlacementInput) { p.IATrusted = false }), "RESTRICTED", 3},
		{"open = ceiling", good, with(func(p *PlacementInput) { p.OpenMillis = in.OpenCeiling - 21_000_000 }), "", 0},
		{"ceiling + 1", good, with(func(p *PlacementInput) { p.OpenMillis = in.OpenCeiling - 21_000_000 + 1 }), "QUOTA_EXCEEDED", 5},
		{"on-chain count = ceiling", onchain("21000000"), with(func(p *PlacementInput) { p.OpenOnchainCount = 3 }), "QUOTA_EXCEEDED", 5},
		{"on-chain no count bound", onchain("21000000"), with(func(p *PlacementInput) { p.OpenOnchainCount, p.OpenOnchainCeiling = 99, 0 }), "", 0},
		{"lightning ignores count", good, with(func(p *PlacementInput) { p.OpenOnchainCount = 99 }), "", 0},
		{"ln not receivable", good, with(func(p *PlacementInput) { p.LightningReceivable = false }), "QUOTA_EXCEEDED", 5},
		{"on-chain ignores receivable", onchain("21000000"), with(func(p *PlacementInput) { p.LightningReceivable = false }), "", 0},
		{"out of bounds and over ceiling", amount("1000000001"), with(func(p *PlacementInput) { p.OpenMillis = in.OpenCeiling }), "RESTRICTED", 4},
	}
	for _, c := range cases {
		code, step := codeStep(CheckPlacement(c.req, c.in))
		if code != c.code || step != c.step {
			t.Errorf("%s: %s step %d, want %s step %d", c.name, code, step, c.code, c.step)
		}
	}
}
