package nip47

import (
	"encoding/hex"
	"encoding/json"
	"github.com/ohstr/nmilat/nip01"
	"reflect"
	"strings"
	"testing"
)

// TestGetInfoResult_CircleWalletRoundTrips guards against exactly the bug
// found auditing cashctl: lokihub's get_info_controller.go sends a
// circle_hub-only `circle_wallet: {available_millis, max_exp_secs, fees_ppm,
// circle_policy}` object over the wire, but this type had no field to catch
// it — encoding/json silently drops unknown fields on Unmarshal, so every
// caller (cashctl's `wallet get-info`, `decode --check`) saw an empty
// GetInfoResult where the Hub's own response carried real Circle terms.
func TestGetInfoResult_CircleWalletRoundTrips(t *testing.T) {
	wire := `{
		"alias": "hub",
		"methods": ["get_info", "create_circle_wallet"],
		"circle_wallet": {
			"available_millis": 42000,
			"max_exp_secs": 86400,
			"fees_ppm": 5000,
			"circle_policy": "follow_set",
			"identity": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"per_wallet_max_millis": 500000,
			"min_budget_renewal": "monthly"
		}
	}`
	var got GetInfoResult
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.CircleWallet == nil {
		t.Fatalf("CircleWallet = nil, want populated — the circle_wallet wire field was dropped")
	}
	want := CircleWalletInfo{
		AvailableMillis: 42000, MaxExpSecs: 86400, FeesPpm: 5000, CirclePolicy: CirclePolicyFollowSet,
		Identity:           "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		PerWalletMaxMillis: 500000, MinBudgetRenewal: "monthly",
	}
	g := *got.CircleWallet
	g.present = nil
	if !reflect.DeepEqual(g, want) {
		t.Errorf("CircleWallet = %+v, want %+v", g, want)
	}
}

// TestCircleWalletInfo_UnreportedLimitsStayOffTheWire checks that a Hub that
// doesn't report its per-wallet ceiling or renewal floor (both OPTIONAL in
// NIP-CW) sends neither key, rather than a misleading 0 or "".
func TestCircleWalletInfo_UnreportedLimitsStayOffTheWire(t *testing.T) {
	raw, err := json.Marshal(CircleWalletInfo{AvailableMillis: 1, CirclePolicy: CirclePolicyAllowlist})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, key := range []string{"per_wallet_max_millis", "min_budget_renewal"} {
		if strings.Contains(string(raw), key) {
			t.Errorf("%s = present in %s, want omitted", key, raw)
		}
	}
}

// TestGetInfoResult_CircleWalletAbsentForOrdinaryWallet confirms an ordinary
// (non-circle_hub) get_info response — no circle_wallet key at all, the
// common case — leaves CircleWallet nil rather than a zero-valued struct, so
// callers can tell "not a circle_hub connection" apart from "a circle_hub
// with every field legitimately zero."
func TestGetInfoResult_CircleWalletAbsentForOrdinaryWallet(t *testing.T) {
	var got GetInfoResult
	if err := json.Unmarshal([]byte(`{"alias":"plain wallet","methods":["get_info"]}`), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.CircleWallet != nil {
		t.Errorf("CircleWallet = %+v, want nil", got.CircleWallet)
	}
}

// TestPayInvoiceResult_FeeSkimRoundTrips guards the pay_invoice/pay_keysend/
// list_transactions counterpart of the same bug: lokihub's payResponse and
// nip47/models.Transaction both carry a `fee_skim_mloki` field specifically
// so a circle_wallet member can see the Hub's forwarding-fee cut on top of
// the real routing fee (nip47/controllers/models.go's own doc comment: without
// it "a circle member had no NWC-facing way to learn why their balance
// dropped by more than invoice_amount+fees_paid"). PayInvoiceResult/
// PayKeysendResult/Transaction here had no matching field.
func TestPayInvoiceResult_FeeSkimRoundTrips(t *testing.T) {
	var got PayInvoiceResult
	if err := json.Unmarshal([]byte(`{"preimage":"deadbeef","fees_paid":3,"fee_skim_mloki":500}`), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.FeeSkimMloki != 500 {
		t.Errorf("FeeSkimMloki = %d, want 500", got.FeeSkimMloki)
	}
	if got.FeesPaidMloki != 3 {
		t.Errorf("FeesPaidMloki = %d, want 3", got.FeesPaidMloki)
	}
}

func TestPayKeysendResult_FeeSkimRoundTrips(t *testing.T) {
	var got PayKeysendResult
	if err := json.Unmarshal([]byte(`{"preimage":"deadbeef","fee_skim_mloki":250}`), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.FeeSkimMloki != 250 {
		t.Errorf("FeeSkimMloki = %d, want 250", got.FeeSkimMloki)
	}
}

func TestTransaction_FeeSkimRoundTrips(t *testing.T) {
	var got Transaction
	wire := `{"type":"outgoing","payment_hash":"ab12","amount":50000,"fees_paid":3,"fee_skim_mloki":250,"created_at":1}`
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.FeeSkimMloki != 250 {
		t.Errorf("FeeSkimMloki = %d, want 250", got.FeeSkimMloki)
	}
}

// T08-01, T08-02 (K-N47-1): one expiration tag, covered by the id; the reader's
// refusals.
func TestT08_01_Expiration(t *testing.T) {
	app := strings.Repeat("0", 63) + "1"
	wallet := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	ev, err := NewRequestEvent(app, wallet, "mint_cash", map[string]int{"a": 1}, EncryptionNIP44V2, WithExpiration(1720000300))
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Sign(app); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := RequestExpiration(ev); err != nil || !ok || v != 1720000300 {
		t.Fatalf("RequestExpiration %d %v %v", v, ok, err)
	}
	n := 0
	for _, tag := range ev.Tags {
		if tag[0] == "expiration" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d expiration tags", n)
	}
	before := ev.ID
	ev.Tags[len(ev.Tags)-1][1] = "1720000301"
	if id, _ := ev.HashID(); hex.EncodeToString(id) == before {
		t.Error("the id does not cover the expiration")
	}
	if _, err := NewRequestEvent(app, wallet, "mint_cash", nil, EncryptionNIP44V2, WithExpiration(0)); err == nil {
		t.Error("expiration 0 built")
	}
	if _, ok, _ := RequestExpiration(&nip01.Event{}); ok {
		t.Error("missing reported present")
	}
	for name, tags := range map[string][][]string{
		"two":  {{"expiration", "1"}, {"expiration", "2"}},
		"0123": {{"expiration", "0123"}},
		"12a":  {{"expiration", "12a"}},
		"-5":   {{"expiration", "-5"}},
	} {
		if _, _, err := RequestExpiration(&nip01.Event{Tags: tags}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// T08-04, T08-10: the circle terms round trip; fees_ppm 0 is reported; accepting
// true, false or absent; MissingAlways names what a block left out.
func TestT08_04_CircleWalletInfo(t *testing.T) {
	full := `{"available_millis":1,"max_exp_secs":2,"fees_ppm":0,"fee_reserve":{"ppm":10,"min_millis":1000},` +
		`"dust_threshold_millis":5,"circle_policy":"allowlist","identity":"ab","accepting":false,` +
		`"rotation_delay_secs":86400,"per_wallet_max_receive_millis":9}`
	var i CircleWalletInfo
	if err := json.Unmarshal([]byte(full), &i); err != nil {
		t.Fatal(err)
	}
	if i.FeeReserve == nil || i.FeeReserve.Ppm != 10 || *i.DustThresholdMillis != 5 || *i.RotationDelaySecs != 86400 ||
		i.PerWalletMaxReceiveMillis != 9 || i.Accepting == nil || *i.Accepting {
		t.Fatalf("%+v", i)
	}
	if m := i.MissingAlways(); len(m) != 0 {
		t.Errorf("missing %v", m)
	}
	b, _ := json.Marshal(i)
	if !strings.Contains(string(b), `"fees_ppm":0`) {
		t.Errorf("fees_ppm 0 dropped: %s", b)
	}
	var sparse CircleWalletInfo
	_ = json.Unmarshal([]byte(`{"available_millis":1}`), &sparse)
	if sparse.Accepting != nil || len(sparse.MissingAlways()) != 7 {
		t.Errorf("sparse: %+v %v", sparse, sparse.MissingAlways())
	}
}

// T08-05, T08-06, T08-07, T08-08, T08-09.
func TestT08_05_BudgetNotificationsCodesNetwork(t *testing.T) {
	total, used := int64(100), int64(150)
	r := GetBudgetResult{TotalBudgetMloki: 10, UsedBudgetMloki: 20, TotalReceiveBudget: &total, UsedReceiveBudget: &used}
	if r.RemainingSend() != 0 {
		t.Error("send not clamped")
	}
	if v, ok := r.RemainingReceive(); !ok || v != 0 {
		t.Error("receive not clamped")
	}
	if _, ok := (GetBudgetResult{}).RemainingReceive(); ok {
		t.Error("absent receive budget reported")
	}
	var rp RotationPending
	if err := json.Unmarshal([]byte(`{"connection_pubkey":"ab","completes_at":1720000000}`), &rp); err != nil || rp.CompletesAt != 1720000000 {
		t.Errorf("rotation_pending: %+v", rp)
	}
	if ErrRequestReused != "REQUEST_REUSED" || ErrWalletExists != "WALLET_EXISTS" || NotificationWalletFrozen != "wallet_frozen" ||
		MethodDeleteCircleWallet != "delete_circle_wallet" {
		t.Error("constants")
	}
	var info GetInfoResult
	_ = json.Unmarshal([]byte(`{"methods":["get_info"],"network":"regtest","chain":"bitcoin"}`), &info)
	if info.Network != "regtest" || info.Chain != "bitcoin" {
		t.Errorf("%+v", info)
	}
	for _, n := range []string{"mainnet", "testnet", "signet", "regtest"} {
		if !ValidNetwork(n) {
			t.Errorf("%s", n)
		}
	}
	for _, n := range []string{"Mainnet", "main", ""} {
		if ValidNetwork(n) {
			t.Errorf("%q valid", n)
		}
	}
}
