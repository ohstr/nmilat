package nip47

import (
	"encoding/json"
	"testing"
)

// TestGetInfoResult_CircleWalletRoundTrips guards against exactly the bug
// found auditing cashctl: lokihub's get_info_controller.go sends a
// circle_hub-only `circle_wallet: {available_mloki, max_exp_secs, fees_ppm,
// circle_policy}` object over the wire, but this type had no field to catch
// it — encoding/json silently drops unknown fields on Unmarshal, so every
// caller (cashctl's `wallet get-info`, `decode --check`) saw an empty
// GetInfoResult where the Hub's own response carried real Circle terms.
func TestGetInfoResult_CircleWalletRoundTrips(t *testing.T) {
	wire := `{
		"alias": "hub",
		"methods": ["get_info", "create_circle_wallet"],
		"circle_wallet": {
			"available_mloki": 42000,
			"max_exp_secs": 86400,
			"fees_ppm": 5000,
			"circle_policy": "allowlist"
		}
	}`
	var got GetInfoResult
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.CircleWallet == nil {
		t.Fatalf("CircleWallet = nil, want populated — the circle_wallet wire field was dropped")
	}
	want := CircleWalletInfo{AvailableMloki: 42000, MaxExpSecs: 86400, FeesPpm: 5000, CirclePolicy: "allowlist"}
	if *got.CircleWallet != want {
		t.Errorf("CircleWallet = %+v, want %+v", *got.CircleWallet, want)
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
