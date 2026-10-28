package nipcash

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// T09-21, T09-28.
func TestServingMethodAndLists(t *testing.T) {
	rid := "00112233445566778899aabbccddeeff"
	for params, want := range map[string]string{
		`{"cancel":true,"request_id":"` + rid + `"}`:                   MethodCashLookup,
		`{"cancel":true,"request_id":"` + rid + `","cash_secret":"s"}`: MethodCashLookup,
		`{"request_id":"` + rid + `","address":"bc1q"}`:                "cash_withdraw",
	} {
		got, err := ServingMethod("cash_withdraw", json.RawMessage(params))
		if err != nil || got != want {
			t.Errorf("%s → %q %v", params, got, err)
		}
	}
	for _, params := range []string{
		`{"cancel":false,"request_id":"` + rid + `"}`,
		`{"cancel":true,"request_id":"` + rid + `","notify":"x"}`,
		`{"cancel":true,"request_id":"` + rid + `","quote":{}}`,
		`{"cancel":true}`,
	} {
		if _, err := ServingMethod("cash_withdraw", json.RawMessage(params)); !errors.Is(err, ErrBadCancel) {
			t.Errorf("%s: %v", params, err)
		}
	}
	if got, _ := ServingMethod("cash_status", json.RawMessage(`{"cancel":true}`)); got != "cash_status" {
		t.Errorf("other method %q", got)
	}
	cancel, _ := ServingMethod("cash_withdraw", json.RawMessage(`{"cancel":true,"request_id":"`+rid+`"}`))
	if ReuseCheckApplies(cancel) {
		t.Error("a cancel request is reuse-checked")
	}
	for m, want := range map[string]bool{"mint_cash": true, "cash_transfer": true, "cash_consolidate": true, "cash_order": true,
		"cash_withdraw": true, "cash_lookup": false, "cash_status": false, "cash_redeem": false, "create_circle_wallet": false} {
		if ReuseCheckApplies(m) != want {
			t.Errorf("ReuseCheckApplies(%s)", m)
		}
	}
	for _, m := range []string{"cash_status", "cash_redeem", "cash_withdraw_quote", "cash_withdraw", "cash_transfer", "cash_consolidate"} {
		if !AnswersWithTombstone(m) {
			t.Errorf("AnswersWithTombstone(%s)", m)
		}
	}
	if AnswersWithTombstone("cash_lookup") {
		t.Error("cash_lookup answers with a tombstone")
	}
	for m, want := range map[string]bool{"cash_withdraw": true, "cash_transfer": true, "cash_consolidate": true, "cash_order": true,
		"cash_lookup": false, "cash_withdraw_quote": false} {
		if RequiresRequestID(m) != want {
			t.Errorf("RequiresRequestID(%s)", m)
		}
	}
}

// T09-30 (K-VB-2).
func TestKVB2_WithdrawCosts(t *testing.T) {
	it := func(params string, proof bool) transport.Item {
		i := transport.Item{Params: json.RawMessage(params), BillProof: json.RawMessage(`{}`)}
		if proof {
			i.Proof = json.RawMessage(`{}`)
		}
		return i
	}
	for name, tc := range map[string]struct {
		i    transport.Item
		want int
	}{
		"pubkey quote":     {it(`{}`, true), 2},
		"CK quote":         {it(`{"attestation_event":"{}"}`, true), 3},
		"cash-mode quote":  {it(`{}`, false), 1},
		"pubkey withdraw":  {it(`{"identity_event":"{}","quote":{"kind":23187}}`, true), 4},
		"CK withdraw":      {it(`{"identity_event":"{}","attestation_event":"{}","quote":{"kind":23187}}`, true), 5},
		"bearer withdraw":  {it(`{"cash_secret":"s","quote":{"kind":23187}}`, false), 2},
		"cancel by pubkey": {it(`{"cancel":true}`, true), 2},
		"bearer cancel":    {it(`{"cancel":true,"cash_secret":"s"}`, false), 1},
	} {
		if got := tc.i.VerificationCost(); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}
