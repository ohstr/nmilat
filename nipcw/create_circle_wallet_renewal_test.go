package nipcw

import (
	"encoding/json"
	"strings"
	"testing"
)

// NIP-CW §Request: budget_renewal is OPTIONAL, and a Hub refuses one present but empty, so a request with no
// renewal omits the key rather than writing "". One with a renewal writes it, and both parse back.
func TestCreateCircleWalletRequest_OmitsAnEmptyBudgetRenewal(t *testing.T) {
	for _, renewal := range []string{"", "weekly", "never"} {
		r := CreateCircleWalletRequest{Pubkey: "a", ConnectionPubkey: "b", MaxAmount: 1, MaxReceive: 2, BudgetRenewal: renewal, IdentityEvent: "{}"}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(raw), `"budget_renewal"`); has != (renewal != "") {
			t.Errorf("renewal %q: %s", renewal, raw)
		}
		back, err := ParseCreateCircleWalletRequest(raw)
		if err != nil || back.BudgetRenewal != renewal {
			t.Errorf("renewal %q: parsed %q, %v", renewal, back.BudgetRenewal, err)
		}
	}
}
