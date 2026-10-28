package nipcw

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip47"
)

var testReserve = nip47.FeeReserve{Ppm: 5000, MinMillis: 10000}

// K-CWFEE-1..6 (NIP-CW §Fees, §Own Funds and Caps).
func TestFees_KnownAnswers(t *testing.T) {
	for _, c := range []struct{ amount, want uint64 }{{399, 0}, {400, 1}, {100_000_000, 250_000}} {
		if got := FeeSkim(c.amount, 2500); got != c.want {
			t.Errorf("K-CWFEE-1: FeeSkim(%d, 2500) = %d, want %d", c.amount, got, c.want)
		}
	}
	if got := MaxCost(10_000_000, 2500, testReserve); got != 10_075_000 {
		t.Errorf("K-CWFEE-2: %d", got)
	}
	if got := MaxCost(9_900_000, 2500, testReserve); got != 9_974_250 {
		t.Errorf("K-CWFEE-3: %d", got)
	}
	for _, c := range []struct{ amount, total uint64 }{{4_962_781, 5_000_000}, {4_962_782, 5_000_001}} {
		fee, res := FeeSkim(c.amount, 2500), RoutingFeeReserve(c.amount, testReserve)
		if fee != 12_406 || res != 24_813 || MaxCost(c.amount, 2500, testReserve) != c.total {
			t.Errorf("K-CWFEE-4/5 %d: fee %d reserve %d total %d", c.amount, fee, res, MaxCost(c.amount, 2500, testReserve))
		}
	}
	// With 15,000,000 used of a 20,000,000 send cap, 4,962,781 fits to the msat.
	if used := uint64(15_000_000); used+MaxCost(4_962_781, 2500, testReserve) != 20_000_000 ||
		used+MaxCost(4_962_782, 2500, testReserve) <= 20_000_000 {
		t.Error("K-CWFEE-4/5: the send cap edge moved")
	}
	if res := RoutingFeeReserve(100_000, testReserve); res != 10_000 || MaxCost(100_000, 2500, testReserve) != 110_250 {
		t.Errorf("K-CWFEE-6: reserve %d total %d", res, MaxCost(100_000, 2500, testReserve))
	}
	if got := MaxCost(1_000_000, 2500, testReserve); got != 1_012_500 {
		t.Errorf("K-CWFEE-6: %d", got)
	}
}

func TestFees_NoOverflow(t *testing.T) {
	if got := MaxCost(math.MaxUint64, 1_000_000, nip47.FeeReserve{Ppm: math.MaxInt64, MinMillis: -1}); got != math.MaxUint64 {
		t.Fatalf("MaxCost saturates, got %d", got)
	}
	if got := RoutingFeeReserve(10, nip47.FeeReserve{Ppm: -5, MinMillis: -5}); got != 0 {
		t.Fatalf("negative reserve fields count as 0, got %d", got)
	}
}

// T12-13: get_budget at 1708000000 for a monthly wallet created 1706695200; with
// 1,000,000 in flight used_budget counts it at the most it may cost (S-CW-129).
func TestGetBudget_SpecExample(t *testing.T) {
	var r nip47.GetBudgetResult
	raw := `{"total_budget":20000000,"used_budget":15000000,"renews_at":1709200800,"renewal_period":"monthly","total_receive_budget":50000000,"used_receive_budget":45000000}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	_, next, err := BudgetPeriod(time.Unix(1706695200, 0), r.RenewalPeriod, time.Unix(1708000000, 0))
	if err != nil || r.RenewsAt == nil || int64(*r.RenewsAt) != next.Unix() {
		t.Fatalf("renews_at %v, period next %d (%v)", r.RenewsAt, next.Unix(), err)
	}
	if send := r.RemainingSend(); send != 5_000_000 {
		t.Fatalf("remaining send %d", send)
	}
	if recv, ok := r.RemainingReceive(); !ok || recv != 5_000_000 {
		t.Fatalf("remaining receive %d %v", recv, ok)
	}
	if used := uint64(r.UsedBudgetMloki) + MaxCost(1_000_000, 2500, testReserve); used != 16_012_500 {
		t.Fatalf("used with one in flight = %d", used)
	}
}
