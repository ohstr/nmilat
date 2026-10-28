package nipCO

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// The NIP-CO §Terms get_info example.
const specGetInfo = `{
  "methods": ["get_info"],
  "private_methods": ["cash_lookup", "cash_order"],
  "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "network": "mainnet",
  "chain": "bitcoin",
  "cash_order": {
    "lightning": {"min_millis": 1000000, "max_millis": 1000000000, "fee_base": 1000, "fee_ppm": 1000, "window": 3600},
    "onchain": {"min_millis": 10000000, "max_millis": 1000000000, "fee_base": 21000, "fee_ppm": 2000, "window": 86400,
      "confirmations": [{"up_to_millis": 100000000, "n": 1}, {"up_to_millis": 1000000000, "n": 3}, {"n": 6}]},
    "bill": {"redeem_fee_base": 0, "redeem_fee_ppm": 5000, "min_transfer_millis": 1000}
  }
}`

func u64(v uint64) *uint64 { return &v }

func specTerms(t *testing.T) *Terms {
	t.Helper()
	terms, err := ParseOrderInfo(json.RawMessage(specGetInfo))
	if err != nil {
		t.Fatal(err)
	}
	return terms
}

// T20-03: ParseOrderInfo.
func TestT20_03_ParseOrderInfo(t *testing.T) {
	terms := specTerms(t)
	want := Terms{
		Lightning: &KindTerms{MinMillis: 1000000, MaxMillis: 1000000000, FeeBase: 1000, FeePpm: 1000, Window: 3600},
		Onchain: &KindTerms{MinMillis: 10000000, MaxMillis: 1000000000, FeeBase: 21000, FeePpm: 2000, Window: 86400,
			Confirmations: []Tier{{UpToMillis: u64(100000000), N: 1}, {UpToMillis: u64(1000000000), N: 3}, {N: 6}}},
		Bill: BillTerms{RedeemFeePpm: 5000, MinTransferMillis: 1000},
	}
	if !reflect.DeepEqual(*terms, want) {
		t.Fatalf("terms = %+v", terms)
	}
	if terms.SellsNothing() {
		t.Fatal("sells nothing")
	}
	only, err := ParseOrderInfo(json.RawMessage(`{"cash_order":{"onchain":` +
		`{"min_millis":1,"max_millis":2,"fee_base":0,"fee_ppm":0,"window":1,"confirmations":[{"n":1}]}}}`))
	if err != nil || only.Lightning != nil || only.Onchain == nil {
		t.Fatalf("missing kind: %+v %v", only, err)
	}
	for _, empty := range []string{`{}`, `{"cash_order":{}}`, `{"cash_order":{"bill":{}}}`} {
		n, err := ParseOrderInfo(json.RawMessage(empty))
		if err != nil || !n.SellsNothing() {
			t.Errorf("%s: %+v %v", empty, n, err)
		}
	}
	for _, v := range []string{`1.5`, `"1000"`, `1e3`, `-1`} {
		raw := `{"cash_order":{"lightning":{"min_millis":` + v + `,"max_millis":2,"fee_base":0,"fee_ppm":0,"window":1}}}`
		if _, err := ParseOrderInfo(json.RawMessage(raw)); !errors.Is(err, ErrOrderTerms) {
			t.Errorf("min_millis %s: %v", v, err)
		}
	}
	if _, err := ParseOrderInfo(json.RawMessage(`[]`)); !errors.Is(err, ErrOrderTerms) {
		t.Errorf("array: %v", err)
	}
}

// T20-04: Terms.Validate.
func TestT20_04_Validate(t *testing.T) {
	if err := specTerms(t).Validate(1_000_000_000); err != nil {
		t.Fatalf("spec terms: %v", err)
	}
	mut := func(f func(*Terms)) Terms {
		tt := *specTerms(t)
		l, o := *tt.Lightning, *tt.Onchain
		o.Confirmations = append([]Tier(nil), o.Confirmations...)
		tt.Lightning, tt.Onchain = &l, &o
		f(&tt)
		return tt
	}
	over := mut(func(t *Terms) { t.Lightning.MaxMillis = 1_000_000_001 })
	if err := over.Validate(1_000_000_000); !errors.Is(err, ErrOrderTerms) {
		t.Errorf("over the ceiling: %v", err)
	}
	if err := over.Validate(0); err != nil {
		t.Errorf("client Validate(0): %v", err)
	}
	for name, tt := range map[string]Terms{
		"min > max": mut(func(t *Terms) { t.Onchain.MinMillis = t.Onchain.MaxMillis + 1 }),
		"descending": mut(func(t *Terms) {
			t.Onchain.Confirmations = []Tier{{UpToMillis: u64(1e9), N: 1}, {UpToMillis: u64(1e8), N: 3}, {N: 6}}
		}),
		"n 0":         mut(func(t *Terms) { t.Onchain.Confirmations[1].N = 0 }),
		"open middle": mut(func(t *Terms) { t.Onchain.Confirmations[0].UpToMillis = nil }),
		"closed last": mut(func(t *Terms) { t.Onchain.Confirmations[2].UpToMillis = u64(5e9) }),
		"no tiers":    mut(func(t *Terms) { t.Onchain.Confirmations = nil }),
		"ln tiers":    mut(func(t *Terms) { t.Lightning.Confirmations = []Tier{{N: 1}} }),
		"window 0":    mut(func(t *Terms) { t.Lightning.Window = 0 }),
	} {
		if err := tt.Validate(0); !errors.Is(err, ErrOrderTerms) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (Terms{}).Validate(1); err != nil {
		t.Errorf("sells nothing: %v", err)
	}
}

// T20-06: OrderFee (K-OFEE-1..3) and ConfirmationsFor (K-TIER-1..3).
func TestT20_06_FeesAndTiers(t *testing.T) {
	cases := []struct {
		kind           string
		base, ppm, amt uint64
		fee, pay       uint64
	}{
		{PaymentLightning, 1000, 1000, 21_000_000, 22_000, 21_022_000},
		{PaymentOnchain, 21000, 2000, 21_000_000, 63_000, 21_063_000},
		{PaymentOnchain, 21000, 2001, 21_000_000, 64_000, 21_064_000},
	}
	for i, c := range cases {
		fee, pay, err := OrderFee(c.kind, KindTerms{FeeBase: c.base, FeePpm: c.ppm}, c.amt)
		if err != nil || fee != c.fee || pay != c.pay {
			t.Errorf("K-OFEE-%d: %d %d %v", i+1, fee, pay, err)
		}
	}
	for amt := uint64(1000); amt < 200_000; amt += 7000 {
		_, pay, err := OrderFee(PaymentOnchain, KindTerms{FeeBase: 333, FeePpm: 1234}, amt)
		if err != nil || pay%1000 != 0 {
			t.Fatalf("on-chain pay %d not whole base units (%v)", pay, err)
		}
	}
	if _, _, err := OrderFee(PaymentLightning, KindTerms{FeeBase: 1}, ^uint64(0)); !errors.Is(err, ErrOrderAmount) {
		t.Errorf("2^64 overflow: %v", err)
	}
	if _, _, err := OrderFee(PaymentLightning, KindTerms{FeePpm: ^uint64(0)}, ^uint64(0)); !errors.Is(err, ErrOrderAmount) {
		t.Errorf("product overflow: %v", err)
	}
	if _, _, err := OrderFee(PaymentOnchain, KindTerms{}, 21_000_500); err == nil {
		t.Error("on-chain 21,000,500 accepted")
	}
	tiers := specTerms(t).Onchain.Confirmations
	for _, c := range []struct {
		v uint64
		n uint32
	}{{21_063_000, 1}, {500_000_000, 3}, {2_000_000_000, 6}, {100_000_000, 1}, {100_000_001, 3}} {
		if n, err := ConfirmationsFor(tiers, c.v); err != nil || n != c.n {
			t.Errorf("ConfirmationsFor(%d) = %d %v, want %d", c.v, n, err, c.n)
		}
	}
	if _, err := ConfirmationsFor(nil, 1); err == nil {
		t.Error("no tiers accepted")
	}
	// The reply's confirmations is the tier of pay_millis.
	_, pay, _ := OrderFee(PaymentOnchain, *specTerms(t).Onchain, 21_000_000)
	if n, _ := ConfirmationsFor(tiers, pay); n != 1 {
		t.Errorf("tier of pay_millis %d = %d", pay, n)
	}
}

// T20-12: MintSplit (K-SPLIT-1, K-OMINT-1..5).
func TestT20_12_MintSplit(t *testing.T) {
	const fee, max = 63_000, 1_000_000_000
	for _, c := range []struct {
		received uint64
		want     []uint64
	}{
		{2_500_063_000, []uint64{1_000_000_000, 1_000_000_000, 500_000_000}},
		{21_063_000, []uint64{21_000_000}},
		{20_000_000, []uint64{19_937_000}},
		{25_000_000, []uint64{24_937_000}},
		{10_000_000, []uint64{9_937_000}},
		{50_000, nil},
		{fee, nil},
		{fee + 1, []uint64{1}},
		{fee + max, []uint64{max}},
	} {
		if got := MintSplit(c.received, fee, max); !reflect.DeepEqual(got, c.want) {
			t.Errorf("MintSplit(%d) = %v, want %v", c.received, got, c.want)
		}
	}
}
