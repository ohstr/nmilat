package nipCZ

import "testing"

// T14-04 (10522 half) and CZ-INFO-01.
func TestParseCashZapInfo(t *testing.T) {
	f := newFx(t)
	m1, m2, m3 := hexKey(t), hexKey(t), hexKey(t)
	c1, _ := compressed(m1)
	_, c2 := compressed(m2)
	c3, _ := compressed(m3)
	info, err := ParseCashZapInfo(signInfo(t, f.recipPriv,
		[]string{"chain", "bitcoin"},
		[]string{"mint", c1, "bitcoin"},
		[]string{"mint", c2, "flokicoin"}, // chain not accepted: ignored
		[]string{"mint", c3},              // no chain: ignored
		[]string{"mint", m3, "bitcoin"},   // x-only, not 66 hex: ignored
		[]string{"relay", "wss://r.example"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if info.Pubkey != f.recip || !info.Accepts("bitcoin") || info.Accepts("flokicoin") {
		t.Fatalf("%+v", info)
	}
	if !info.ListsMinter(m1, "bitcoin") || !info.ListsMinter("03"+m1, "bitcoin") || !info.ListsMinter(c1, "bitcoin") {
		t.Fatal("listed minter not found by every key form")
	}
	if info.ListsMinter(m2, "flokicoin") || info.ListsMinter(m3, "bitcoin") || info.ListsMinter(m1, "flokicoin") {
		t.Fatal("an ignored mint counted")
	}
	if len(info.Relays) != 1 {
		t.Fatal(info.Relays)
	}

	// No chain tags: any chain, and a mint for any chain counts.
	info, err = ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"mint", c2, "flokicoin"}))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Accepts("anything") || !info.ListsMinter(m2, "flokicoin") || info.ListsMinter(m2, "bitcoin") {
		t.Fatalf("%+v", info)
	}

	// No 10522: any chain, no minter.
	var none *CashZapInfo
	if !none.Accepts("bitcoin") || none.ListsMinter(m1, "bitcoin") {
		t.Fatal("nil info")
	}
	if _, err := ParseCashZapInfo(f.note); err == nil {
		t.Fatal("wrong kind parsed")
	}
}

// T14-04: 02‖K, 03‖K, x-only K and a get_info pubkey K are one Minter (S-CZ-55).
func TestSameMinter(t *testing.T) {
	k := hexKey(t)
	c02, c03 := compressed(k)
	for _, pair := range [][2]string{{c02, c03}, {c02, k}, {c03, k}, {k, k}} {
		if !SameMinter(pair[0], pair[1]) {
			t.Fatalf("%v", pair)
		}
	}
	if SameMinter("04"+k, k) || SameMinter(k, hexKey(t)) || SameMinter("", "") {
		t.Fatal("matched a different key")
	}
}
