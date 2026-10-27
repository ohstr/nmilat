package nipcash

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

const (
	wdPriv1 = "0000000000000000000000000000000000000000000000000000000000000001"
	wdPriv3 = "0000000000000000000000000000000000000000000000000000000000000003"
	wdHub   = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" // key 1
	wdBill  = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" // key 2
	wdSlice = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" // key 3
	wdCK1   = "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d"
	wdRID1  = "00112233445566778899aabbccddeeff"

	kAddr1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	kAddr2 = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
	kAddr3 = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
	kAddr4 = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"
	kAddr5 = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kj9wkru"
	kAddr6 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

	kWQ1 = "bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22"
	kWQ2 = "484362992237afca0ec22c8ab27a6abb6214ac0294e38f702a5bb75e4678d276"
	kWQ3 = "a913107c809253d590766e54f89cd2d323b460303f00650e7df9660d539227be"
	kWR2 = "2b376b910505799c6f92edcb3c3543e47e73fc210b877cdd91738c367d21cfef"
)

var wdPays = []ScriptType{{0, 20}, {0, 32}, {1, 32}}

// T21-01: DecodeWitnessAddress / ClassifyAddress at HRP bc (K-ADDR-1..12).
func TestT21_01_ClassifyAddress(t *testing.T) {
	for addr, want := range map[string]ScriptType{
		kAddr1: {0, 20}, kAddr2: {0, 32}, kAddr3: {1, 32}, kAddr4: {2, 16}, kAddr5: {1, 20},
	} {
		got, err := ClassifyAddress(addr, "bc")
		if err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", addr, got, err, want)
		}
	}
	if _, err := ClassifyAddress(kAddr6, "bc"); !errors.Is(err, ErrAddressNetwork) {
		t.Errorf("K-ADDR-6: %v", err)
	}
	for _, addr := range []string{
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", // K-ADDR-7
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",                     // K-ADDR-8
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kqq7e2cw9",                   // K-ADDR-9
		strings.ToUpper(kAddr1),                                          // K-ADDR-10
		"BC1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                     // K-ADDR-11
		"bc1" + strings.Repeat("q", 88),                                  // 91 characters
		"bc1",                                                            // nothing after the separator
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb",                     // b is not in the charset
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                     // checksum
	} {
		if _, err := ClassifyAddress(addr, "bc"); !errors.Is(err, ErrAddressMalformed) {
			t.Errorf("%s: %v, want malformed", addr, err)
		}
	}
	if len("bc1"+strings.Repeat("q", 88)) != 91 {
		t.Fatal("length fixture")
	}
	if _, err := ClassifyAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc"); !errors.Is(err, ErrAddressNoWitness) {
		t.Errorf("K-ADDR-12: %v", err)
	}
	if v, prog, err := DecodeWitnessAddress(kAddr1, ""); err != nil || v != 0 || len(prog) != 20 {
		t.Errorf("hrp \"\": %d %x %v", v, prog, err)
	}
}

// T21-02: NormalizeAddress and PaysScriptType.
func TestT21_02_NormalizeAndPays(t *testing.T) {
	if got, err := NormalizeAddress(strings.ToUpper(kAddr1)); err != nil || got != kAddr1 {
		t.Errorf("K-ADDR-10: %q %v", got, err)
	}
	if _, err := NormalizeAddress("BC1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"); !errors.Is(err, ErrAddressMalformed) {
		t.Errorf("K-ADDR-11: %v", err)
	}
	if got, err := NormalizeAddress("  " + kAddr1 + "\t"); err != nil || got != kAddr1 {
		t.Errorf("trim: %q %v", got, err)
	}
	for _, st := range []ScriptType{{2, 16}, {1, 20}} {
		if PaysScriptType(wdPays, st) {
			t.Errorf("%v paid", st)
		}
	}
	if !PaysScriptType(wdPays, ScriptType{1, 32}) {
		t.Error("(1,32) not paid")
	}
	b, _ := json.Marshal(wdPays)
	if string(b) != "[[0,20],[0,32],[1,32]]" {
		t.Errorf("script types JSON %s", b)
	}
	terms := WithdrawTerms{ScriptTypes: [][2]int{{0, 20}, {1, 32}}}
	if got := terms.ScriptTypeList(); len(got) != 2 || got[1] != (ScriptType{1, 32}) {
		t.Errorf("ScriptTypeList %v", got)
	}
	if hex.EncodeToString(WitnessScript(1, bytes.Repeat([]byte{0xaa}, 32)))[:4] != "5120" {
		t.Error("v1 script")
	}
}

// T21-29: WithdrawHRPs and ClassifyAddressAmong (K-ADDR-13).
func TestT21_29_ClassifyAddressAmong(t *testing.T) {
	hrps, ok := WithdrawHRPs("bitcoin")
	if !ok || len(hrps) < 3 || hrps[0] != "bc" {
		t.Fatalf("bitcoin hrps %v %v", hrps, ok)
	}
	if _, ok := WithdrawHRPs("dogecoin"); ok {
		t.Error("an unknown chain is known")
	}
	among := []string{"bc", "tb", "bcrt"}
	for addr, wantHRP := range map[string]string{kAddr6: "tb", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080": "bcrt"} {
		st, hrp, err := ClassifyAddressAmong(addr, among)
		if err != nil || hrp != wantHRP || st != (ScriptType{0, 20}) {
			t.Errorf("%s: %v %s %v", addr, st, hrp, err)
		}
	}
	if _, _, err := ClassifyAddressAmong("zz1qw508d6qejxtdg4y5r3zarvary0c5xw7k3c49eg", among); !errors.Is(err, ErrAddressNetwork) {
		t.Errorf("zz: %v", err)
	}
	if fc, _ := WithdrawHRPs("flokicoin"); fc[0] != "fc" {
		t.Errorf("flokicoin %v", fc)
	}
}

// F-ADDR-1.
func FuzzDecodeWitnessAddress(f *testing.F) {
	for _, s := range []string{kAddr1, kAddr2, kAddr3, kAddr4, kAddr5, kAddr6, strings.ToUpper(kAddr1), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, prog, err := DecodeWitnessAddress(s, "")
		if n, nerr := NormalizeAddress(s); nerr == nil && n != strings.TrimSpace(s) && strings.ToLower(strings.TrimSpace(s)) != n {
			t.Fatalf("NormalizeAddress(%q) = %q", s, n)
		}
		if err != nil {
			return
		}
		if strings.ToLower(s) != s {
			t.Fatalf("accepted a string that is not lowercase: %q", s)
		}
		if v == 0 && len(prog) != 20 && len(prog) != 32 {
			t.Fatalf("v0 program of %d bytes", len(prog))
		}
		hrp := s[:strings.LastIndexByte(s, '1')]
		data, _ := bech32.ConvertBits(prog, 8, 5, true)
		enc := bech32.Encode
		if v > 0 {
			enc = bech32.EncodeM
		}
		re, rerr := enc(hrp, append([]byte{v}, data...))
		if rerr != nil || re != s {
			t.Fatalf("re-encodes to %q (%v), not %q", re, rerr, s)
		}
	})
}

// T21-03: WithdrawFee (K-WFEE-1..6).
func TestT21_03_WithdrawFee(t *testing.T) {
	rf := func(amount, base, ppm uint64) uint64 { f, _, _ := RedeemFee(amount, base, ppm); return f }
	for i, c := range []struct{ amount, network, base, ppm, redeem, hub, fee, payout uint64 }{
		{21000000, 1200000, 500000, 2000, rf(21000000, 0, 5000), 542000, 1742000, 19258000},
		{21000000, 1200001, 500000, 2000, rf(21000000, 0, 5000), 542000, 1743000, 19257000},
		{21000000, 50000, 0, 0, rf(21000000, 100000, 5000), 0, 205000, 20795000},
		{1000000, 1200000, 500000, 2000, rf(1000000, 0, 5000), 502000, 1000000, 0},
		{21000500, 1200000, 500000, 2000, rf(21000500, 0, 5000), 542001, 1742500, 19258000},
		{999, 0, 1, 0, 0, 1, 999, 0},
	} {
		hub, fee, payout, err := WithdrawFee(c.amount, c.network, c.base, c.ppm, c.redeem)
		if err != nil || hub != c.hub || fee != c.fee || payout != c.payout {
			t.Errorf("K-WFEE-%d: %d %d %d %v", i+1, hub, fee, payout, err)
		}
		if payout%1000 != 0 || fee > c.amount || fee+payout != c.amount {
			t.Errorf("K-WFEE-%d: invariants", i+1)
		}
	}
	if _, _, _, err := WithdrawFee(21000000, 0, 0, 1000001, 0); !errors.Is(err, ErrFeeRate) {
		t.Errorf("K-WFEE-6: %v", err)
	}
	if _, _, _, err := WithdrawFee(21000000, 0, 0, 1000000, 0); err != nil {
		t.Errorf("ppm 1e6: %v", err)
	}
	if _, _, _, err := WithdrawFee(^uint64(0), 0, ^uint64(0), 1000000, 0); !errors.Is(err, ErrFeeOverflow) {
		t.Errorf("base + product overflow: %v", err)
	}
	if _, _, _, err := WithdrawFee(10, ^uint64(0), 1, 0, 0); !errors.Is(err, ErrFeeOverflow) {
		t.Errorf("network + hub overflow: %v", err)
	}
}
