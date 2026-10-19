package nip57

import (
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// bolt11FieldsMatchCharset checks the bolt11FieldPaymentHash/
// bolt11FieldDescription/bolt11FieldDescriptionHash constants against the
// bech32 charset directly, documenting where "1", "13" and "23" come from
// rather than leaving them as unexplained magic numbers.
func TestBolt11FieldsMatchCharset(t *testing.T) {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	if got := strings.IndexByte(charset, 'p'); got != bolt11FieldPaymentHash {
		t.Fatalf("'p' is at charset index %d, want %d", got, bolt11FieldPaymentHash)
	}
	if got := strings.IndexByte(charset, 'd'); got != bolt11FieldDescription {
		t.Fatalf("'d' is at charset index %d, want %d", got, bolt11FieldDescription)
	}
	if got := strings.IndexByte(charset, 'h'); got != bolt11FieldDescriptionHash {
		t.Fatalf("'h' is at charset index %d, want %d", got, bolt11FieldDescriptionHash)
	}
}

// TestDecodeBolt11 checks decodeBolt11 against a real Flokicoin mainnet
// invoice, using the same vector (and expected fields) flndecodepay's own
// test suite verifies itself against — see
// github.com/flokiorg/flndecodepay@v1.0.0/decodepay_test.go.
func TestDecodeBolt11(t *testing.T) {
	const invoice = "lnfc50n1p5hxs4npp5smus34m4mzd2jk7gepqkx9j89w2ukrjfajrvevwgslklzgt8l4zsdqqcqzvsxqyz5vqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqyqqqqlgqqqqqeqpjqrzjqtnr4hly8edgpl5wvcx86ekcc2rezdnq2calx5xpwk92l50qscwteapyqqqqqqqqquqqqqlgqqqqqeqpjqrzjqwz8th0q6p25q5wcvxh2s75n960tm3tung3vc7lmmmcdltt98pjs9apyqqqqqqqqqgqqqqlgqqqqqeqpjqsp5ge3wl84an6d34x6r7hm82thlg7vgwdffec5xnut90uwj3fvtaqjs9qxpqysgq6rp4rv2lgkffvd239dmj4ehg7vfxuuulu2amjpjf3rrhjhyay0djvjj8hn95rlz9g2kudqmqhw49urrxm6fhnzx6htwpjv6hj3k53hcq7qxkwk"

	inv, err := decodeBolt11(invoice)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inv.Currency != "fc" {
		t.Errorf("Currency: got %q, want %q", inv.Currency, "fc")
	}
	if inv.AmountMloki != 5000 {
		t.Errorf("AmountMloki: got %d, want 5000", inv.AmountMloki)
	}
	wantPaymentHash := "86f908d775d89aa95bc8c8416316472b95cb0e49ec86ccb1c887edf12167fd45"[:64]
	if inv.PaymentHash != wantPaymentHash {
		t.Errorf("PaymentHash: got %s, want %s", inv.PaymentHash, wantPaymentHash)
	}
	if inv.Description != "" {
		t.Errorf("Description: got %q, want empty (invoice has an empty d tag)", inv.Description)
	}
	if inv.DescriptionHash != "" {
		t.Errorf("DescriptionHash: got %q, want empty (invoice has no h tag)", inv.DescriptionHash)
	}
}

// buildTestBolt11 assembles an unsigned BOLT11 string (zeroed timestamp and
// signature) with a payment hash and the given memo. decodeBolt11 does not
// verify the node signature, so this is enough to exercise field parsing.
func buildTestBolt11(t *testing.T, hrp, memo string) string {
	t.Helper()
	words := make([]byte, bolt11TimestampWords)

	appendField := func(fieldType int, payload []byte) {
		data, err := bech32.ConvertBits(payload, 8, 5, true)
		if err != nil {
			t.Fatalf("convert field %d: %v", fieldType, err)
		}
		words = append(words, byte(fieldType), byte(len(data)/32), byte(len(data)%32))
		words = append(words, data...)
	}
	appendField(bolt11FieldPaymentHash, make([]byte, 32))
	appendField(bolt11FieldDescription, []byte(memo))

	words = append(words, make([]byte, bolt11SignatureWords)...)
	s, err := bech32.Encode(hrp, words)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return s
}

func TestDecodeBolt11DescriptionAndCurrency(t *testing.T) {
	tests := []struct {
		hrp, memo, currency string
		amount              int64
	}{
		{"lnbc2500u", "coffee ☕", "bc", 250000000},
		{"lntb", "testnet tip", "tb", 0},
		{"lnfc10n", "", "fc", 1000},
	}
	for _, test := range tests {
		inv, err := decodeBolt11(buildTestBolt11(t, test.hrp, test.memo))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", test.hrp, err)
		}
		if inv.Currency != test.currency {
			t.Errorf("%s: Currency = %q, want %q", test.hrp, inv.Currency, test.currency)
		}
		if inv.Description != test.memo {
			t.Errorf("%s: Description = %q, want %q", test.hrp, inv.Description, test.memo)
		}
		if inv.AmountMloki != test.amount {
			t.Errorf("%s: AmountMloki = %d, want %d", test.hrp, inv.AmountMloki, test.amount)
		}
	}
}

func TestDecodeBolt11HRP(t *testing.T) {
	tests := []struct {
		hrp      string
		currency string
		want     int64
	}{
		{"lnfc", "fc", 0},
		{"lnfc50n", "fc", 5000},
		{"lnfc2500u", "fc", 250000000},
		{"lnfc1m", "fc", 100000000},
		{"lnfc10p", "fc", 1},
		{"lnbc1", "bc", 100000000000},
		{"lnbcrt20u", "bcrt", 2000000},
	}

	for _, test := range tests {
		currency, got, err := decodeBolt11HRP(test.hrp)
		if err != nil {
			t.Errorf("decodeBolt11HRP(%q): unexpected error: %v", test.hrp, err)
			continue
		}
		if currency != test.currency {
			t.Errorf("decodeBolt11HRP(%q) currency = %q, want %q", test.hrp, currency, test.currency)
		}
		if got != test.want {
			t.Errorf("decodeBolt11HRP(%q) = %d, want %d", test.hrp, got, test.want)
		}
	}
}

func TestDecodeBolt11AmountInvalidPico(t *testing.T) {
	if _, _, err := decodeBolt11HRP("lnfc15p"); err == nil {
		t.Error("expected error for pico amount not divisible by 10")
	}
}

// An amount too large for int64 mloki is refused, never wrapped into a
// different (or negative) amount.
func TestDecodeBolt11HRP_RefusesAnAmountThatOverflows(t *testing.T) {
	for _, hrp := range []string{
		"lnfc99999999999",        // issue #135: wrapped to 1864711949423024128
		"lnfc92233720368547758m", // issue #135: wrapped to -8000000
		"lnfc92233721",
		"lnfc92233720369m",
		"lnfc92233720368548u",
		"lnfc92233720368547759n",
	} {
		if _, got, err := decodeBolt11HRP(hrp); err == nil {
			t.Errorf("decodeBolt11HRP(%q) = %d, want an overflow error", hrp, got)
		}
	}
}

// The largest amount each multiplier can carry still decodes exactly.
func TestDecodeBolt11HRP_LargestAmountPerMultiplier(t *testing.T) {
	for hrp, want := range map[string]int64{
		"lnfc92233720":             9_223_372_000_000_000_000,
		"lnfc92233720368m":         9_223_372_036_800_000_000,
		"lnfc92233720368547u":      9_223_372_036_854_700_000,
		"lnfc92233720368547758n":   9_223_372_036_854_775_800,
		"lnfc9223372036854775800p": 922_337_203_685_477_580,
	} {
		if _, got, err := decodeBolt11HRP(hrp); err != nil || got != want {
			t.Errorf("decodeBolt11HRP(%q) = %d, %v; want %d", hrp, got, err, want)
		}
	}
}
