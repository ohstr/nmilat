package nip57

import (
	"strings"
	"testing"
)

// bolt11FieldsMatchCharset checks the bolt11FieldPaymentHash/
// bolt11FieldDescriptionHash constants against the bech32 charset directly,
// documenting where "1" and "23" come from rather than leaving them as
// unexplained magic numbers.
func TestBolt11FieldsMatchCharset(t *testing.T) {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	if got := strings.IndexByte(charset, 'p'); got != bolt11FieldPaymentHash {
		t.Fatalf("'p' is at charset index %d, want %d", got, bolt11FieldPaymentHash)
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

	if inv.AmountMloki != 5000 {
		t.Errorf("AmountMloki: got %d, want 5000", inv.AmountMloki)
	}
	wantPaymentHash := "86f908d775d89aa95bc8c8416316472b95cb0e49ec86ccb1c887edf12167fd45"[:64]
	if inv.PaymentHash != wantPaymentHash {
		t.Errorf("PaymentHash: got %s, want %s", inv.PaymentHash, wantPaymentHash)
	}
	if inv.DescriptionHash != "" {
		t.Errorf("DescriptionHash: got %q, want empty (invoice has no h tag)", inv.DescriptionHash)
	}
}

func TestDecodeBolt11AmountMultipliers(t *testing.T) {
	tests := []struct {
		hrp  string
		want int64
	}{
		{"lnfc", 0},
		{"lnfc50n", 5000},
		{"lnfc2500u", 250000000},
		{"lnfc1m", 100000000},
		{"lnfc10p", 1},
		{"lnbc1", 100000000000},
	}

	for _, test := range tests {
		got, err := decodeBolt11Amount(test.hrp)
		if err != nil {
			t.Errorf("decodeBolt11Amount(%q): unexpected error: %v", test.hrp, err)
			continue
		}
		if got != test.want {
			t.Errorf("decodeBolt11Amount(%q) = %d, want %d", test.hrp, got, test.want)
		}
	}
}

func TestDecodeBolt11AmountInvalidPico(t *testing.T) {
	if _, err := decodeBolt11Amount("lnfc15p"); err == nil {
		t.Error("expected error for pico amount not divisible by 10")
	}
}
