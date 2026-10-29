package nip57

import (
	"errors"
	"testing"
)

// A second 32-byte payment hash field refuses the invoice: readers disagree on which one counts (flnd keeps the
// first), so a payer could pay a hash other than the one a claim proof binds. A field of another length is skipped,
// as BOLT 11 says.
func TestDecodeBolt11_RepeatedPaymentHashIsRefused(t *testing.T) {
	for name, inv := range map[string]string{
		"two payment hashes are refused":                                  "lnfc1u1qqqqqqqpp5424242424242424242424242424242424242424242424242424qpp5hwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwasqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2ygrr0",
		"the same payment hash twice is refused":                          "lnfc1u1qqqqqqqpp5424242424242424242424242424242424242424242424242424qpp5424242424242424242424242424242424242424242424242424qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyycxat",
		"a payment hash with non-zero padding then a good one is refused": "lnfc1u1qqqqqqqpp5424242424242424242424242424242424242424242424242424ppp5424242424242424242424242424242424242424242424242424qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcljde6",
	} {
		if _, err := decodeBolt11(inv); !errors.Is(err, ErrBolt11PaymentHashRepeated) {
			t.Errorf("%s: got %v, want ErrBolt11PaymentHashRepeated", name, err)
		}
	}
	inv, err := decodeBolt11("lnfc1u1qqqqqqqppj4242424242424242424242424242424242424242424242424gpp5424242424242424242424242424242424242424242424242424qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqymzyf9")
	if err != nil || inv.PaymentHash != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("a short payment hash then a good one: %v %+v", err, inv)
	}
}
