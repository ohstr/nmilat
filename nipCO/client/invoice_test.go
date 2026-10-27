package client

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipCO"
)

// A Lightning reply's invoice must be for exactly pay_millis.
func TestCheckOrderInvoice(t *testing.T) {
	ph := sha256.Sum256([]byte("x"))
	inv := func(millis uint64) string {
		s, err := nip57test.SignedBolt11(nip57test.Invoice{Currency: "bc", AmountMillis: millis, PaymentHash: ph[:],
			Timestamp: 1720000000, Expiry: 3600, NodePriv: nip57test.NewKey(1).Priv})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, c := range []struct {
		name    string
		invoice string
		ok      bool
	}{
		{"exact", inv(21022000), true},
		{"one less", inv(21021900), false},
		{"amountless", inv(0), false},
		{"not an invoice", "lnbc210220n1...", false},
	} {
		err := checkOrderInvoice(&nipCO.Order{Payment: nipCO.PaymentLightning, PayMillis: 21022000, Invoice: c.invoice})
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrOrderReplyInvalid)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
