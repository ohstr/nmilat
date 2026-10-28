package nip57test

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipAZ"
)

func TestReceiptsValidate(t *testing.T) {
	sender, provider, recipient := NewKey(1), NewKey(2), NewKey(3)
	cases := []struct {
		name     string
		spec     Spec
		currency string
		validate func(*nip01.Event) error
	}{
		{"9735 bc", Spec{}, "bc", nip57.ValidateZapReceiptForRelay},
		{"9735 fc", Spec{Currency: "fc"}, "fc", nip57.ValidateZapReceiptForRelay},
		{"9521 flokicoin", Spec{Kind: nipAZ.KindAltZapReceipt}, "fc", nipAZ.ValidateAltZapReceiptForRelay},
		{"9521 bitcoin", Spec{Kind: nipAZ.KindAltZapReceipt, Chain: "bitcoin"}, "bc", nipAZ.ValidateAltZapReceiptForRelay},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.spec
			s.Sender, s.Provider, s.Recipient = sender, provider, recipient.Pub
			s.Amount, s.CreatedAt = 21000, 1_700_000_000
			ev, err := Receipt(s)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.validate(ev); err != nil {
				t.Fatalf("receipt doesn't validate: %v", err)
			}
			if ev.PubKey != provider.Pub {
				t.Errorf("signed by %s, want the provider", ev.PubKey)
			}
			var bolt11 string
			for _, tag := range ev.Tags {
				if len(tag) > 1 && tag[0] == "bolt11" {
					bolt11 = tag[1]
				}
			}
			inv, err := nip57.DecodeBolt11(bolt11)
			if err != nil {
				t.Fatal(err)
			}
			if inv.Currency != c.currency || inv.AmountMloki != 21000 {
				t.Errorf("invoice %s %d, want %s 21000", inv.Currency, inv.AmountMloki, c.currency)
			}
		})
	}
}

func TestReceiptUnknownChain(t *testing.T) {
	if _, err := Receipt(Spec{Kind: nipAZ.KindAltZapReceipt, Chain: "dogecoin", Sender: NewKey(1), Provider: NewKey(2), Recipient: NewKey(3).Pub, Amount: 1}); err == nil {
		t.Fatal("want an error for a chain with no invoice currency")
	}
}

// A 9521 to an IA-defined account carries the request's ia, and one with a
// resolved pubkey carries r: both pass the relay subset.
func TestAltZapReceiptAttestedConnection(t *testing.T) {
	ev, err := Receipt(Spec{
		Kind: nipAZ.KindAltZapReceipt, Sender: NewKey(1), Provider: NewKey(2),
		Connection: [2]string{"telegram", "4242"}, Resolved: NewKey(3).Pub, Amount: 21000, CreatedAt: 1_700_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nipAZ.ValidateAltZapReceiptForRelay(ev); err != nil {
		t.Fatal(err)
	}
	r, err := nipAZ.ParseAltZapReceipt(ev)
	if err != nil {
		t.Fatal(err)
	}
	if r.IA != TestIA.Pub || r.Request.IA != TestIA.Pub || r.ResolvedPubkey != NewKey(3).Pub {
		t.Errorf("ia %q, request ia %q, r %q", r.IA, r.Request.IA, r.ResolvedPubkey)
	}
}
