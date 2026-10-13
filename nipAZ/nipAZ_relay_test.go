package nipAZ

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
)

// The *ForRelay validators enforce NIP-AZ's relay column: they tolerate the
// SHOULD/MAY rules a relay can't act on but still reject anything forged.
// Each tolerated case must also fail the strict validator, so a test passing
// here proves the relaxation and not a broken fixture.
//
// nip57.DecodeBolt11 is swapped by stubAltZapInvoice, so no t.Parallel().

func withoutTag(tags [][]string, name string) [][]string {
	var out [][]string
	for _, tag := range tags {
		if tag[0] != name {
			out = append(out, tag)
		}
	}
	return out
}

func TestValidateAltZapRequestForRelay_ToleratesShouldRules(t *testing.T) {
	cases := map[string]func(kind int) [][]string{
		"missing lnurl":     func(kind int) [][]string { return zapRequestTags(kind, "") },
		"lightning address": func(kind int) [][]string { return zapRequestTags(kind, altZapLightningAddress) },
		"missing relays":    func(kind int) [][]string { return withoutTag(zapRequestTags(kind, validTestLnurl), "relays") },
		"https relay": func(kind int) [][]string {
			return append(withoutTag(zapRequestTags(kind, validTestLnurl), "relays"), []string{"relays", "https://relay.example.com"})
		},
		"missing chain": func(kind int) [][]string { return withoutTag(zapRequestTags(kind, validTestLnurl), "chain") },
		"non-numeric amount": func(kind int) [][]string {
			return append(withoutTag(zapRequestTags(kind, validTestLnurl), "amount"), []string{"amount", "lots"})
		},
		"two e tags": func(kind int) [][]string {
			return append(zapRequestTags(kind, validTestLnurl), []string{"e", testPaymentHash}, []string{"e", testPaymentHash})
		},
		"malformed zap split": func(kind int) [][]string {
			return append(zapRequestTags(kind, validTestLnurl), []string{"zap", "not-a-key"})
		},
	}
	for name, tags := range cases {
		for _, kind := range []int{KindAltZapRequest, KindAltZapOnBehalfRequest} {
			ev := altZapRequestWithTags(t, kind, tags(kind))
			if err := ValidateAltZapRequestForRelay(ev); err != nil {
				t.Errorf("%s, kind %d: relay rejected a SHOULD-level miss: %v", name, kind, err)
			}
			if err := ValidateAltZapRequest(ev, 0); err == nil {
				t.Errorf("%s, kind %d: strict validator accepted it; the fixture is not testing a SHOULD rule", name, kind)
			}
		}
	}
}

func TestValidateAltZapRequestForRelay_EnforcesMustRules(t *testing.T) {
	sender := []string{"P", "0000000000000000000000000000000000000000000000000000000000000002"}
	cases := []struct {
		name string
		kind int
		tags [][]string
		want error
	}{
		{"no p", KindAltZapRequest, withoutTag(zapRequestTags(KindAltZapRequest, validTestLnurl), "p"), nip57.ErrRecipientTagCount},
		{"P on 9520", KindAltZapRequest, append(zapRequestTags(KindAltZapRequest, validTestLnurl), sender), ErrSenderTagNotAllowed},
		{"no P on 9523", KindAltZapOnBehalfRequest, withoutTag(zapRequestTags(KindAltZapOnBehalfRequest, validTestLnurl), "P"), ErrMissingSenderTag},
		{"two P on 9523", KindAltZapOnBehalfRequest, append(zapRequestTags(KindAltZapOnBehalfRequest, validTestLnurl), sender), ErrSenderTagCount},
	}
	for _, tc := range cases {
		ev := altZapRequestWithTags(t, tc.kind, tc.tags)
		if err := ValidateAltZapRequestForRelay(ev); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	ev := altZapRequestWithTags(t, KindAltZapRequest, zapRequestTags(KindAltZapRequest, validTestLnurl))
	ev.Content = "tampered"
	if err := ValidateAltZapRequestForRelay(ev); !errors.Is(err, nip57.ErrInvalidSignature) {
		t.Errorf("tampered request: got %v, want ErrInvalidSignature", err)
	}
}

func TestValidateAltZapReceiptForRelay_ToleratesAmountMismatch(t *testing.T) {
	receipt, descHash := signedAltZapReceipt(t)
	stubAltZapInvoice(t, &nip57.Invoice{Currency: "fc", PaymentHash: testPaymentHash, AmountMloki: 999, DescriptionHash: descHash})

	if err := ValidateAltZapReceiptForRelay(receipt); err != nil {
		t.Errorf("relay rejected a settled receipt over an amount mismatch: %v", err)
	}
	if err := ValidateAltZapReceipt(receipt); !errors.Is(err, nip57.ErrAmountMismatch) {
		t.Errorf("strict: got %v, want ErrAmountMismatch", err)
	}
}

func TestValidateAltZapReceiptForRelay_RejectsForgery(t *testing.T) {
	receipt, descHash := signedAltZapReceipt(t)
	good := nip57.Invoice{Currency: "fc", PaymentHash: testPaymentHash, AmountMloki: 1000, DescriptionHash: descHash}

	stubAltZapInvoice(t, &good)
	if err := ValidateAltZapReceiptForRelay(receipt); err != nil {
		t.Fatalf("relay rejected a conforming receipt: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(inv *nip57.Invoice)
		want   error
	}{
		{"hash lock", func(inv *nip57.Invoice) { inv.PaymentHash = "00" + testPaymentHash[2:] }, ErrHashLockMismatch},
		{"invoice chain", func(inv *nip57.Invoice) { inv.Currency = "bc" }, ErrChainMismatch},
		{"description hash", func(inv *nip57.Invoice) { inv.DescriptionHash = "" }, nip57.ErrDescriptionHashMismatch},
	}
	for _, tc := range cases {
		inv := good
		tc.mutate(&inv)
		stubAltZapInvoice(t, &inv)
		if err := ValidateAltZapReceiptForRelay(receipt); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	stubAltZapInvoice(t, &good)
	forged := &nip01.Event{Kind: KindAltZapReceipt, Tags: append(withoutTag(receipt.Tags, "p"), []string{"p", "0000000000000000000000000000000000000000000000000000000000000009"})}
	if err := forged.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign forged receipt: %v", err)
	}
	if err := ValidateAltZapReceiptForRelay(forged); !errors.Is(err, nip57.ErrRecipientMismatch) {
		t.Errorf("redirected recipient: got %v, want ErrRecipientMismatch", err)
	}
}
