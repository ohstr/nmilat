package nipAZ

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
)

// AltZap is deliberately stricter than NIP-57: the lnurl tag is required on
// 5520/5523 and must be bech32, and a description hash that doesn't bind the
// embedded request must reject. nip57 relaxes both for relay ingest, and
// nipAZ shares nip57's error values and utils.ValidateLNURL with it, so
// these tests pin the AltZap side against that relaxation leaking across.
//
// nip57.DecodeBolt11 is a package-level var these tests swap, so nothing in
// this file may call t.Parallel().

const altZapLightningAddress = "alice@example.com"

// altZapRequestWithTags signs a request of the given kind from a full tag
// set, so a test can omit or corrupt any single tag.
func altZapRequestWithTags(t *testing.T, kind int, tags [][]string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: kind, Tags: tags}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return ev
}

// zapRequestTags returns the tags for a 5520/5523 request with the given
// lnurl value; an empty lnurl omits the tag entirely.
func zapRequestTags(kind int, lnurl string) [][]string {
	recipient := "0000000000000000000000000000000000000000000000000000000000000001"
	tags := [][]string{
		{"p", recipient, "nostr"},
		{"amount", "1000"},
		{"chain", "flokicoin"},
		{"relays", "wss://relay.example.com"},
	}
	if lnurl != "" {
		tags = append(tags, []string{"lnurl", lnurl})
	}
	if kind == KindAltZapOnBehalfRequest {
		tags = append(tags, []string{"P", recipient})
	}
	return tags
}

func TestAltZapRejectsLightningAddressLnurl(t *testing.T) {
	for _, kind := range []int{KindAltZapRequest, KindAltZapOnBehalfRequest} {
		ev := altZapRequestWithTags(t, kind, zapRequestTags(kind, altZapLightningAddress))

		err := ValidateAltZapRequest(ev, 0)
		if err == nil {
			t.Fatalf("kind %d: AltZap accepted a lightning address in the lnurl tag", kind)
		}
		if !errors.Is(err, nip57.ErrInvalidLNURL) {
			t.Errorf("kind %d: got %v, want nip57.ErrInvalidLNURL", kind, err)
		}
	}
}

func TestAltZapDirectPaymentRejectsLightningAddressLnurl(t *testing.T) {
	recipient := "0000000000000000000000000000000000000000000000000000000000000001"
	ev := altZapRequestWithTags(t, KindAltZapDirectPayment, [][]string{
		{"amount", "1000"},
		{"bolt11", "lnfc-direct-payment"},
		{"chain", "flokicoin"},
		{"relays", "wss://relay.example.com"},
		{"P", recipient},
		{"lnurl", altZapLightningAddress},
	})

	err := ValidateAltZapRequest(ev, 0)
	if err == nil {
		t.Fatal("AltZap accepted a lightning address in a direct-payment lnurl tag")
	}
	if !errors.Is(err, nip57.ErrInvalidLNURL) {
		t.Errorf("got %v, want nip57.ErrInvalidLNURL", err)
	}
}

func TestAltZapRequiresLnurlTag(t *testing.T) {
	for _, kind := range []int{KindAltZapRequest, KindAltZapOnBehalfRequest} {
		ev := altZapRequestWithTags(t, kind, zapRequestTags(kind, ""))

		err := ValidateAltZapRequest(ev, 0)
		if err == nil {
			t.Fatalf("kind %d: AltZap accepted a request with no lnurl tag", kind)
		}
		if !errors.Is(err, ErrMissingLNURLTag) {
			t.Errorf("kind %d: got %v, want ErrMissingLNURLTag", kind, err)
		}
	}
}

// Non-vacuity check: the guards above must fail for the lnurl value, not
// because the fixture is malformed in some other way.
func TestAltZapAcceptsBech32Lnurl(t *testing.T) {
	for _, kind := range []int{KindAltZapRequest, KindAltZapOnBehalfRequest} {
		ev := altZapRequestWithTags(t, kind, zapRequestTags(kind, validTestLnurl))

		if err := ValidateAltZapRequest(ev, 0); err != nil {
			t.Errorf("kind %d: AltZap rejected a valid bech32 lnurl: %v", kind, err)
		}
	}
}

// signedAltZapReceipt builds a 5521 receipt embedding a valid 5520 request,
// and returns it with the hex sha256 of its description tag.
func signedAltZapReceipt(t *testing.T) (*nip01.Event, string) {
	t.Helper()
	req := signedZapRequestEvent(t, KindAltZapRequest, nil)
	descBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal embedded request: %v", err)
	}
	sum := sha256.Sum256(descBytes)

	receipt := &nip01.Event{
		Kind: KindAltZapReceipt,
		Tags: [][]string{
			{"bolt11", "lnfc-zap"},
			{"chain", "flokicoin"},
			{"preimage", "preimage1"},
			{"p", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"description", string(descBytes)},
		},
	}
	if err := receipt.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return receipt, hex.EncodeToString(sum[:])
}

func stubAltZapInvoice(t *testing.T, inv *nip57.Invoice) {
	t.Helper()
	original := nip57.DecodeBolt11
	t.Cleanup(func() { nip57.DecodeBolt11 = original })
	nip57.DecodeBolt11 = func(string) (*nip57.Invoice, error) { return inv, nil }
}

func TestAltZapReceiptRejectsAbsentDescriptionHash(t *testing.T) {
	receipt, _ := signedAltZapReceipt(t)
	stubAltZapInvoice(t, &nip57.Invoice{AmountMloki: 1000})

	err := ValidateAltZapReceipt(receipt)
	if err == nil {
		t.Fatal("AltZap accepted a receipt whose invoice carries no description hash")
	}
	if !errors.Is(err, nip57.ErrDescriptionHashMismatch) {
		t.Errorf("got %v, want nip57.ErrDescriptionHashMismatch", err)
	}
}

func TestAltZapReceiptRejectsMismatchedDescriptionHash(t *testing.T) {
	receipt, _ := signedAltZapReceipt(t)
	stubAltZapInvoice(t, &nip57.Invoice{
		AmountMloki:     1000,
		DescriptionHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})

	err := ValidateAltZapReceipt(receipt)
	if err == nil {
		t.Fatal("AltZap accepted a receipt whose description hash does not bind the request")
	}
	if !errors.Is(err, nip57.ErrDescriptionHashMismatch) {
		t.Errorf("got %v, want nip57.ErrDescriptionHashMismatch", err)
	}
}

func TestAltZapReceiptAcceptsMatchingDescriptionHash(t *testing.T) {
	receipt, descHash := signedAltZapReceipt(t)
	stubAltZapInvoice(t, &nip57.Invoice{AmountMloki: 1000, DescriptionHash: descHash})

	if err := ValidateAltZapReceipt(receipt); err != nil {
		t.Fatalf("AltZap rejected a conforming receipt: %v", err)
	}
}

func TestAltZapDirectPaymentHashLockStillEnforced(t *testing.T) {
	recipient := "0000000000000000000000000000000000000000000000000000000000000001"
	ev := altZapRequestWithTags(t, KindAltZapDirectPayment, [][]string{
		{"amount", "1000"},
		{"bolt11", "lnfc-direct-payment"},
		{"chain", "flokicoin"},
		{"relays", "wss://relay.example.com"},
		{"P", recipient},
	})

	stubAltZapInvoice(t, &nip57.Invoice{AmountMloki: 1000, DescriptionHash: "wrong-hash"})

	err := ValidateAltZapRequest(ev, 0)
	if err == nil {
		t.Fatal("AltZap accepted a direct payment whose bolt11 hash lock does not match")
	}
	if !errors.Is(err, ErrHashLockMismatch) {
		t.Errorf("got %v, want ErrHashLockMismatch", err)
	}
}
