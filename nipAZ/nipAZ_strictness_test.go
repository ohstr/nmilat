package nipAZ

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/utils"
)

// AltZap is deliberately stricter than NIP-57: the lnurl tag is required on
// 9520/9523 and must be bech32, and a description hash that doesn't bind the
// embedded request must reject. nip57 relaxes both for relay ingest, and
// nipAZ shares nip57's error values and utils.ValidateLNURL with it, so
// these tests pin the AltZap side against that relaxation leaking across.
//
// nip57.DecodeBolt11 is a package-level var these tests swap, so nothing in
// this file may call t.Parallel().

const altZapLightningAddress = "alice@example.com"

// testPreimage and testPaymentHash are a real hash-lock pair for receipt
// fixtures: SHA256(hex-decoded testPreimage) == testPaymentHash.
const testPreimage = "1111111111111111111111111111111111111111111111111111111111111111"

var testPaymentHash = func() string {
	b, _ := hex.DecodeString(testPreimage)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}()

func TestAltZapRequestSenderTagRules(t *testing.T) {
	pTag := []string{"p", "0000000000000000000000000000000000000000000000000000000000000001"}
	base := [][]string{pTag, {"amount", "1000"}, {"chain", "flokicoin"}, {"lnurl", validTestLnurl}, {"relays", "wss://relay.example.com"}}
	sender := []string{"P", "0000000000000000000000000000000000000000000000000000000000000002"}

	if _, err := ParseAltZapRequest(altZapRequestWithTags(t, KindAltZapRequest, append(base, sender))); !errors.Is(err, ErrSenderTagNotAllowed) {
		t.Errorf("9520 with P: got %v, want ErrSenderTagNotAllowed", err)
	}
	if _, err := ParseAltZapRequest(altZapRequestWithTags(t, KindAltZapOnBehalfRequest, append(base, sender, sender))); !errors.Is(err, ErrSenderTagCount) {
		t.Errorf("9523 with two P: got %v, want ErrSenderTagCount", err)
	}
	if _, err := ParseAltZapRequest(altZapRequestWithTags(t, KindAltZapOnBehalfRequest, append(base, sender))); err != nil {
		t.Errorf("9523 with one P: unexpected error %v", err)
	}
}

func TestAltZapReceiptHashLockAndChain(t *testing.T) {
	receipt, descHash := signedAltZapReceipt(t)
	good := nip57.Invoice{Currency: "fc", PaymentHash: testPaymentHash, AmountMloki: 1000, DescriptionHash: descHash}

	wrongHash := good
	wrongHash.PaymentHash = "00" + testPaymentHash[2:]
	stubAltZapInvoice(t, &wrongHash)
	if err := legacyValidateReceipt(receipt); !errors.Is(err, ErrHashLockMismatch) {
		t.Errorf("wrong payment hash: got %v, want ErrHashLockMismatch", err)
	}

	bitcoinInvoice := good
	bitcoinInvoice.Currency = "bc"
	stubAltZapInvoice(t, &bitcoinInvoice)
	if err := legacyValidateReceipt(receipt); !errors.Is(err, ErrChainMismatch) {
		t.Errorf("bitcoin invoice on a flokicoin receipt: got %v, want ErrChainMismatch", err)
	}
}

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

// zapRequestTags returns the tags for a 9520/9523 request with the given
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

		err := legacyValidateRequest(ev, 0)
		if err == nil {
			t.Fatalf("kind %d: AltZap accepted a lightning address in the lnurl tag", kind)
		}
		if !errors.Is(err, nip57.ErrInvalidLNURL) {
			t.Errorf("kind %d: got %v, want nip57.ErrInvalidLNURL", kind, err)
		}
	}
}

func TestAltZapRequiresLnurlTag(t *testing.T) {
	for _, kind := range []int{KindAltZapRequest, KindAltZapOnBehalfRequest} {
		ev := altZapRequestWithTags(t, kind, zapRequestTags(kind, ""))

		err := legacyValidateRequest(ev, 0)
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

		if err := legacyValidateRequest(ev, 0); err != nil {
			t.Errorf("kind %d: AltZap rejected a valid bech32 lnurl: %v", kind, err)
		}
	}
}

// signedAltZapReceipt builds a 9521 receipt embedding a valid 9520 request,
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
			{"preimage", testPreimage},
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
	stubAltZapInvoice(t, &nip57.Invoice{Currency: "fc", PaymentHash: testPaymentHash, AmountMloki: 1000})

	err := legacyValidateReceipt(receipt)
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
		Currency:        "fc",
		PaymentHash:     testPaymentHash,
		AmountMloki:     1000,
		DescriptionHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})

	err := legacyValidateReceipt(receipt)
	if err == nil {
		t.Fatal("AltZap accepted a receipt whose description hash does not bind the request")
	}
	if !errors.Is(err, nip57.ErrDescriptionHashMismatch) {
		t.Errorf("got %v, want nip57.ErrDescriptionHashMismatch", err)
	}
}

func TestAltZapReceiptAcceptsMatchingDescriptionHash(t *testing.T) {
	receipt, descHash := signedAltZapReceipt(t)
	stubAltZapInvoice(t, &nip57.Invoice{Currency: "fc", PaymentHash: testPaymentHash, AmountMloki: 1000, DescriptionHash: descHash})

	if err := legacyValidateReceipt(receipt); err != nil {
		t.Fatalf("AltZap rejected a conforming receipt: %v", err)
	}
}

// legacyValidateRequest runs the server validator against a policy that
// accepts the fixtures' chain, endpoint and any ia; amount 0 takes the
// request's own amount as the callback's.
func legacyValidateRequest(ev *nip01.Event, amount int64) error {
	endpoint, err := utils.DecodeLNURL(validTestLnurl)
	if err != nil {
		return err
	}
	if amount == 0 {
		if zr, err := ParseAltZapRequest(ev); err == nil {
			amount = zr.Amount
		}
	}
	_, err = ValidateAltZapRequest(ev, ServerPolicy{
		Chains: []Chain{"flokicoin"}, OwnEndpoint: endpoint, TrustedIA: func(string) bool { return true },
	}, amount)
	return err
}

// legacyValidateReceipt runs the strict receipt validator with rule 10
// satisfied by the receipt's own signer.
func legacyValidateReceipt(ev *nip01.Event) error {
	_, err := ValidateAltZapReceipt(ev, ReceiptPolicy{NostrPubkeyFor: func(string) (string, error) { return ev.PubKey, nil }})
	return err
}
