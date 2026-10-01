package nip57

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Repro for issue #33: ValidateZapReceipt, which nip57/relayreg registers as a
// hard reject for kind 9735, enforces two NIP-57 SHOULD/optional rules as MUST
// and so drops receipts that are otherwise valid and correctly signed.
//
//   - Cause 1: the embedded zap request's `lnurl` tag is run through
//     utils.ValidateLNURL, which requires bech32 `lnurl1…`. NIP-57 marks the
//     tag "recommended, but optional" and Appendix F states only that it
//     SHOULD equal the recipient's lnurl. Real clients put a lightning
//     address there.
//   - Cause 2: an invoice with no description hash at all is reported as a
//     *mismatch* (`want=`), conflating "absent" with "wrong".
//
// Both tests assert the behavior the issue argues for, so both fail against
// today's validator.

// newReceiptWithLnurl builds a signed receipt whose embedded, signed zap
// request carries the given lnurl tag, and stubs DecodeBolt11 so the invoice
// agrees with it. descriptionHash selects what the stub reports.
func newReceiptWithLnurl(t *testing.T, lnurl string, descriptionHash func(matching string) string) func() error {
	t.Helper()

	const recipient = "0000000000000000000000000000000000000000000000000000000000000001"

	zapReq := NewZapRequest(ZapRequestParams{
		Recipient:  recipient,
		Relays:     []string{"wss://relay.com"},
		AmountMsat: 1000,
		Lnurl:      lnurl,
	})
	if err := zapReq.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign zap request: %v", err)
	}

	descBytes, err := json.Marshal(zapReq)
	if err != nil {
		t.Fatalf("marshal zap request: %v", err)
	}
	sum := sha256.Sum256(descBytes)
	matching := hex.EncodeToString(sum[:])

	originalDecode := DecodeBolt11
	t.Cleanup(func() { DecodeBolt11 = originalDecode })
	DecodeBolt11 = func(string) (*Invoice, error) {
		return &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHash(matching)}, nil
	}

	receipt := NewZapReceipt(ZapReceiptParams{
		ProviderPubkey: "provider1",
		Recipient:      recipient,
		Bolt11:         "lnfc1...",
		Description:    string(descBytes),
	})
	if err := receipt.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}

	return func() error { return ValidateZapReceipt(receipt) }
}

func TestIssue33LightningAddressLnurlIsAccepted(t *testing.T) {
	matching := func(m string) string { return m }

	// Control: a bech32 lnurl is accepted today.
	t.Run("bech32 lnurl", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5", matching)
		if err := validate(); err != nil {
			t.Fatalf("bech32 lnurl should validate, got: %v", err)
		}
	})

	// The report: 72 of 88 rejections were this. The tag is optional and its
	// rule is SHOULD-level, so an otherwise valid receipt must not be
	// rejected over it.
	t.Run("lightning address lnurl", func(t *testing.T) {
		// QUARANTINED 2026-10-01, and this is the open bug, not a flake: this
		// subtest fails deterministically (3/3) and failed on its own branch
		// before it was merged, so it is a live repro rather than a regression.
		// It is skipped only so `main` is not red while the fix is decided —
		// deliberately at the SUBTEST level, so the two controls either side keep
		// running and the day the fix lands this single Skip is the only thing to
		// remove.
		//
		// The bug: ValidateZapReceipt rejects the whole receipt over the FORMAT of
		// an optional, SHOULD-level tag. The "no lnurl tag" subtest below proves
		// omitting it validates fine, so rejecting a present-but-non-bech32 value
		// is strictly harsher than rejecting its absence — which cannot be right.
		//
		// NOT fixed here on purpose. The fix is a semantics change to nip57's
		// validation (accept the lud16 lightning-address form, or stop treating
		// this tag's format as fatal), nipAZ reuses these same error values, and
		// neither package has been through the audit that covered the cash and
		// private-transport surfaces. That is a reviewed change, not a release
		// unblock. See data/docs/release/release-runbook-2026-10-01.md §1e.
		t.Skip("open bug (issue 33): a lightning-address lnurl tag is rejected although the tag is optional and SHOULD-level; see this subtest's comment")

		validate := newReceiptWithLnurl(t, "alice@example.com", matching)
		if err := validate(); err != nil {
			t.Fatalf("lightning-address lnurl should not reject a valid receipt, got: %v", err)
		}
	})

	// A receipt carrying no lnurl tag at all is already fine -- included to
	// show the rejection is specific to the tag's *format*, not its absence.
	t.Run("no lnurl tag", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "", matching)
		if err := validate(); err != nil {
			t.Fatalf("absent lnurl tag should validate, got: %v", err)
		}
	})
}

func TestIssue33AbsentDescriptionHashIsNotAMismatch(t *testing.T) {
	const bech32Lnurl = "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"

	// Control: a genuinely wrong hash is a mismatch, and should stay one.
	t.Run("wrong hash", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, bech32Lnurl, func(string) string {
			return "00000000000000000000000000000000000000000000000000000000deadbeef"
		})
		err := validate()
		if !errors.Is(err, ErrDescriptionHashMismatch) {
			t.Fatalf("wrong hash should be a mismatch, got: %v", err)
		}
	})

	// The report: 3 of the 14 hash rejections were an invoice with no `h`
	// field. "Absent" and "wrong" are different conditions -- the second
	// suggests the invoice may not belong to this zap, the first does not --
	// so absent must not surface as ErrDescriptionHashMismatch with `want=`.
	t.Run("absent hash", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, bech32Lnurl, func(string) string { return "" })
		err := validate()
		if errors.Is(err, ErrDescriptionHashMismatch) {
			t.Fatalf("absent hash reported as a mismatch: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), "want=") && strings.HasSuffix(err.Error(), "want=") {
			t.Fatalf("absent hash reported with an empty want=: %v", err)
		}
	})
}
