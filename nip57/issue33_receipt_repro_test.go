package nip57

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// Issue #33 — RESOLVED IN MAIN, and this file is now its regression test rather
// than its repro.
//
// The original report, and this file as it arrived on the worktree-integration
// branch, argued that ValidateZapReceipt "which nip57/relayreg registers as a hard
// reject for kind 9735" enforced two SHOULD/optional NIP-57 rules as MUST and so
// dropped otherwise-valid receipts — 72 of 88 rejections by its count. The two
// causes it named:
//
//   - the embedded zap request's `lnurl` tag is run through utils.ValidateLNURL,
//     which requires bech32 `lnurl1…`, while NIP-57 Appendix A calls the tag
//     "recommended, but optional" and Appendix F states only that it SHOULD equal
//     the recipient's lnurl. Real clients put a LUD-16 lightning address there.
//   - an invoice with no description hash at all was reported as a *mismatch*,
//     conflating "absent" with "wrong".
//
// **That premise no longer holds.** relayreg.go registers
// ValidateZapReceiptForRelay, not ValidateZapReceipt — checked, not assumed — and
// that validator tolerates exactly these two deviations by design, as its own doc
// comment spells out. So the fix landed, but in a different shape than the repro
// anticipated: rather than loosening the strict validator, main grew a second,
// relay-tolerant entry point and pointed relay ingest at it. policyStrict stays
// strict on purpose, for "callers building or settling their own zaps", where you
// control the tag you emit.
//
// Which means the repro as written asserted the wrong thing about the wrong
// function, and failed for that reason rather than because a bug was present —
// deterministically, 3/3, including on its own branch. Rewritten here to assert
// the design that actually shipped, in both directions, because the asymmetry IS
// the fix and nothing else pinned it:
//
//   - the relay path MUST tolerate a LUD-16 lnurl and an absent description hash;
//   - the strict path MUST still reject the former, or "strict" means nothing.
//
// newReceiptWithLnurl builds a signed receipt whose embedded, signed zap
// request carries the given lnurl tag, and stubs DecodeBolt11 so the invoice
// agrees with it. descriptionHash selects what the stub reports.
//
// Returns a func taking the validator to apply, because which validator is used
// is the whole point of issue #33: the same receipt is meant to be accepted by
// the relay path and rejected by the strict one.
func newReceiptWithLnurl(t *testing.T, lnurl string, descriptionHash func(matching string) string) func(validate func(*nip01.Event) error) error {
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

	return func(validate func(*nip01.Event) error) error { return validate(receipt) }
}

func TestIssue33LightningAddressLnurlIsAccepted(t *testing.T) {
	matching := func(m string) string { return m }

	// Control: a bech32 lnurl is accepted on both paths.
	t.Run("bech32 lnurl", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5", matching)
		if err := validate(ValidateZapReceipt); err != nil {
			t.Fatalf("bech32 lnurl should validate strictly, got: %v", err)
		}
		if err := validate(ValidateZapReceiptForRelay); err != nil {
			t.Fatalf("bech32 lnurl should validate for relay ingest, got: %v", err)
		}
	})

	// The issue's own case. A relay stores receipts settled by someone else, and a
	// receipt is the record that a payment happened, so dropping one at ingest over
	// the FORMAT of an optional tag silently loses that record. This is the
	// assertion that would have failed before relay ingest moved off the strict
	// validator.
	t.Run("lightning address lnurl is tolerated for relay ingest", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "alice@example.com", matching)
		if err := validate(ValidateZapReceiptForRelay); err != nil {
			t.Fatalf("a LUD-16 lightning address is what real clients put in the lnurl tag, and "+
				"NIP-57 makes the tag optional and its matching a SHOULD, so relay ingest must "+
				"not drop the receipt over it; got: %v", err)
		}
	})

	// And the other half of the design, which nothing else pins: strict stays
	// strict. policyStrict is for callers building or settling their own zaps,
	// where the tag is yours to emit correctly — if this ever starts passing, the
	// two policies have collapsed into one and the distinction relayreg relies on
	// is gone.
	t.Run("lightning address lnurl is still rejected strictly", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "alice@example.com", matching)
		if err := validate(ValidateZapReceipt); !errors.Is(err, ErrInvalidLNURL) {
			t.Fatalf("the strict validator must still require the bech32 form, got: %v", err)
		}
	})

	// A receipt carrying no lnurl tag at all is fine on either path -- included to
	// show the strict rejection above is specific to the tag's *format*, not its
	// presence.
	t.Run("no lnurl tag", func(t *testing.T) {
		validate := newReceiptWithLnurl(t, "", matching)
		if err := validate(ValidateZapReceipt); err != nil {
			t.Fatalf("absent lnurl tag should validate strictly, got: %v", err)
		}
		if err := validate(ValidateZapReceiptForRelay); err != nil {
			t.Fatalf("absent lnurl tag should validate for relay ingest, got: %v", err)
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
		// Strict deliberately: requireDescriptionHash is only set under
		// policyStrict, so running this through the relay validator would make
		// it vacuous — it tolerates the hash entirely.
		err := validate(ValidateZapReceipt)
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
		err := validate(ValidateZapReceipt)
		if errors.Is(err, ErrDescriptionHashMismatch) {
			t.Fatalf("absent hash reported as a mismatch: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), "want=") && strings.HasSuffix(err.Error(), "want=") {
			t.Fatalf("absent hash reported with an empty want=: %v", err)
		}
	})
}
