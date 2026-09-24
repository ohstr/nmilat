package nip57

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// Relay ingest must accept what other relays' clients actually publish,
// while a caller settling or accounting for its own zap keeps the strict
// reading. Every case below asserts both outcomes, so a relaxation can't be
// tested in only one direction.

// bech32Lnurl is a real bech32-decodable lnurl — utils.ValidateLNURL
// requires this form, not a placeholder string.
const bech32Lnurl = "lnurl1dp68gurn8ghj7ar9wd6zucm0d5hkzurf9akxuatjdsyukzu5"

// lightningAddress is what real clients put in the lnurl tag instead of the
// bech32 form, and is the single largest cause of rejected receipts.
const lightningAddress = "alice@example.com"

func assertErr(t *testing.T, name string, got, want error) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: got %v, want nil", name, got)
	case want != nil && !errors.Is(got, want):
		t.Errorf("%s: got %v, want %v", name, got, want)
	}
}

// bothReceiptPaths runs the strict and relay-ingest receipt validators over
// the same event. A nil want means the path must accept it.
func bothReceiptPaths(t *testing.T, receipt *nip01.Event, wantStrict, wantRelay error) {
	t.Helper()
	assertErr(t, "ValidateZapReceipt", ValidateZapReceipt(receipt), wantStrict)
	assertErr(t, "ValidateZapReceiptForRelay", ValidateZapReceiptForRelay(receipt), wantRelay)
}

// bothRequestPaths does the same for a bare kind-9734 request.
func bothRequestPaths(t *testing.T, req *nip01.Event, wantStrict, wantRelay error) {
	t.Helper()
	assertErr(t, "ValidateZapRequest", ValidateZapRequest(req, 0), wantStrict)
	assertErr(t, "ValidateZapRequestForRelay", ValidateZapRequestForRelay(req), wantRelay)
}

// signReceiptWithTags builds and signs a 9735 receipt from an explicit tag
// set, for the cases that need a required tag removed or corrupted.
func signReceiptWithTags(t *testing.T, tags [][]string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{
		CreatedAt: uint64(time.Now().Unix()),
		Kind:      KindZapReceipt,
		Tags:      tags,
	}
	if err := ev.Sign(zapsTestPrivKey); err != nil {
		t.Fatalf("sign zap receipt: %v", err)
	}
	return ev
}

// conformingReceipt returns a receipt whose embedded request carries extra
// tags, with a stubbed invoice that matches it exactly.
func conformingReceipt(t *testing.T, extra ...[]string) *nip01.Event {
	t.Helper()
	receipt := signReceipt(t, signRequest(t, requestTags(extra...)))
	stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})
	return receipt
}

// --- the lnurl tag -------------------------------------------------------

func TestZapLNURLPolicy(t *testing.T) {
	tests := []struct {
		name       string
		tag        []string // nil omits the tag entirely
		wantStrict error
	}{
		{name: "bech32", tag: []string{"lnurl", bech32Lnurl}, wantStrict: nil},
		{name: "no lnurl tag", tag: nil, wantStrict: nil},
		{name: "tag with no value", tag: []string{"lnurl"}, wantStrict: nil},
		{name: "lightning address", tag: []string{"lnurl", lightningAddress}, wantStrict: ErrInvalidLNURL},
		{name: "wrong bech32 prefix", tag: []string{"lnurl", "npub1sn0wdenkukak0d93wbs853d79h5480dcxfhdaj"}, wantStrict: ErrInvalidLNURL},
		{name: "not bech32", tag: []string{"lnurl", "https://example.com/pay"}, wantStrict: ErrInvalidLNURL},
		{name: "empty value", tag: []string{"lnurl", ""}, wantStrict: ErrInvalidLNURL},
		{name: "garbage", tag: []string{"lnurl", "!!!not-an-lnurl!!!"}, wantStrict: ErrInvalidLNURL},
	}

	for _, tt := range tests {
		t.Run("receipt/"+tt.name, func(t *testing.T) {
			var extra [][]string
			if tt.tag != nil {
				extra = append(extra, tt.tag)
			}
			receipt := conformingReceipt(t, extra...)
			// On the receipt path the embedded request's failure is
			// wrapped, but errors.Is still reaches the cause.
			bothReceiptPaths(t, receipt, tt.wantStrict, nil)
		})

		t.Run("request/"+tt.name, func(t *testing.T) {
			var extra [][]string
			if tt.tag != nil {
				extra = append(extra, tt.tag)
			}
			bothRequestPaths(t, signRequest(t, requestTags(extra...)), tt.wantStrict, nil)
		})
	}
}

func TestZapLNURLRecordedVerbatimOnRelayPath(t *testing.T) {
	receipt := conformingReceipt(t, []string{"lnurl", lightningAddress})

	zr, err := parseZapReceipt(receipt, policyRelay)
	if err != nil {
		t.Fatalf("relay parse rejected the receipt: %v", err)
	}
	if zr.Request.Lnurl != lightningAddress {
		t.Errorf("Lnurl = %q, want the raw tag value %q", zr.Request.Lnurl, lightningAddress)
	}
}

// --- the description hash ------------------------------------------------

func TestZapDescriptionHashPolicy(t *testing.T) {
	const otherHash = "00000000000000000000000000000000000000000000000000000000000000ff"

	t.Run("matching", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, requestTags()))
		stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})
		bothReceiptPaths(t, receipt, nil, nil)
	})

	t.Run("mismatched", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, requestTags()))
		stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: otherHash})
		bothReceiptPaths(t, receipt, ErrDescriptionHashMismatch, nil)
	})

	t.Run("absent", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, requestTags()))
		stubInvoice(t, &Invoice{AmountMloki: 1000})
		bothReceiptPaths(t, receipt, ErrMissingDescriptionHash, nil)
	})
}

// --- SHOULD-level structural rules ---------------------------------------

func TestZapRelaysTagPolicy(t *testing.T) {
	noRelays := [][]string{{"p", validRecipient}, {"amount", "1000"}}

	t.Run("receipt", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, noRelays))
		stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})
		bothReceiptPaths(t, receipt, ErrMissingRelaysTag, nil)
	})

	t.Run("request", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, noRelays), ErrMissingRelaysTag, nil)
	})
}

// The recipient count stays strict on both paths: ValidateZapReceipt
// cross-checks the receipt's "p" tag against the embedded request's author,
// which needs an unambiguous recipient.
func TestZapRecipientTagCountStaysStrict(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, [][]string{
			{"relays", "wss://relay.example.com"},
			{"amount", "1000"},
		}), ErrRecipientTagCount, ErrRecipientTagCount)
	})

	t.Run("two", func(t *testing.T) {
		other := "0000000000000000000000000000000000000000000000000000000000000002"
		bothRequestPaths(t, signRequest(t, requestTags([]string{"p", other})), ErrRecipientTagCount, ErrRecipientTagCount)
	})
}

func TestZapOptionalTagsAbsent(t *testing.T) {
	// P, e, a, k and preimage are all optional and their absence must never
	// fail either path.
	bothReceiptPaths(t, conformingReceipt(t), nil, nil)
}

// --- MUST-level rules, which neither path may relax ----------------------

func TestZapMustLevelRejections(t *testing.T) {
	validDesc := func(t *testing.T) string {
		t.Helper()
		b, err := json.Marshal(signRequest(t, requestTags()))
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		return string(b)
	}

	t.Run("wrong kind", func(t *testing.T) {
		ev := signReceiptWithTags(t, [][]string{{"p", validRecipient}})
		ev.Kind = 1
		if err := ev.Sign(zapsTestPrivKey); err != nil {
			t.Fatalf("re-sign: %v", err)
		}
		bothReceiptPaths(t, ev, ErrWrongKind, ErrWrongKind)
	})

	t.Run("tampered receipt signature", func(t *testing.T) {
		receipt := conformingReceipt(t)
		receipt.Content = "tampered after signing"
		bothReceiptPaths(t, receipt, ErrInvalidSignature, ErrInvalidSignature)
	})

	t.Run("missing p tag", func(t *testing.T) {
		bothReceiptPaths(t, signReceiptWithTags(t, [][]string{
			{"bolt11", "lnbc10n1pjqxyz"},
			{"description", validDesc(t)},
		}), ErrMissingRecipientTag, ErrMissingRecipientTag)
	})

	t.Run("missing bolt11 tag", func(t *testing.T) {
		bothReceiptPaths(t, signReceiptWithTags(t, [][]string{
			{"p", validRecipient},
			{"description", validDesc(t)},
		}), ErrMissingBolt11Tag, ErrMissingBolt11Tag)
	})

	t.Run("missing description tag", func(t *testing.T) {
		bothReceiptPaths(t, signReceiptWithTags(t, [][]string{
			{"p", validRecipient},
			{"bolt11", "lnbc10n1pjqxyz"},
		}), ErrMissingDescriptionTag, ErrMissingDescriptionTag)
	})

	t.Run("description is not json", func(t *testing.T) {
		bothReceiptPaths(t, signReceiptWithTags(t, [][]string{
			{"p", validRecipient},
			{"bolt11", "lnbc10n1pjqxyz"},
			{"description", "not json at all"},
		}), ErrInvalidDescriptionJSON, ErrInvalidDescriptionJSON)
	})

	t.Run("tampered embedded request signature", func(t *testing.T) {
		req := signRequest(t, requestTags())
		req.Content = "tampered after signing"
		receipt := signReceipt(t, req)
		stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})
		bothReceiptPaths(t, receipt, ErrInvalidEmbeddedRequest, ErrInvalidEmbeddedRequest)
	})

	t.Run("undecodable bolt11", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, requestTags()))
		original := DecodeBolt11
		t.Cleanup(func() { DecodeBolt11 = original })
		DecodeBolt11 = func(string) (*Invoice, error) { return nil, errors.New("bad invoice") }
		bothReceiptPaths(t, receipt, ErrBolt11DecodeFailed, ErrBolt11DecodeFailed)
	})

	t.Run("amount mismatch", func(t *testing.T) {
		receipt := signReceipt(t, signRequest(t, requestTags()))
		stubInvoice(t, &Invoice{AmountMloki: 42, DescriptionHash: descriptionHashOf(t, receipt)})
		bothReceiptPaths(t, receipt, ErrAmountMismatch, ErrAmountMismatch)
	})

	t.Run("recipient mismatch", func(t *testing.T) {
		other := "0000000000000000000000000000000000000000000000000000000000000002"
		receipt := signReceiptWithTags(t, [][]string{
			{"p", other},
			{"bolt11", "lnbc10n1pjqxyz"},
			{"description", validDesc(t)},
		})
		stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})
		bothReceiptPaths(t, receipt, ErrRecipientMismatch, ErrRecipientMismatch)
	})

	t.Run("bad relay url scheme", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, [][]string{
			{"p", validRecipient},
			{"relays", "http://relay.example.com"},
		}), ErrInvalidRelayScheme, ErrInvalidRelayScheme)
	})

	t.Run("non-numeric amount", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, [][]string{
			{"p", validRecipient},
			{"relays", "wss://relay.example.com"},
			{"amount", "lots"},
		}), ErrInvalidAmount, ErrInvalidAmount)
	})

	t.Run("non-positive amount", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, [][]string{
			{"p", validRecipient},
			{"relays", "wss://relay.example.com"},
			{"amount", "0"},
		}), ErrInvalidAmountValue, ErrInvalidAmountValue)
	})

	t.Run("malformed p tag", func(t *testing.T) {
		bothRequestPaths(t, signRequest(t, [][]string{
			{"p", "not-hex"},
			{"relays", "wss://relay.example.com"},
		}), ErrInvalidRecipientTag, ErrInvalidRecipientTag)
	})
}

// --- kind 9734 specifics -------------------------------------------------

// The relay variant takes no expected amount and must never fail on the
// amount cross-check alone, while the strict one still enforces it.
func TestValidateZapRequestForRelayIgnoresExpectedAmount(t *testing.T) {
	req := signRequest(t, requestTags())

	if err := ValidateZapRequest(req, 1000); err != nil {
		t.Fatalf("strict validation rejected a matching amount: %v", err)
	}
	if err := ValidateZapRequest(req, 9999); !errors.Is(err, ErrAmountMismatch) {
		t.Errorf("strict validation: got %v, want ErrAmountMismatch", err)
	}
	if err := ValidateZapRequestForRelay(req); err != nil {
		t.Errorf("relay validation rejected the request: %v", err)
	}
}
