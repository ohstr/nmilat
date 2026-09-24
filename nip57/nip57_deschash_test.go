package nip57

import (
	"errors"
	"strings"
	"testing"
)

// "The invoice carries no description hash" and "the hash differs" are
// different conditions: the second suggests the receipt may not belong to
// this zap, the first says nothing either way. They must not share an error
// value.

func TestValidateZapReceiptMissingDescriptionHash(t *testing.T) {
	receipt := signReceipt(t, signRequest(t, requestTags()))
	stubInvoice(t, &Invoice{AmountMloki: 1000})

	err := ValidateZapReceipt(receipt)
	if err == nil {
		t.Fatal("accepted an invoice with no description hash")
	}
	if !errors.Is(err, ErrMissingDescriptionHash) {
		t.Errorf("got %v, want ErrMissingDescriptionHash", err)
	}
	if errors.Is(err, ErrDescriptionHashMismatch) {
		t.Error("an absent description hash was reported as a mismatch")
	}
}

func TestValidateZapReceiptMismatchedDescriptionHash(t *testing.T) {
	receipt := signReceipt(t, signRequest(t, requestTags()))
	const invoiceHash = "00000000000000000000000000000000000000000000000000000000000000ff"
	stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: invoiceHash})

	err := ValidateZapReceipt(receipt)
	if err == nil {
		t.Fatal("accepted an invoice whose description hash does not bind the request")
	}
	if !errors.Is(err, ErrDescriptionHashMismatch) {
		t.Fatalf("got %v, want ErrDescriptionHashMismatch", err)
	}
	if errors.Is(err, ErrMissingDescriptionHash) {
		t.Error("a mismatched description hash was reported as missing")
	}

	// have= is what the invoice carries, want= is what the description
	// hashes to. Reporting them the other way round sends a reader looking
	// at the wrong side of the comparison.
	want := descriptionHashOf(t, receipt)
	if !strings.Contains(err.Error(), "have="+invoiceHash) {
		t.Errorf("error should report the invoice's hash as have=, got %q", err)
	}
	if !strings.Contains(err.Error(), "want="+want) {
		t.Errorf("error should report the computed hash as want=, got %q", err)
	}
}

func TestValidateZapReceiptMatchingDescriptionHash(t *testing.T) {
	receipt := signReceipt(t, signRequest(t, requestTags()))
	stubInvoice(t, &Invoice{AmountMloki: 1000, DescriptionHash: descriptionHashOf(t, receipt)})

	if err := ValidateZapReceipt(receipt); err != nil {
		t.Fatalf("rejected a conforming receipt: %v", err)
	}
}
