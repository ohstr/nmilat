package utils

import (
	"testing"
)

// ValidateLNURL has exactly two production callers — nip57.ParseZapRequest
// and nipAZ.ParseAltZapRequest — and they enforce different policies on top
// of it. AltZap requires the bech32 form; NIP-57 treats the lnurl tag as
// optional and its form as a SHOULD, and relaxes it at relay ingest inside
// nip57 rather than here. Loosening this function would silently relax
// AltZap too, so it stays strict: these cases pin that contract.

func TestValidateLNURLRejectsLightningAddress(t *testing.T) {
	// LUD-16 identifiers are what real NIP-57 clients put in the lnurl tag.
	// They are not bech32 and must keep failing here.
	for _, addr := range []string{
		"alice@example.com",
		"bob@zapf.network",
		"a1b2c3@relay.example.org",
	} {
		if err := ValidateLNURL(addr); err == nil {
			t.Errorf("ValidateLNURL(%q) = nil, want an error", addr)
		}
	}
}

func TestValidateLNURLRejectsMalformedInput(t *testing.T) {
	for _, name := range []string{"", " ", "lnurl", "lnurl1", "not-bech32-at-all"} {
		if err := ValidateLNURL(name); err == nil {
			t.Errorf("ValidateLNURL(%q) = nil, want an error", name)
		}
	}
}

// The encode/validate pair must round-trip, including for the URL shape
// GetLud16URL produces — that is the exact chain nip57.RequestZapInvoice
// uses to turn a LUD-16 identifier into a conforming lnurl tag.
func TestEncodeLNURLRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"https://service.example.com/api?q=abc",
		"http://v2onion.onion/api?q=abc",
		GetLud16URL("alice@example.com"),
	} {
		encoded, err := EncodeLNURL(raw)
		if err != nil {
			t.Fatalf("EncodeLNURL(%q): %v", raw, err)
		}
		if err := ValidateLNURL(encoded); err != nil {
			t.Errorf("ValidateLNURL(EncodeLNURL(%q)) = %v, want nil", raw, err)
		}
	}
}
