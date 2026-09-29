package transport

import (
	"strings"
	"testing"
)

// TestNormalizeNodeIdentity covers the shape mismatch that made the private
// transport undiscoverable by its own documented discovery path.
//
// A client is told to anchor trust in the identity recovered from a bill's mint
// signature. That recovery yields a 33-byte COMPRESSED pubkey; a Nostr event's
// author is the 32-byte x-only form. The announcement was therefore published
// under one spelling and looked up under another, and the lookup returned nothing
// — indistinguishable from a hub that does not offer the transport at all.
func TestNormalizeNodeIdentity(t *testing.T) {
	xonly := strings.Repeat("ab", 32)

	// A compressed key loses only its parity byte; parity is recovered from the
	// curve when verifying, so nothing is lost.
	for _, prefix := range []string{"02", "03"} {
		got, err := NormalizeNodeIdentity(prefix + xonly)
		if err != nil {
			t.Fatalf("NormalizeNodeIdentity(%s…) error = %v", prefix, err)
		}
		if got != xonly {
			t.Errorf("NormalizeNodeIdentity(%s…) = %s, want the x-only form %s", prefix, got, xonly)
		}
	}

	// Already x-only: unchanged, so a caller holding the right form is unaffected.
	if got, err := NormalizeNodeIdentity(xonly); err != nil || got != xonly {
		t.Errorf("NormalizeNodeIdentity(xonly) = (%s, %v), want it returned unchanged", got, err)
	}

	// Case-insensitive, since a recovered key may arrive uppercased.
	if got, err := NormalizeNodeIdentity(strings.ToUpper("02" + xonly)); err != nil || got != xonly {
		t.Errorf("NormalizeNodeIdentity(uppercase) = (%s, %v), want %s", got, err, xonly)
	}
}

func TestNormalizeNodeIdentity_Rejects(t *testing.T) {
	for _, tc := range []struct {
		in  string
		why string
	}{
		{in: "", why: "empty"},
		{in: "not-hex-at-all", why: "not hex"},
		{in: strings.Repeat("ab", 31), why: "too short"},
		{in: strings.Repeat("ab", 34), why: "too long"},
		// 33 bytes but not a compressed pubkey: silently stripping the first byte
		// would produce a plausible-looking identity that matches nothing, which is
		// the same silent failure this function exists to remove.
		{in: "04" + strings.Repeat("ab", 32), why: "33 bytes not beginning 02/03"},
	} {
		if got, err := NormalizeNodeIdentity(tc.in); err == nil {
			t.Errorf("NormalizeNodeIdentity(%q) = %q, want an error (%s)", tc.in, got, tc.why)
		}
	}
}
