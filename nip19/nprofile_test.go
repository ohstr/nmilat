package nip19

import (
	"testing"
)

func TestDecodeNprofile(t *testing.T) {
	// Let's test providing a valid nprofile string.
	// This corresponds to a standard profile. Let's use it to check our TLV logic.
	// Encodes TLV(type=0, len=32, value=pubkeyHex) for pubkey 3bf0d7c7e6fa8d5c8a0f5a6b0c9d2e1f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d.
	const expectedPubkey = "3bf0d7c7e6fa8d5c8a0f5a6b0c9d2e1f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d"
	validNprofile := "nprofile1qqsrhuxhcln04r2u3g8456cvn5hp7j3m9swsa8u20dk96n3l9gdse8g2ee63l"
	hexStr, err := DecodeNprofile(validNprofile)
	if err != nil {
		t.Fatalf("Failed to decode valid nprofile: %v", err)
	}

	if len(hexStr) != 64 {
		t.Errorf("Expected 64 char hex pubkey, got length %d: %s", len(hexStr), hexStr)
	}

	if hexStr != expectedPubkey {
		t.Errorf("Expected pubkey %s, got %s", expectedPubkey, hexStr)
	}
}
