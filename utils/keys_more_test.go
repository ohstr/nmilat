package utils

import "testing"

func TestGetPublicKey(t *testing.T) {
	pubkey, err := GetPublicKey("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pubkey) != 64 {
		t.Errorf("expected a 64-char hex pubkey, got length %d: %s", len(pubkey), pubkey)
	}

	if _, err := GetPublicKey("not-hex"); err == nil {
		t.Error("expected error for non-hex private key")
	}
	if _, err := GetPublicKey("abcd"); err == nil {
		t.Error("expected error for a too-short private key")
	}
}
