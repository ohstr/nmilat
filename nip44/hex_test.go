package nip44

import (
	"testing"

	"github.com/ohstr/nmilat/utils"
)

func TestEncryptHexRoundTrip(t *testing.T) {
	const (
		alicePriv = "0000000000000000000000000000000000000000000000000000000000000001"
		bobPriv   = "0000000000000000000000000000000000000000000000000000000000000002"
	)
	alicePub, err := utils.GetPublicKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := utils.GetPublicKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	payload, err := EncryptHex("hello bob", alicePriv, bobPub)
	if err != nil {
		t.Fatalf("EncryptHex: %v", err)
	}
	got, err := DecryptHex(payload, bobPriv, alicePub)
	if err != nil {
		t.Fatalf("DecryptHex: %v", err)
	}
	if got != "hello bob" {
		t.Fatalf("got %q", got)
	}

	// Both sides derive the same conversation key.
	k1, _ := ConversationKeyHex(alicePriv, bobPub)
	k2, _ := ConversationKeyHex(bobPriv, alicePub)
	if string(k1) != string(k2) {
		t.Fatal("conversation keys differ")
	}
}

func TestConversationKeyHexInvalidKeys(t *testing.T) {
	if _, err := ConversationKeyHex("zz", "00"); err == nil {
		t.Error("expected an error for a non-hex private key")
	}
	if _, err := ConversationKeyHex("0000000000000000000000000000000000000000000000000000000000000001", "abcd"); err == nil {
		t.Error("expected an error for a short public key")
	}
}
