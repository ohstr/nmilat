package nip59

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
)

func TestWrap(t *testing.T) {
	// Generate Sender keys
	senderPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate sender key: %v", err)
	}
	senderPrivKeyHex := hex.EncodeToString(senderPrivKey.Serialize())

	// Generate Recipient keys
	recipientPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	recipientPubKeyBytes := recipientPrivKey.PubKey().SerializeCompressed()
	recipientPubKeyHex := hex.EncodeToString(recipientPubKeyBytes[1:]) // Nostr uses x-only pubkeys (or compressed without prefix? actually mostly x-only now but btcec gives 33 bytes)

	// Wait, standard nostr uses schnorr public keys (32 bytes).
	// But library might be using 33 bytes. Let's check how other tests do it or how Wrap expects it.
	// Wrap uses: recipientPub, err := schnorr.ParsePubKey(recipientPubBytes)
	// schnorr.ParsePubKey expects 32 bytes (x-only).
	// So we should use recipientPrivKey.PubKey().SerializeCompressed()[1:]

	// Create a dummy payload event
	payload := nip01.NewEvent(1, "Hello Secret World")
	if err := payload.Sign(senderPrivKeyHex); err != nil {
		t.Fatalf("payload.Sign() error = %v", err)
	}

	// Perform Wrap
	wrapEvent, err := Wrap(payload, senderPrivKeyHex, recipientPubKeyHex)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Basic Validations
	if wrapEvent.Kind != KindGiftWrap {
		t.Errorf("Wrap() kind = %d, want %d", wrapEvent.Kind, KindGiftWrap)
	}

	if len(wrapEvent.Tags) != 1 || wrapEvent.Tags[0][0] != "p" || wrapEvent.Tags[0][1] != recipientPubKeyHex {
		t.Errorf("Wrap() tags malformed or missing recipient p tag")
	}

	// Verify we can decrypt it (Round trip simulation)

	// 1. Decrypt Outer Layer (Gift Wrap)
	// Need ephemeral public key from the specific event property?
	// NIP-59: "The receiver decrypts the content using the public key from the 'pubkey' field of the Gift Wrap event."

	ephemeralPubBytes, _ := hex.DecodeString(wrapEvent.PubKey)
	ephemeralPub, _ := schnorr.ParsePubKey(ephemeralPubBytes)

	// Recipient calculates conversation key: (RecipPriv + EphemPub)
	convKeyOuter, err := nip44.GenerateConversationKey(recipientPrivKey, ephemeralPub)
	if err != nil {
		t.Fatalf("failed to generate outer conversation key: %v", err)
	}

	decryptedSealJSON, err := nip44.Decrypt(wrapEvent.Content, convKeyOuter)
	if err != nil {
		t.Fatalf("failed to decrypt outer layer: %v", err)
	}

	var sealEvent nip01.Event
	if err := json.Unmarshal([]byte(decryptedSealJSON), &sealEvent); err != nil {
		t.Fatalf("failed to unmarshal seal event: %v", err)
	}

	if sealEvent.Kind != KindSeal {
		t.Errorf("Seal kind = %d, want %d", sealEvent.Kind, KindSeal)
	}

	// 2. Decrypt Inner Layer (Seal)
	// Sender is the pubkey of the seal
	senderPubBytes, _ := hex.DecodeString(sealEvent.PubKey)
	senderPub, _ := schnorr.ParsePubKey(senderPubBytes)

	// Recipient calculates conversation key: (RecipPriv + SenderPub)
	convKeyInner, err := nip44.GenerateConversationKey(recipientPrivKey, senderPub)
	if err != nil {
		t.Fatalf("failed to generate inner conversation key: %v", err)
	}

	decryptedPayloadJSON, err := nip44.Decrypt(sealEvent.Content, convKeyInner)
	if err != nil {
		t.Fatalf("failed to decrypt inner layer: %v", err)
	}

	var resultPayload nip01.Event
	if err := json.Unmarshal([]byte(decryptedPayloadJSON), &resultPayload); err != nil {
		t.Fatalf("failed to unmarshal payload event: %v", err)
	}

	if resultPayload.Content != "Hello Secret World" {
		t.Errorf("Decrypted payload content = %s, want 'Hello Secret World'", resultPayload.Content)
	}
}
