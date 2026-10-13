package nip44

import (
	"encoding/hex"
	"fmt"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
)

// ConversationKeyHex derives the NIP-44 conversation key between a hex
// private key and a hex Nostr public key (32-byte x-only, as in events).
func ConversationKeyHex(privKeyHex, pubKeyHex string) ([]byte, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)

	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	key, err := GenerateConversationKey(priv, pub)
	if err != nil {
		return nil, fmt.Errorf("derive conversation key: %w", err)
	}
	return key, nil
}

// EncryptHex encrypts plaintext from the holder of privKeyHex to pubKeyHex.
func EncryptHex(plaintext, privKeyHex, pubKeyHex string) (string, error) {
	key, err := ConversationKeyHex(privKeyHex, pubKeyHex)
	if err != nil {
		return "", err
	}
	return Encrypt(plaintext, key)
}

// DecryptHex decrypts a payload sent to the holder of privKeyHex by pubKeyHex.
func DecryptHex(payload, privKeyHex, pubKeyHex string) (string, error) {
	key, err := ConversationKeyHex(privKeyHex, pubKeyHex)
	if err != nil {
		return "", err
	}
	return Decrypt(payload, key)
}
