// Package nip44 implements NIP-44: Encrypted Payloads (Versioned), the
// current ChaCha20+HMAC-SHA256 (encrypt-then-MAC) scheme (v2) for
// direct-message and other private event content, superseding the legacy
// AES-CBC scheme in nip04.
package nip44

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

const (
	Version = 2
)

var (
	ErrInvalidVersion  = errors.New("unknown encryption version")
	ErrMessageTooShort = errors.New("message too short")
	ErrInvalidPadding  = errors.New("invalid padding")
	ErrInvalidMAC      = errors.New("invalid MAC")
)

// GenerateConversationKey computes the conversation key using HKDF-SHA256-Extract
// derived from the secp256k1 shared secret X coordinate.
func GenerateConversationKey(privKey *btcec.PrivateKey, pubKey *btcec.PublicKey) ([]byte, error) {
	sharedSecret := btcec.GenerateSharedSecret(privKey, pubKey)

	salt := []byte("nip44-v2")
	// NIP-44 v2 uses ONLY the HKDF-Extract step for the conversation key.
	prk := hkdf.Extract(sha256.New, sharedSecret, salt)
	return prk, nil
}

// getMessageKeys derives chacha_key, chacha_nonce, and hmac_key from conversationKey and nonce.
func getMessageKeys(conversationKey, nonce []byte) (chachaKey, chachaNonce, hmacKey []byte, err error) {
	// HKDF-Expand(PRK=conversationKey, info=nonce, length=76)
	reader := hkdf.Expand(sha256.New, conversationKey, nonce)
	keys := make([]byte, 76)
	if _, err := io.ReadFull(reader, keys); err != nil {
		return nil, nil, nil, err
	}
	return keys[0:32], keys[32:44], keys[44:76], nil
}

// Encrypt encrypts plaintext using NIP-44 v2.
func Encrypt(plaintext string, conversationKey []byte) (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	chachaKey, chachaNonce, hmacKey, err := getMessageKeys(conversationKey, nonce)
	if err != nil {
		return "", err
	}

	padded := pad(plaintext)
	ciphertext := make([]byte, len(padded))
	cipher, err := chacha20.NewUnauthenticatedCipher(chachaKey, chachaNonce)
	if err != nil {
		return "", err
	}
	cipher.XORKeyStream(ciphertext, padded)

	mac := hmacAad(hmacKey, ciphertext, nonce)

	// Result: [Version (1)] [Nonce (32)] [Ciphertext (v)] [MAC (32)]
	result := make([]byte, 1+32+len(ciphertext)+32)
	result[0] = Version
	copy(result[1:33], nonce)
	copy(result[33:33+len(ciphertext)], ciphertext)
	copy(result[33+len(ciphertext):], mac)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt decrypts NIP-44 v2 payload.
func Decrypt(payload string, conversationKey []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %w", err)
	}

	// Min length: Version(1) + Nonce(32) + PaddedData(min 32 + length prefix 2) + MAC(32)
	// But let's be more general: min is 1 + 32 + 2 + 32 = 67?
	// Spec says calcPaddedLen(1) = 32. So 1 + 32 + 32 + 32 = 97.
	// nostr-tools checks if len < 99 (includes some overhead or larger min padding?)
	if len(data) < 97 {
		return "", ErrMessageTooShort
	}

	if data[0] != Version {
		return "", ErrInvalidVersion
	}

	nonce := data[1:33]
	ciphertext := data[33 : len(data)-32]
	mac := data[len(data)-32:]

	chachaKey, chachaNonce, hmacKey, err := getMessageKeys(conversationKey, nonce)
	if err != nil {
		return "", err
	}

	// Verify MAC
	calculatedMac := hmacAad(hmacKey, ciphertext, nonce)
	if !hmac.Equal(calculatedMac, mac) {
		return "", ErrInvalidMAC
	}

	// Decrypt
	padded := make([]byte, len(ciphertext))
	cipher, err := chacha20.NewUnauthenticatedCipher(chachaKey, chachaNonce)
	if err != nil {
		return "", err
	}
	cipher.XORKeyStream(padded, ciphertext)

	return unpad(padded)
}

func hmacAad(key, message, aad []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(aad)
	h.Write(message)
	return h.Sum(nil)
}

func pad(plaintext string) []byte {
	unpadded := []byte(plaintext)
	unpaddedLen := len(unpadded)
	prefix := make([]byte, 2)
	prefix[0] = byte(unpaddedLen >> 8)
	prefix[1] = byte(unpaddedLen)

	paddedLen := calcPaddedLen(unpaddedLen)
	result := make([]byte, 2+paddedLen)
	copy(result[0:2], prefix)
	copy(result[2:2+unpaddedLen], unpadded)
	// Padding bytes are 0 in nostr-tools (based on code I saw, subarray suffix left empty)
	// Spec says "padded with random data" is RECOMMENDED, but zeroes are simpler and also valid if decrypted correctly.
	// nostr-tools uses `new Uint8Array(...)` which is zeroes.
	return result
}

func unpad(padded []byte) (string, error) {
	if len(padded) < 2 {
		return "", ErrInvalidPadding
	}
	unpaddedLen := int(padded[0])<<8 | int(padded[1])
	if unpaddedLen < 1 || unpaddedLen > 65535 {
		return "", ErrInvalidPadding
	}
	if len(padded) != 2+calcPaddedLen(unpaddedLen) {
		return "", ErrInvalidPadding
	}
	if unpaddedLen > len(padded)-2 {
		return "", ErrInvalidPadding
	}
	return string(padded[2 : 2+unpaddedLen]), nil
}

func calcPaddedLen(l int) int {
	if l <= 32 {
		return 32
	}
	// Logic from nostr-tools:
	// const nextPower = 1 << Math.floor(Math.log2(len - 1)) + 1;
	// const chunk = nextPower <= 256 ? 32 : nextPower / 8;
	// return chunk * (Math.floor((len - 1) / chunk) + 1);

	nextPower := int(math.Pow(2, math.Floor(math.Log2(float64(l-1)))+1))
	var chunk int
	if nextPower <= 256 {
		chunk = 32
	} else {
		chunk = nextPower / 8
	}

	return chunk * ((l-1)/chunk + 1)
}
