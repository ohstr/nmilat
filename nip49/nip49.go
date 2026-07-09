// Package nip49 implements NIP-49: Private Key Encryption, the
// scrypt-derived, password-protected "ncryptsec" encoding for a private
// key.
package nip49

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	LogNDefault = 16 // N = 2^16 = 65536. NIP-49 suggests something secure.
	// Spec says: N=2^18 is recommended for high security, but defaults often 16 or 15 for reasonable time.
	// NIP-49 spec draft usually implies user chooses or standardizes.
	// We will implement Encode/Decode logic.
)

func Encrypt(privKeyHex, password string) (string, error) {
	privKey, err := hex.DecodeString(privKeyHex)
	if err != nil || len(privKey) != 32 {
		return "", fmt.Errorf("invalid private key")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Scrypt params: N=2^16, r=8, p=1
	// logN = 16
	logN := byte(LogNDefault)
	N := 1 << logN
	r := 8
	p := 1

	key, err := scrypt.Key([]byte(password), salt, N, r, p, 32)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 24) // XChaCha20 nonce
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, privKey, nil)

	// Format: Version (0x02) | LogN (1) | Salt (16) | Nonce (24) | Ciphertext (32+16)
	var data []byte
	data = append(data, 0x02)
	data = append(data, logN)
	data = append(data, salt...)
	data = append(data, nonce...)
	data = append(data, ciphertext...)

	// Bech32 Encode
	// 'ncryptsec' is the HRP for private keys?
	// NIP-49 uses 'ncryptsec'.
	// Need to convert 8bit to 5bit
	conv, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode("ncryptsec", conv)
}

func Decrypt(ncryptsec, password string) (string, error) {
	hrp, decoded, err := bech32.DecodeNoLimit(ncryptsec)
	if err != nil {
		return "", err
	}
	if hrp != "ncryptsec" {
		return "", fmt.Errorf("invalid hrp")
	}

	data, err := bech32.ConvertBits(decoded, 5, 8, false)
	if err != nil {
		return "", err
	}

	if len(data) < 1+1+16+24+16 { // Min length check
		return "", fmt.Errorf("data too short")
	}

	version := data[0]
	if version != 0x02 {
		return "", fmt.Errorf("unsupported version %d", version)
	}

	logN := data[1]
	salt := data[2:18]
	nonce := data[18:42]
	ciphertext := data[42:]

	N := 1 << logN
	r := 8
	p := 1

	key, err := scrypt.Key([]byte(password), salt, N, r, p, 32)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (bad password?)")
	}

	return hex.EncodeToString(plaintext), nil
}
