// Package nip04 implements NIP-04: Encrypted Direct Message, the legacy
// (pre-NIP-44) shared-secret AES-256-CBC encryption scheme for kind-4
// direct messages. Prefer nip44 for new applications; NIP-04 remains in
// use only for backward compatibility with older clients.
package nip04

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
)

func Encrypt(data, senderPrivKey, receiverPubKey string) (string, error) {

	sharedSecret, err := deriveSharedSecret(senderPrivKey, receiverPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to derive shared secret: %w", err)
	}

	iv, ciphertext, err := encryptAESCBC(sharedSecret, []byte(data))
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return fmt.Sprintf("%s?iv=%s", base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(iv)), nil
}

func Decrypt(data, senderPubKeyHex, receiverPrivKeyHex string) (string, error) {

	tabs := strings.Split(data, "?iv=")
	if len(tabs) != 2 {
		return "", fmt.Errorf("invalid data format: missing or incorrect IV")
	}

	iv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tabs[1]))
	if err != nil {
		return "", fmt.Errorf("invalid IV: decoding failed: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tabs[0]))
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext: %w", err)
	}

	sharedSecret, err := deriveSharedSecret(receiverPrivKeyHex, senderPubKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to derive shared secret: %w", err)
	}

	plaintext, err := decryptAESCBC(iv, sharedSecret, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

func deriveSharedSecret(privKeyHex, pubKeyHex string) ([]byte, error) {

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}

	return btcec.GenerateSharedSecret(privKey, pubKey), nil // X shared point
}

func encryptAESCBC(key, plaintext []byte) ([]byte, []byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	plaintext = pkcs7Pad(plaintext, block.BlockSize())

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return iv, ciphertext, nil
}

func decryptAESCBC(iv, key, ciphertext []byte) ([]byte, error) {

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv: invalid length %d", len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = pkcs7Unpad(plaintext, block.BlockSize())
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("invalid padding size")
	}

	padding := int(data[length-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding: %d", padding)
	}

	for i := range padding {
		if data[length-1-i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:length-padding], nil
}
