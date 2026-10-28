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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

	// MinPlaintextSize and MaxPlaintextSize bound a plaintext's length in bytes.
	MinPlaintextSize = 1
	MaxPlaintextSize = 1<<32 - 1

	// extendedPrefixThreshold is the first length written with the 6-byte
	// prefix (two zero bytes, then a u32) instead of a u16.
	extendedPrefixThreshold = 65536
)

var (
	ErrInvalidVersion  = errors.New("unknown encryption version")
	ErrMessageTooShort = errors.New("message too short")
	ErrInvalidPadding  = errors.New("invalid padding")
	ErrInvalidMAC      = errors.New("invalid MAC")
	// ErrInvalidPlaintextLength is a plaintext shorter than MinPlaintextSize
	// or longer than MaxPlaintextSize: no peer could open it.
	ErrInvalidPlaintextLength = errors.New("invalid plaintext length")
	// ErrInvalidKeys is message keys of the wrong length.
	ErrInvalidKeys = errors.New("invalid message keys")
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
	if err := checkPlaintextLen(len(plaintext)); err != nil {
		return "", err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return encryptWithNonce(plaintext, conversationKey, nonce)
}

// checkPlaintextLen refuses a length NIP-44 cannot carry.
func checkPlaintextLen(n int) error {
	if n < MinPlaintextSize || n > MaxPlaintextSize {
		return fmt.Errorf("%w: %d bytes", ErrInvalidPlaintextLength, n)
	}
	return nil
}

func encryptWithNonce(plaintext string, conversationKey, nonce []byte) (string, error) {
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
	p, err := parsePayload(payload)
	if err != nil {
		return "", err
	}
	keys, err := p.keys(conversationKey)
	if err != nil {
		return "", err
	}
	return p.open(keys)
}

// Keys are one payload's message keys: they open that payload and no other,
// and reveal nothing about the conversation key they came from.
type Keys struct {
	ChaChaKey   []byte // 32 bytes
	ChaChaNonce []byte // 12 bytes
	HMACKey     []byte // 32 bytes
}

type keysJSON struct {
	ChaChaKey   string `json:"chacha_key"`
	ChaChaNonce string `json:"chacha_nonce"`
	HMACKey     string `json:"hmac_key"`
}

// MarshalJSON writes {"chacha_key", "chacha_nonce", "hmac_key"} as hex.
func (k Keys) MarshalJSON() ([]byte, error) {
	return json.Marshal(keysJSON{hex.EncodeToString(k.ChaChaKey), hex.EncodeToString(k.ChaChaNonce), hex.EncodeToString(k.HMACKey)})
}

// UnmarshalJSON reads MarshalJSON's form, checking each key's length.
func (k *Keys) UnmarshalJSON(b []byte) error {
	var j keysJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	var out Keys
	for _, f := range []struct {
		s   string
		n   int
		dst *[]byte
	}{{j.ChaChaKey, chacha20.KeySize, &out.ChaChaKey}, {j.ChaChaNonce, chacha20.NonceSize, &out.ChaChaNonce}, {j.HMACKey, sha256.Size, &out.HMACKey}} {
		v, err := hex.DecodeString(f.s)
		if err != nil || len(v) != f.n {
			return ErrInvalidKeys
		}
		*f.dst = v
	}
	*k = out
	return nil
}

// MessageKeys returns the keys that open payload, after checking its version,
// length and MAC under conversationKey.
func MessageKeys(conversationKey []byte, payload string) (Keys, error) {
	p, err := parsePayload(payload)
	if err != nil {
		return Keys{}, err
	}
	return p.keys(conversationKey)
}

// OpenWithKeys checks payload's MAC with keys.HMACKey and decrypts it, without
// the conversation key.
func OpenWithKeys(keys Keys, payload string) (string, error) {
	if len(keys.ChaChaKey) != chacha20.KeySize || len(keys.ChaChaNonce) != chacha20.NonceSize || len(keys.HMACKey) != sha256.Size {
		return "", ErrInvalidKeys
	}
	p, err := parsePayload(payload)
	if err != nil {
		return "", err
	}
	if !hmac.Equal(hmacAad(keys.HMACKey, p.ciphertext, p.nonce), p.mac) {
		return "", ErrInvalidMAC
	}
	return p.open(keys)
}

// payload is a decoded NIP-44 v2 payload: version | nonce | ciphertext | mac.
type payload struct {
	nonce, ciphertext, mac []byte
}

func parsePayload(s string) (payload, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return payload{}, fmt.Errorf("base64 decode error: %w", err)
	}
	// Version(1) + Nonce(32) + smallest padded plaintext(32) + MAC(32).
	if len(data) < 97 {
		return payload{}, ErrMessageTooShort
	}
	if data[0] != Version {
		return payload{}, ErrInvalidVersion
	}
	return payload{nonce: data[1:33], ciphertext: data[33 : len(data)-32], mac: data[len(data)-32:]}, nil
}

// keys derives the payload's message keys and checks its MAC.
func (p payload) keys(conversationKey []byte) (Keys, error) {
	chachaKey, chachaNonce, hmacKey, err := getMessageKeys(conversationKey, p.nonce)
	if err != nil {
		return Keys{}, err
	}
	if !hmac.Equal(hmacAad(hmacKey, p.ciphertext, p.nonce), p.mac) {
		return Keys{}, ErrInvalidMAC
	}
	return Keys{ChaChaKey: chachaKey, ChaChaNonce: chachaNonce, HMACKey: hmacKey}, nil
}

// open decrypts and unpads; the MAC must already be checked.
func (p payload) open(keys Keys) (string, error) {
	padded := make([]byte, len(p.ciphertext))
	cipher, err := chacha20.NewUnauthenticatedCipher(keys.ChaChaKey, keys.ChaChaNonce)
	if err != nil {
		return "", err
	}
	cipher.XORKeyStream(padded, p.ciphertext)
	return unpad(padded)
}

func hmacAad(key, message, aad []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(aad)
	h.Write(message)
	return h.Sum(nil)
}

// pad frames plaintext with its length, a u16 below extendedPrefixThreshold
// and [0, 0] plus a u32 from it on, then zero padding. The length must have
// passed checkPlaintextLen.
func pad(plaintext string) []byte {
	unpaddedLen := len(plaintext)
	prefixLen := 2
	if unpaddedLen >= extendedPrefixThreshold {
		prefixLen = 6
	}
	result := make([]byte, prefixLen+calcPaddedLen(unpaddedLen))
	if prefixLen == 2 {
		binary.BigEndian.PutUint16(result, uint16(unpaddedLen))
	} else {
		binary.BigEndian.PutUint32(result[2:], uint32(unpaddedLen))
	}
	copy(result[prefixLen:], plaintext)
	return result
}

// unpad reverses pad. A u16 length of 0 signals the extended prefix, which
// must then carry a length of at least extendedPrefixThreshold.
func unpad(padded []byte) (string, error) {
	if len(padded) < 2 {
		return "", ErrInvalidPadding
	}
	unpaddedLen, prefixLen := int(binary.BigEndian.Uint16(padded)), 2
	if unpaddedLen == 0 {
		if len(padded) < 6 {
			return "", ErrInvalidPadding
		}
		unpaddedLen, prefixLen = int(binary.BigEndian.Uint32(padded[2:])), 6
		if unpaddedLen < extendedPrefixThreshold {
			return "", ErrInvalidPadding
		}
	}
	if len(padded) != prefixLen+calcPaddedLen(unpaddedLen) {
		return "", ErrInvalidPadding
	}
	return string(padded[prefixLen : prefixLen+unpaddedLen]), nil
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
