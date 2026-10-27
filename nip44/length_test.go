package nip44

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The 65535-byte case of NIP-44's length-prefix vectors: plaintext is 'a'
// repeated, with the fixed conversation key and nonce. Longer plaintexts are
// refused (MaxPlaintextSize, as the upstream vector file's
// invalid.encrypt_msg_lengths requires); the 65536 and 65537 rows, which use
// an extended prefix, are therefore not produced here.
func TestExtendedLengthPrefixVectors(t *testing.T) {
	key, _ := hex.DecodeString("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d")
	nonce, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	for _, v := range []struct {
		n                        int
		plaintextSHA, payloadSHA string
	}{
		{65535, "6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42", "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"},
	} {
		plaintext := strings.Repeat("a", v.n)
		if got := sha256Hex(plaintext); got != v.plaintextSHA {
			t.Fatalf("%d: plaintext sha256 = %s, want %s", v.n, got, v.plaintextSHA)
		}
		payload, err := encryptWithNonce(plaintext, key, nonce)
		if err != nil {
			t.Fatalf("%d: encrypt: %v", v.n, err)
		}
		if got := sha256Hex(payload); got != v.payloadSHA {
			t.Errorf("%d: payload sha256 = %s, want %s", v.n, got, v.payloadSHA)
		}
		out, err := Decrypt(payload, key)
		if err != nil || out != plaintext {
			t.Errorf("%d: decrypt = %d bytes, %v; want the plaintext back", v.n, len(out), err)
		}
	}
}

func TestEncrypt_RoundTripsAcrossThePrefixBoundary(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	for _, n := range []int{65536, 70000} {
		if _, err := Encrypt(strings.Repeat("b", n), key); !errors.Is(err, ErrInvalidPlaintextLength) {
			t.Errorf("%d: Encrypt = %v, want ErrInvalidPlaintextLength", n, err)
		}
	}
	for _, n := range []int{1, 65535} {
		plaintext := strings.Repeat("b", n)
		payload, err := Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("%d: Encrypt: %v", n, err)
		}
		if out, err := Decrypt(payload, key); err != nil || out != plaintext {
			t.Errorf("%d: Decrypt = %d bytes, %v", n, len(out), err)
		}
	}
}

func TestEncrypt_RefusesAnEmptyPlaintext(t *testing.T) {
	if _, err := Encrypt("", make([]byte, 32)); !errors.Is(err, ErrInvalidPlaintextLength) {
		t.Errorf("Encrypt(\"\") error = %v, want ErrInvalidPlaintextLength", err)
	}
}

func TestCheckPlaintextLen(t *testing.T) {
	for n, ok := range map[int]bool{0: false, 1: true, 65535: true, 65536: false, 100000: false} {
		if err := checkPlaintextLen(n); (err == nil) != ok {
			t.Errorf("checkPlaintextLen(%d) = %v, want ok=%v", n, err, ok)
		}
	}
}

func TestPad_PrefixForm(t *testing.T) {
	if p := pad(strings.Repeat("a", 65535)); binary.BigEndian.Uint16(p) != 65535 || len(p) != 2+65536 {
		t.Errorf("65535: prefix %x, len %d; want a u16 and 2+65536 bytes", p[:2], len(p))
	}
	if _, err := Encrypt(strings.Repeat("a", 65536), make([]byte, 32)); !errors.Is(err, ErrInvalidPlaintextLength) {
		t.Errorf("65536 bytes: %v, want ErrInvalidPlaintextLength", err)
	}
}

func TestUnpad_RefusesMalformedPrefixes(t *testing.T) {
	for name, padded := range map[string][]byte{
		"too short":                   {0},
		"u16 zero (no extended form)": append([]byte{0, 0}, make([]byte, 4+65536)...),
		"u16 length, wrong pad size":  {0, 1, 'a'},
	} {
		if _, err := unpad(padded); !errors.Is(err, ErrInvalidPadding) {
			t.Errorf("%s: unpad error = %v, want ErrInvalidPadding", name, err)
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
