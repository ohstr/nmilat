package utils

import (
	"errors"
	"strings"
	"testing"
)

const (
	keyZero    = "0000000000000000000000000000000000000000000000000000000000000000"
	keyOne     = "0000000000000000000000000000000000000000000000000000000000000001"
	keyNMinus1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
	keyN       = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	keyNPlus1  = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
	keyMax     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// A secret of 0 or at or above n is refused: btcec would reduce it mod n into a
// different key (n+1 used to give the same pubkey as 1).
func TestGetPublicKey_RefusesASecretOutsideTheCurveOrder(t *testing.T) {
	for _, k := range []string{keyZero, keyN, keyNPlus1, keyMax} {
		if pub, err := GetPublicKey(k); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("GetPublicKey(%s…) = %q, %v; want ErrInvalidPrivateKey", k[:8], pub, err)
		}
	}
}

func TestGetPublicKey_AcceptsTheEndsOfTheRange(t *testing.T) {
	for k, want := range map[string]string{
		keyOne:     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		keyNMinus1: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	} {
		if pub, err := GetPublicKey(k); err != nil || pub != want {
			t.Errorf("GetPublicKey(%s…) = %q, %v; want %q", k[:8], pub, err, want)
		}
	}
}

func TestParsePrivateKeyHex_RefusesBadEncoding(t *testing.T) {
	for _, k := range []string{"", "zz", strings.Repeat("01", 31), strings.Repeat("01", 33)} {
		if _, err := ParsePrivateKeyHex(k); err == nil {
			t.Errorf("ParsePrivateKeyHex(%q) succeeded", k)
		}
	}
}
