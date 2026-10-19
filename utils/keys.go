package utils

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
)

func Validate32Key(hexStr string) error {
	if len(hexStr) != 64 {
		return fmt.Errorf("invalid key, bad size: %d", len(hexStr))
	}

	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return errors.New("invalid hex format")
		}
	}

	return nil
}

func GetPublicKey(privKeyHex string) (string, error) {
	priv, err := ParsePrivateKeyHex(privKeyHex)
	if err != nil {
		return "", err
	}
	publicKeyBytes := priv.PubKey().SerializeCompressed()
	return hex.EncodeToString(publicKeyBytes[1:]), nil
}

// curveOrder is secp256k1's group order n, big-endian.
var curveOrder = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

// ErrInvalidPrivateKey is a secret key outside [1, n-1]: PrivKeyFromBytes would
// silently reduce it mod n into a different, meaningless key.
var ErrInvalidPrivateKey = errors.New("invalid private key: must be in [1, n-1]")

// ParsePrivateKeyHex decodes a 32-byte hex secret key and refuses one that is
// 0 or at or above the curve order, which btcec leaves to the caller.
func ParsePrivateKeyHex(privKeyHex string) (*btcec.PrivateKey, error) {
	b, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid private key length")
	}
	if bytes.Compare(b, curveOrder[:]) >= 0 || bytes.Equal(b, make([]byte, 32)) {
		return nil, ErrInvalidPrivateKey
	}
	priv, _ := btcec.PrivKeyFromBytes(b)
	return priv, nil
}
