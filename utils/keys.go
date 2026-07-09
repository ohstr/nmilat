package utils

import (
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return errors.New("invalid hex format")
		}
	}

	return nil
}

func GetPublicKey(privKeyHex string) (string, error) {
	b, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("invalid private key length")
	}

	_, pubKey := btcec.PrivKeyFromBytes(b)
	publicKeyBytes := pubKey.SerializeCompressed()
	return hex.EncodeToString(publicKeyBytes[1:]), nil
}
