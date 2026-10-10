package nip19

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
)

// ErrPrivateKey is returned by ParsePublicKey for an nsec.
var ErrPrivateKey = errors.New("nip19: got a private key (nsec), want a public key")

// ParsePublicKey accepts an npub, an nprofile or 64-character hex and
// returns the public key as lowercase hex. Unlike NormalizeToHex it rejects
// an nsec, anything that isn't exactly 32 bytes, and any key that isn't a
// valid x-only secp256k1 point, instead of passing the input through.
func ParsePublicKey(input string) (string, error) {
	input = strings.TrimSpace(input)
	lower := strings.ToLower(input)

	var key []byte
	switch {
	case strings.HasPrefix(lower, "nsec1"):
		return "", ErrPrivateKey
	case strings.HasPrefix(lower, "npub1"):
		b, err := decodeBech32Bytes(input, "npub")
		if err != nil {
			return "", fmt.Errorf("nip19: invalid npub: %w", err)
		}
		key = b
	case strings.HasPrefix(lower, "nprofile1"):
		p, err := DecodeProfile(input)
		if err != nil {
			return "", fmt.Errorf("nip19: invalid nprofile: %w", err)
		}
		b, err := hex.DecodeString(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("nip19: invalid nprofile: %w", err)
		}
		key = b
	default:
		if len(input) != 64 {
			return "", fmt.Errorf("nip19: public key hex is %d characters, want 64", len(input))
		}
		b, err := hex.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("nip19: invalid public key hex: %w", err)
		}
		key = b
	}

	if len(key) != 32 {
		return "", fmt.Errorf("nip19: public key is %d bytes, want 32", len(key))
	}
	if _, err := schnorr.ParsePubKey(key); err != nil {
		return "", fmt.Errorf("nip19: not a valid public key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
