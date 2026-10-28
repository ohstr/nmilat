package nipcash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ValidRequestID reports a request_id of the form NIP-CASH §request_id requires:
// an even number of lowercase hex characters, 32 to 64 inclusive.
func ValidRequestID(s string) bool {
	if len(s) < 32 || len(s) > 64 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NewRequestID returns a fresh request_id: 32 bytes from crypto/rand, as 64
// lowercase hex.
func NewRequestID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("nipcash: request_id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// DerivedRequestID is the id a re-placed call carries: the lowercase hex of
// sha256("retry:" ‖ replaced), over replaced exactly as sent.
func DerivedRequestID(replaced string) (string, error) {
	if !ValidRequestID(replaced) {
		return "", fmt.Errorf("nipcash: %q is not a request_id", replaced)
	}
	sum := sha256.Sum256([]byte("retry:" + replaced))
	return hex.EncodeToString(sum[:]), nil
}
