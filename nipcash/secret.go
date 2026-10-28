package nipcash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

// randReader is where cash secrets come from; a test swaps it to check that a
// failing reader is an error, never a panic.
var randReader io.Reader = rand.Reader

// ValidCashSecret reports a cash secret of the wire form: 64 lowercase hex (32
// bytes).
func ValidCashSecret(s string) bool { return isLowerHex64(s) }

// ValidCommitment reports a cash commitment of the wire form: 64 lowercase hex.
func ValidCommitment(s string) bool { return isLowerHex64(s) }

// CashCommitment is the commitment of a secret: the lowercase hex sha256 of its
// 32 raw bytes (never of its hex text).
func CashCommitment(secretHex string) (string, error) {
	if !ValidCashSecret(secretHex) {
		return "", fmt.Errorf("nipcash: a cash secret is 64 lowercase hex characters")
	}
	raw, _ := hex.DecodeString(secretHex)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CommitmentsEqual compares two commitments in constant time.
func CommitmentsEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewCashTarget generates a fresh 256-bit cash secret and its commitment, for a
// cash-mode mint recipient or transfer/consolidate target. The caller persists
// Secret() before the call goes out.
func NewCashTarget() (*CashTarget, error) {
	var raw [32]byte
	if _, err := io.ReadFull(randReader, raw[:]); err != nil {
		return nil, fmt.Errorf("nipcash: cash secret: %w", err)
	}
	return CashTargetFromSecret(hex.EncodeToString(raw[:]))
}

// CashTargetFromSecret rebuilds a target from a secret the caller already holds
// (for example one written ahead of the call).
func CashTargetFromSecret(secretHex string) (*CashTarget, error) {
	commit, err := CashCommitment(secretHex)
	if err != nil {
		return nil, err
	}
	return &CashTarget{secret: secretHex, commit: commit}, nil
}

// Commitment is the target's commitment, what travels on the wire.
func (t *CashTarget) Commitment() string { return t.commit }
