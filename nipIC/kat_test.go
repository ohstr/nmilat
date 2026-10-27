package nipIC

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// K-CK-1's negative: sha256("discord:080351110224678912") is the key of an
// input with a leading zero, which NewConnectionKey refuses and so never
// produces (plan §4.2).
func TestKCK1_NeverProduced(t *testing.T) {
	sum := sha256.Sum256([]byte("discord:080351110224678912"))
	if hex.EncodeToString(sum[:]) != "fec2a66329b3254449b6ab5934972f151fb2f9f1545802fdb06ad8f515b7060f" {
		t.Fatalf("K-CK-1 negative = %x", sum)
	}
	if _, err := NewConnectionKey("discord", "080351110224678912"); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("a leading zero: %v", err)
	}
}
