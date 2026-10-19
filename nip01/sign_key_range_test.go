package nip01

import (
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/utils"
)

// Signing with a secret of 0 fails instead of producing a meaningless pubkey.
func TestSign_RefusesAZeroSecret(t *testing.T) {
	ev := NewEvent(1, "x")
	if err := ev.Sign(strings.Repeat("0", 64)); !errors.Is(err, utils.ErrInvalidPrivateKey) {
		t.Errorf("Sign(0) error = %v, want ErrInvalidPrivateKey", err)
	}
}
