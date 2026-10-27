package nipcash

import (
	"errors"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// reencodeM is s with its bech32 checksum replaced by a bech32m one.
func reencodeM(t *testing.T, s string) string {
	t.Helper()
	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		t.Fatal(err)
	}
	m, err := bech32.EncodeM(hrp, bits5)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Credentials are NIP-19 bech32: a bech32m checksum is refused by every
// credential decoder (tokens and connection strings alike).
func TestCredentialDecoders_RefuseBech32m(t *testing.T) {
	if _, err := Decode(reencodeM(t, ktok1)); !errors.Is(err, ErrBech32m) {
		t.Errorf("token: %v, want ErrBech32m", err)
	}
	if _, err := DecodeCashHubConnection(reencodeM(t, kch1String)); !errors.Is(err, ErrBech32m) {
		t.Errorf("cashhub1: %v, want ErrBech32m", err)
	}
	if _, err := Decode(ktok1); err != nil {
		t.Errorf("the bech32 token itself: %v", err)
	}
}
