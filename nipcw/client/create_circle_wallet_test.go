package client

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcw"
)

// With no connection key, the client generates a fresh one per call; a key the
// caller supplied (and may have saved) is used as given.
func TestWithConnectionKey(t *testing.T) {
	a, err := withConnectionKey(nipcw.CreateCircleWalletParams{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := withConnectionKey(nipcw.CreateCircleWalletParams{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Connection.IsZero() || a.Connection.Pubkey() == b.Connection.Pubkey() {
		t.Fatalf("generated keys %q and %q: want two fresh, distinct keys", a.Connection.Pubkey(), b.Connection.Pubkey())
	}

	own, err := nipcw.ConnectionKeyFromSecret(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	kept, err := withConnectionKey(nipcw.CreateCircleWalletParams{Connection: own})
	if err != nil {
		t.Fatal(err)
	}
	if kept.Connection.Secret() != own.Secret() {
		t.Fatal("a caller-supplied connection key was replaced")
	}
}
