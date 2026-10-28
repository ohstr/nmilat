package client

import (
	"context"
	"testing"
)

// Connect refuses anything that is not a circlehub1 string before dialing.
func TestConnect_RejectsGarbage(t *testing.T) {
	for _, s := range []string{"not a connection", "nostr+walletconnect://x?relay=wss://r&secret=y"} {
		if _, err := Connect(context.Background(), s, Options{}); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}
