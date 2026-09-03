package client

import (
	"context"
	"testing"
)

// TestConnect_RejectsGarbage covers the one piece of Connect's logic
// testable without a live relay: neither a valid pairing URI nor a valid
// cash token, so it must fail before ever attempting to dial. Connect
// itself always dials out (relayclient.NewNWCClient), so a real connection
// round-trip isn't exercisable in this repo's own test suite — see the
// implementation plan's own note on live-network verification.
func TestConnect_RejectsGarbage(t *testing.T) {
	_, err := Connect(context.Background(), "not a pairing uri or a cash token")
	if err == nil {
		t.Fatal("expected an error for input that is neither a pairing URI nor a cash token")
	}
}
