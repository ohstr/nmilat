package client

import (
	"context"
	"testing"
)

// TestConnect_RejectsGarbage mirrors nipcash/client's own test — the one
// piece of Connect's logic testable without a live relay (Connect always
// dials out via relayclient.NewNWCClient, so a real round trip isn't
// exercisable in this repo's own test suite).
func TestConnect_RejectsGarbage(t *testing.T) {
	_, err := Connect(context.Background(), "not a pairing uri")
	if err == nil {
		t.Fatal("expected an error for a non-pairing-URI input")
	}
}
