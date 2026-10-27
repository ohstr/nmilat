package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// NIP-CASH §Multiple Relay Hints: when every relay fails, report what was tried,
// not only the last failure. Both relays here refuse connections.
func TestPrivateTransport_ReportsEveryRelayFailure(t *testing.T) {
	relays := []string{"ws://127.0.0.1:1", "ws://127.0.0.1:2"}
	s := hostileSession(transport.DefaultLimits(), strings.Repeat("b", 64))
	s.relays = relays
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, _, err := s.subscribeAndPublish(ctx, strings.Repeat("c", 64), &outgoing{ev: nip01.NewEvent(1, "x")})
	if err == nil {
		t.Fatal("no error with every relay unreachable")
	}
	for _, r := range relays {
		if !strings.Contains(err.Error(), r) {
			t.Errorf("error %q does not name relay %s", err, r)
		}
	}
}
