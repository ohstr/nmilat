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

	_, _, subErr := s.subscribeReplies(ctx, strings.Repeat("c", 64))
	pubErr := s.publish(ctx, nip01.NewEvent(1, "x"))
	for name, err := range map[string]error{"subscribe": subErr, "publish": pubErr} {
		if err == nil {
			t.Fatalf("%s: no error with every relay unreachable", name)
		}
		for _, r := range relays {
			if !strings.Contains(err.Error(), r) {
				t.Errorf("%s error %q does not name relay %s", name, err, r)
			}
		}
	}
}
