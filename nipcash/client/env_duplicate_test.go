package client

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// E-ENV-08 (S-CASH-137): the relay hands the Hub one request twice; the Hub
// serves it once (E3, the nonce is served), so the item runs once and one reply
// is published.
func TestEENV08_RelayDuplicatesTheRequest(t *testing.T) {
	var decided atomic.Int32
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		decided.Add(1)
		return alwaysSucceed(item)
	})
	s, relay := openTestSession(t, hub)
	var heard atomic.Int32
	relay.OnEvent(func(_ *cashtest.Relay, ev *nip01.Event) {
		if ev.Kind == transport.KindPrivateRequest {
			heard.Add(1)
		}
	})
	relay.Duplicate(func(ev *nip01.Event) bool { return ev.Kind == transport.KindPrivateRequest })

	priv, target := sessionKeypair(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	out, err := s.StatusMany(ctx, []BatchStatus{{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}})
	if err != nil || len(out) != 1 || out[0].State != OutcomeResult {
		t.Fatalf("StatusMany = %+v, %v", out, err)
	}
	// Give the second copy time to reach the Hub, then count.
	time.Sleep(200 * time.Millisecond)
	replies := 0
	for _, ev := range relay.Accepted() {
		if ev.Kind == transport.KindPrivateResponse {
			replies++
		}
	}
	if heard.Load() != 2 {
		t.Fatalf("the Hub's relay handed it the request %d times, want 2", heard.Load())
	}
	if decided.Load() != 1 || replies != 1 || len(hub.envelopes()) != 1 {
		t.Fatalf("decided %d, replies %d, envelopes %d; want one each", decided.Load(), replies, len(hub.envelopes()))
	}
}
