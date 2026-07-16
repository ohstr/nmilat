package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// powTestPrivKey is an arbitrary, fixed test-only private key, only used to
// produce validly signed events so processEvent's Verify() call reaches the
// PoW check instead of failing earlier on signature format.
const powTestPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// minedPowTestEvent mines a genuinely signed event with at least
// targetDifficulty leading zero bits.
func minedPowTestEvent(t *testing.T, targetDifficulty int) *nip01.Event {
	t.Helper()
	pubKey, err := utils.GetPublicKey(powTestPrivKey)
	if err != nil {
		t.Fatalf("failed to derive pubkey: %v", err)
	}
	ev := nip01.NewUnsignedEvent(1, pubKey, "pow test event")
	if err := ev.Mine(context.Background(), targetDifficulty); err != nil {
		t.Fatalf("failed to mine pow: %v", err)
	}
	if err := ev.Sign(powTestPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return ev
}

// sendEventAndAwaitOK feeds ev through processEvent (via ProcessPacket, the
// real dispatch path) and returns the OK response it produces.
func sendEventAndAwaitOK(t *testing.T, sess *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	t.Helper()
	ctx := context.WithValue(context.Background(), sessionContextKey{}, sess)

	go func() {
		if err := sess.ProcessPacket(ctx, wire.NewEventPacket(ev)); err != nil {
			t.Errorf("ProcessPacket: unexpected error: %v", err)
		}
	}()

	select {
	case resp := <-sess.incoming:
		ok, isOk := resp.(*wire.OkSubscriptionResponse)
		if !isOk {
			t.Fatalf("expected *wire.OkSubscriptionResponse, got %T (%+v)", resp, resp)
		}
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for OK response")
		return nil
	}
}

func newPowTestSession(t *testing.T, limitation nip11.Limitation) *Session {
	t.Helper()
	store := newStore(t)
	md := &nip11.Metadata{Limitation: limitation}
	sc := NewSessionContext(store, &ClientInfo{}, md, nil, nil, nil)
	return &Session{SessionContext: sc}
}

// TestProcessEvent_PowNotEnforcedByDefault covers the zero-value/default
// case: MinPowDifficulty and StrictPow both unset (0/false) accepts a
// zero-difficulty event, matching the documented "min: 0 == accept all"
// default and staying backward compatible with configs that predate the
// pow: block entirely.
func TestProcessEvent_PowNotEnforcedByDefault(t *testing.T) {
	sess := newPowTestSession(t, nip11.Limitation{})

	resp := sendEventAndAwaitOK(t, sess, minedPowTestEvent(t, 0))
	if !resp.Accepted {
		t.Fatalf("expected event to be accepted, got rejected: %q", resp.Message)
	}
}

// TestProcessEvent_PowAdvisoryOnly covers StrictPow=false with a non-zero
// MinPowDifficulty: the relay is documented to still accept
// under-difficulty events in this mode (min_pow_difficulty is advertised in
// NIP-11 but not enforced), only rejecting once Strict is turned on.
func TestProcessEvent_PowAdvisoryOnly(t *testing.T) {
	sess := newPowTestSession(t, nip11.Limitation{MinPowDifficulty: 20, StrictPow: false})

	resp := sendEventAndAwaitOK(t, sess, minedPowTestEvent(t, 0))
	if !resp.Accepted {
		t.Fatalf("expected advisory-only mode to accept an under-difficulty event, got rejected: %q", resp.Message)
	}
}

// TestProcessEvent_PowStrictRejectsInsufficientDifficulty covers the
// enforcing case: StrictPow=true with a MinPowDifficulty the event doesn't
// meet gets rejected with an OK false and a "pow: ..." message.
func TestProcessEvent_PowStrictRejectsInsufficientDifficulty(t *testing.T) {
	sess := newPowTestSession(t, nip11.Limitation{MinPowDifficulty: 20, StrictPow: true})

	resp := sendEventAndAwaitOK(t, sess, minedPowTestEvent(t, 0))
	if resp.Accepted {
		t.Fatal("expected an under-difficulty event to be rejected in strict mode")
	}
	if resp.Message == "" || !containsPowPrefix(resp.Message) {
		t.Fatalf("expected a %q-prefixed rejection message, got %q", "pow: ", resp.Message)
	}
}

// TestProcessEvent_PowStrictAcceptsSufficientDifficulty is the positive
// counterpart of TestProcessEvent_PowStrictRejectsInsufficientDifficulty:
// strict mode still accepts an event that genuinely meets MinPowDifficulty.
func TestProcessEvent_PowStrictAcceptsSufficientDifficulty(t *testing.T) {
	const minDifficulty = 8
	sess := newPowTestSession(t, nip11.Limitation{MinPowDifficulty: minDifficulty, StrictPow: true})

	resp := sendEventAndAwaitOK(t, sess, minedPowTestEvent(t, minDifficulty))
	if !resp.Accepted {
		t.Fatalf("expected a sufficiently-mined event to be accepted, got rejected: %q", resp.Message)
	}
}

func containsPowPrefix(s string) bool {
	const prefix = "pow: "
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
