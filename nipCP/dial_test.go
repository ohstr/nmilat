package nipCP

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
)

// DialRelays against in-process relays: Store writes and reads back, Sync opens.
// The relays never challenge AUTH and answer every REQ with what they stored
// before its OK, so the outcome does not depend on timing: every wrap is read
// back from both, and an empty answer waits at most AuthWait.
func TestDialRelaysStoreAndSync(t *testing.T) {
	a, b := cashtest.NewRelay(t), cashtest.NewRelay(t)
	priv, user := key(t)
	rs := DialRelays(priv)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	relays := []string{a.URL(), b.URL()}
	// Several wraps, each read back from both relays as soon as it is stored:
	// none may be lost between the relay's last EVENT and its EOSE.
	const n = 12
	keys := map[string]bool{}
	var wraps []*nip01.Event
	for i := 0; i < n; i++ {
		wrap, e, err := Seal(bill(hx("0123456789ab"[i], 64), 1, StateLive), priv)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := Store(ctx, rs, relays, wrap)
		if err != nil || len(stored) != 2 {
			t.Fatalf("wrap %d stored %v, %v", i, stored, err)
		}
		keys[e.WrapKey] = true
		wraps = append(wraps, wrap)
	}
	s, err := Sync(ctx, rs, relays, priv, FullSyncFilter(user), nil)
	if err != nil || len(s.Entries) != n {
		t.Fatalf("sync %d entries, %v", len(s.Entries), err)
	}
	for _, e := range s.Entries {
		if !keys[e.WrapKey] {
			t.Fatalf("unknown entry %+v", e)
		}
	}
	for _, w := range wraps {
		if len(s.On[w.ID]) != 2 {
			t.Fatalf("wrap %s on %v", w.ID, s.On[w.ID])
		}
	}
}

// An empty answer from a relay that never challenges waits AuthWait, then
// returns nothing; a negative AuthWait never waits.
func TestDialRelaysAuthWait(t *testing.T) {
	r := cashtest.NewRelay(t)
	priv, user := key(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := FullSyncFilter(user)
	for _, wait := range []time.Duration{-1, time.Millisecond} {
		got, err := DialRelaysWith(DialConfig{AuthKeyHex: priv, AuthWait: wait}).Query(ctx, r.URL(), f)
		if err != nil || len(got) != 0 {
			t.Fatalf("AuthWait %v: %v %v", wait, got, err)
		}
	}
	if d := DialRelaysWith(DialConfig{AuthKeyHex: priv}).(dialRelays); d.authWait != DefaultAuthWait {
		t.Fatalf("default AuthWait %v", d.authWait)
	}
}
