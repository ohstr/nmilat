package nipCP

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
)

// DialRelays against in-process relays: Store writes and reads back, Sync opens.
func TestDialRelaysStoreAndSync(t *testing.T) {
	a, b := cashtest.NewRelay(t), cashtest.NewRelay(t)
	priv, user := key(t)
	rs := DialRelays(priv)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	wrap, e, err := Seal(bill(hx('1', 64), 1, StateLive), priv)
	if err != nil {
		t.Fatal(err)
	}
	relays := []string{a.URL(), b.URL()}
	stored, err := Store(ctx, rs, relays, wrap)
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %v, %v", stored, err)
	}
	s, err := Sync(ctx, rs, relays, priv, FullSyncFilter(user), nil)
	if err != nil || len(s.Entries) != 1 || s.Entries[0].WrapKey != e.WrapKey || len(s.On[wrap.ID]) != 2 {
		t.Fatalf("sync %+v %v", s, err)
	}
}
