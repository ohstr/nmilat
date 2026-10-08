package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/wire"
)

// TestProcessEvent_AlwaysReplies: every EVENT gets exactly one OK, whatever
// the store does with it.
func TestProcessEvent_AlwaysReplies(t *testing.T) {
	cases := []struct {
		name         string
		setup        func(t *testing.T, store *EventStore, sc *SessionContext) context.Context
		wantAccepted bool
		wantPrefix   string
	}{
		{
			name:         "stored",
			setup:        func(*testing.T, *EventStore, *SessionContext) context.Context { return context.Background() },
			wantAccepted: true,
		},
		{
			name: "store_closed",
			setup: func(_ *testing.T, store *EventStore, _ *SessionContext) context.Context {
				store.Close()
				return context.Background()
			},
			wantPrefix: "error: relay unavailable",
		},
		{
			name: "canceled_context",
			setup: func(_ *testing.T, _ *EventStore, sc *SessionContext) context.Context {
				// A full limiter leaves ctx.Done as executeStoreTask's only ready case.
				for len(sc.storeLimiter) < cap(sc.storeLimiter) {
					sc.storeLimiter <- struct{}{}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantPrefix: "error: relay unavailable",
		},
		{
			name: "store_busy",
			setup: func(t *testing.T, store *EventStore, _ *SessionContext) context.Context {
				// Hold bbolt's writer lock so the batch can't commit in time.
				release := make(chan struct{})
				held := make(chan struct{})
				go func() {
					_ = store.Db().Update(func(*bolt.Tx) error {
						close(held)
						<-release
						return nil
					})
				}()
				<-held
				t.Cleanup(func() { close(release) })
				return context.Background()
			},
			wantPrefix: "error: relay busy",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newStore(t)
			cfg := defaultSessionConfig()
			cfg.StoreReplyTimeout = 200 * time.Millisecond
			cfg.MaxConcurrentStoreTasks = 4
			sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, cfg)
			sess := &Session{SessionContext: sc}

			ctx := c.setup(t, store, sc)
			ev := CreateEvent(t, 1)
			if err := sess.processEvent(ctx, &wire.EventPacket{Event: ev}); err != nil {
				t.Fatalf("processEvent: %v", err)
			}

			var ok *wire.OkSubscriptionResponse
			select {
			case reply := <-sess.incoming:
				var isOk bool
				if ok, isOk = reply.(*wire.OkSubscriptionResponse); !isOk {
					t.Fatalf("reply type = %T, want OK", reply)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no OK reply")
			}
			if ok.EventID != ev.ID || ok.Accepted != c.wantAccepted || !strings.HasPrefix(ok.Message, c.wantPrefix) {
				t.Fatalf("OK = %+v, want accepted=%v message=%q...", ok, c.wantAccepted, c.wantPrefix)
			}

			select {
			case extra := <-sess.incoming:
				t.Fatalf("second reply %+v, want exactly one OK", extra)
			case <-time.After(400 * time.Millisecond):
			}
		})
	}
}
