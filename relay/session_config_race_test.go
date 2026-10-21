package relay

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
)

// NewSessionContext runs once per connection against the one *SessionConfig
// the SessionHandler shares across sessions, so filling in defaults for
// zero-valued sizes must not write into that shared struct.
func TestNewSessionContextDoesNotMutateSharedConfig(t *testing.T) {
	shared := &SessionConfig{}
	metadata := &nip11.Metadata{}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := NewSessionContext(nil, &ClientInfo{}, metadata, nil, nil, shared)
			if got := cap(sc.storeLimiter); got != defaultMaxConcurrentStoreTasks {
				t.Errorf("storeLimiter cap = %d, want %d", got, defaultMaxConcurrentStoreTasks)
			}
			if got := cap(sc.incoming); got != defaultOutgoingBufferSize {
				t.Errorf("incoming cap = %d, want %d", got, defaultOutgoingBufferSize)
			}
		}()
	}
	wg.Wait()

	if shared.OutgoingBufferSize != 0 || shared.MaxConcurrentStoreTasks != 0 {
		t.Fatalf("caller's SessionConfig mutated: OutgoingBufferSize=%d MaxConcurrentStoreTasks=%d",
			shared.OutgoingBufferSize, shared.MaxConcurrentStoreTasks)
	}
}

// End-to-end form of the above: concurrent WebSocket connections against a
// handler built with WithSessionConfig that leaves both sizes at zero.
func TestConcurrentSessionsWithZeroSizedSessionConfig(t *testing.T) {
	store, err := NewEventStore(t.TempDir()+"/race.db", &nip11.Limitation{},
		WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	cfg := *defaultSessionConfig()
	cfg.OutgoingBufferSize = 0
	cfg.MaxConcurrentStoreTasks = 0
	cfg.Logger = testlogger.New(t)

	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil, WithSessionConfig(cfg))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	const conns = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer conn.Close()
			awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
				_, ok := r.(*wire.AuthChallengeResponse)
				return ok
			})
		}()
	}
	close(start)
	wg.Wait()
}
