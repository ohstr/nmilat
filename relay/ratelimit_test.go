package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay/ratelimit"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
)

// limitClock is a manual clock for a Limiter, so refill needs no sleep.
type limitClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *limitClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *limitClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newLimitedRelay serves a relay with lim (nil for none) and returns its
// handler and URL.
func newLimitedRelay(t *testing.T, lim *ratelimit.Limiter, opts ...SessionOption) (*SessionHandler, string) {
	t.Helper()
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	opts = append([]SessionOption{WithLogger(testlogger.New(t)), WithRateLimiter(lim)}, opts...)
	handler := NewSessionHandler(store, metadata, nil, opts...)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	// Runs after every dialRelay's close (cleanups are LIFO), before
	// srv.Close: see createWS.
	t.Cleanup(func() { waitForSessionCount(t, handler, 0) })
	metadata.URL = "ws" + strings.TrimPrefix(srv.URL, "http")
	return handler, srv.URL
}

// dialAuthed opens a connection to url that has authenticated (NIP-42) as
// priv.
func dialAuthed(t *testing.T, url, priv string) *roClient {
	t.Helper()
	c := dialRO(t, nil, "ws"+strings.TrimPrefix(url, "http"))
	c.auth(priv)
	return c
}

func dialRelay(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
		_, ok := r.(*wire.AuthChallengeResponse)
		return ok
	})
	return conn
}

func newLimiter(t *testing.T, cfg ratelimit.Config) (*ratelimit.Limiter, *limitClock) {
	t.Helper()
	c := &limitClock{t: time.Unix(1_700_000_000, 0)}
	cfg.Now = c.now
	lim, err := ratelimit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return lim, c
}

// publish sends events in order and returns each one's OK, by id.
func publish(t *testing.T, conn *websocket.Conn, events []*nip01.Event) map[string]*wire.OkSubscriptionResponse {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		for _, ev := range events {
			if err := conn.WriteJSON([]any{"EVENT", ev}); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	oks := make(map[string]*wire.OkSubscriptionResponse, len(events))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(oks) < len(events) {
		var msg wire.ClientPayload
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read after %d OKs: %v", len(oks), err)
		}
		if ok, is := msg.SubscriptionResponse.(*wire.OkSubscriptionResponse); is {
			oks[ok.EventID] = ok
		}
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	return oks
}

func TestRateLimitedEventBurst(t *testing.T) {
	const limit = 25
	lim, clock := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 60, Per: time.Minute, Burst: limit}},
	})
	obs := &recordingObserver{}
	_, url := newLimitedRelay(t, lim, WithObserver(obs))
	conn := dialAuthed(t, url, recipientPrivKey).conn

	events := CreateEvents(t, 300, 1)
	oks := publish(t, conn, events)
	for i, ev := range events {
		ok := oks[ev.ID]
		if i < limit {
			if !ok.Accepted {
				t.Fatalf("event %d refused within the burst: %q", i, ok.Message)
			}
			continue
		}
		if ok.Accepted || !strings.HasPrefix(ok.Message, "rate-limited: ") {
			t.Fatalf("event %d past the burst: accepted %v, %q", i, ok.Accepted, ok.Message)
		}
	}
	if got := obs.reasons[ReasonRateLimited].Load(); got != 300-limit {
		t.Fatalf("observer counted %d rate-limited, want %d", got, 300-limit)
	}

	// One a second refills: three seconds lets three more through.
	clock.advance(3 * time.Second)
	more := CreateEvents(t, 5, 1)
	oks = publish(t, conn, more)
	accepted := 0
	for _, ev := range more {
		if oks[ev.ID].Accepted {
			accepted++
		}
	}
	if accepted != 3 {
		t.Fatalf("%d accepted after a 3s refill, want 3", accepted)
	}
}

func TestRateLimitedEventsPerIP(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerIP: ratelimit.Rate{Events: 10, Per: time.Hour}},
	})
	_, url := newLimitedRelay(t, lim)
	// Two connections from one IP share its budget.
	a, b := dialRelay(t, url), dialRelay(t, url)
	accepted := 0
	for _, conn := range []*websocket.Conn{a, b} {
		events := CreateEvents(t, 8, 1)
		for _, ok := range publish(t, conn, events) {
			if ok.Accepted {
				accepted++
			}
		}
	}
	if accepted != 10 {
		t.Fatalf("%d accepted from one IP, want 10", accepted)
	}
}

func TestNoLimitsAcceptsEveryEvent(t *testing.T) {
	_, url := newLimitedRelay(t, nil)
	conn := dialRelay(t, url)
	events := CreateEvents(t, 300, 1)
	for id, ok := range publish(t, conn, events) {
		if !ok.Accepted {
			t.Fatalf("%s refused with no limits: %q", id, ok.Message)
		}
	}

	// A zero Config is the same as none.
	lim, err := ratelimit.New(ratelimit.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, url = newLimitedRelay(t, lim)
	conn = dialRelay(t, url)
	events = CreateEvents(t, 300, 1)
	for id, ok := range publish(t, conn, events) {
		if !ok.Accepted {
			t.Fatalf("%s refused by a zero Config: %q", id, ok.Message)
		}
	}
}

func TestRateLimitedReqAndCount(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Read: ratelimit.Limit{PerIP: ratelimit.Rate{Events: 2, Per: time.Hour}},
	})
	_, url := newLimitedRelay(t, lim)
	conn := dialRelay(t, url)

	for _, sub := range []string{"s1", "s2"} {
		if err := conn.WriteJSON([]any{"REQ", sub, map[string]any{"kinds": []int{1}}}); err != nil {
			t.Fatal(err)
		}
		awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
			e, ok := r.(*wire.EOSESubscriptionResponse)
			return ok && e.SubscriptionID == sub
		})
	}
	for _, msg := range [][]any{
		{"REQ", "s3", map[string]any{"kinds": []int{1}}},
		{"COUNT", "c1", map[string]any{"kinds": []int{1}}},
	} {
		if err := conn.WriteJSON(msg); err != nil {
			t.Fatal(err)
		}
		sub := msg[1].(string)
		awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
			c, ok := r.(*wire.ClosedSubscriptionResponse)
			if !ok || c.SubscriptionID != sub {
				return false
			}
			if !strings.HasPrefix(c.Message, "rate-limited: ") {
				t.Fatalf("%s closed %q, want rate-limited", sub, c.Message)
			}
			return true
		})
	}
}

func TestRateLimitedConnectionsPerIP(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{MaxConnsPerIP: 2})
	handler, url := newLimitedRelay(t, lim)
	first := dialRelay(t, url)
	dialRelay(t, url)

	_, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http"), nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third connection: err %v, resp %v, want 429", err, resp)
	}
	_ = resp.Body.Close()

	// Closing one frees its slot.
	_ = first.Close()
	waitForSessionCount(t, handler, 1)
	dialRelay(t, url)
}

func TestRateLimitedHTTPBridge(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		HTTP: ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 2, Per: time.Hour}},
	})
	handler, _ := newLimitedRelay(t, lim)
	query := httptest.NewServer(handler.QueryHandler())
	t.Cleanup(query.Close)

	body := []byte(`[{"kinds":[1]}]`)
	for i := range 2 {
		if resp := postQuery(t, query.URL, body, true); resp.StatusCode != http.StatusOK {
			t.Fatalf("query %d: status %d", i, resp.StatusCode)
		}
	}
	resp := postQuery(t, query.URL, body, true)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("third query: status %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}

	// /count shares the signer's HTTP budget.
	count := httptest.NewServer(handler.CountHandler())
	t.Cleanup(count.Close)
	if resp := postQuery(t, count.URL, body, true); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("count: status %d, want 429", resp.StatusCode)
	}
}

func TestRateLimitedEventsHandler(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 1, Per: time.Hour}},
		HTTP:  ratelimit.Limit{PerIP: ratelimit.Rate{Events: 3, Per: time.Hour}},
	})
	store := newStore(t)
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "", WithEventsRateLimiter(lim)))
	t.Cleanup(srv.Close)

	post := func() *http.Response {
		body, err := json.Marshal(CreateEvents(t, 1, 1)[0])
		if err != nil {
			t.Fatal(err)
		}
		return postEvent(t, srv.URL, body, queryTestPrivKey)
	}
	if resp := post(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first event: status %d", resp.StatusCode)
	}
	// The author's Event budget is spent.
	if resp := post(); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second event: status %d, want 429", resp.StatusCode)
	}
	post()
	// Then the IP's HTTP budget.
	if resp := post(); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("fourth request: status %d, want 429 with Retry-After", resp.StatusCode)
	}
}

func TestRateLimitExemptPubkey(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event:  ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 1, Per: time.Hour}},
		Exempt: func(pk string) bool { return pk == publicKey },
	})
	_, url := newLimitedRelay(t, lim)
	conn := dialAuthed(t, url, recipientPrivKey).conn
	for id, ok := range publish(t, conn, CreateEvents(t, 20, 1)) {
		if !ok.Accepted {
			t.Fatalf("%s from an exempt pubkey refused: %q", id, ok.Message)
		}
	}
}

// TestReplayDoesNotSpendTheAuthorsBudget: anyone can replay a signed
// event, so a replay (or a mirror relaying others' events) must not drain
// the author's Event budget.
func TestReplayDoesNotSpendTheAuthorsBudget(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 2, Per: time.Hour}},
	})
	_, url := newLimitedRelay(t, lim)
	victim := dialAuthed(t, url, recipientPrivKey)
	events := CreateEvents(t, 2, 1)
	victim.publish(events[0])

	// Unauthenticated, and authenticated as someone else.
	stranger := dialAuthed(t, url, strangerPrivKey).conn
	for _, conn := range []*websocket.Conn{dialRelay(t, url), stranger} {
		for range 20 {
			if err := conn.WriteJSON([]any{"EVENT", events[0]}); err != nil {
				t.Fatal(err)
			}
		}
		for range 20 {
			awaitResponse(t, conn, func(r wire.SubscriptionResponse) bool {
				_, ok := r.(*wire.OkSubscriptionResponse)
				return ok
			})
		}
	}
	// The victim replaying its own stored event is not charged either.
	victim.publish(events[0])

	victim.publish(events[1])
	victim.send("EVENT", CreateEvents(t, 1, 1)[0])
	_, raw := victim.until("OK")
	var accepted bool
	_ = json.Unmarshal(raw[2], &accepted)
	if accepted {
		t.Fatal("a third new event was accepted past a budget of 2")
	}
}

func TestRateLimitedEventsHandlerPerIP(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerIP: ratelimit.Rate{Events: 2, Per: time.Hour}},
	})
	store := newStore(t)
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "", WithEventsRateLimiter(lim)))
	t.Cleanup(srv.Close)
	for i := range 3 {
		body, err := json.Marshal(CreateEvents(t, 1, 1)[0])
		if err != nil {
			t.Fatal(err)
		}
		resp := postEvent(t, srv.URL, body, queryTestPrivKey)
		if want := http.StatusOK; i == 2 {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("third event from one IP: status %d, want 429", resp.StatusCode)
			}
		} else if resp.StatusCode != want {
			t.Fatalf("event %d: status %d", i, resp.StatusCode)
		}
	}
}

func TestEventsHandlerReplayDoesNotSpendTheAuthorsBudget(t *testing.T) {
	lim, _ := newLimiter(t, ratelimit.Config{
		Event: ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 1, Per: time.Hour}},
	})
	store := newStore(t)
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "", WithEventsRateLimiter(lim)))
	t.Cleanup(srv.Close)
	body, err := json.Marshal(CreateEvents(t, 1, 1)[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if resp := postEvent(t, srv.URL, body, queryTestPrivKey); resp.StatusCode != http.StatusOK {
			t.Fatalf("post %d of one event: status %d", i, resp.StatusCode)
		}
	}
}
