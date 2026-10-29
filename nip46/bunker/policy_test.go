package bunker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip46"
)

// policyServer is a relay-less server with policy p.
func policyServer(t *testing.T, p Policy) *Server {
	t.Helper()
	k, _ := nip46.NewLocalKey(userPriv)
	srv, err := NewServer(ServerConfig{Key: k, Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// handle sends one request from the peer app through Handle and returns the
// parsed response.
func handle(t *testing.T, ctx context.Context, srv *Server, method string, params ...string) *nip46.ResponseEvent {
	t.Helper()
	return handleFrom(t, ctx, srv, peerPriv, method, params...)
}

// handleFrom is handle from the app whose client key is appPriv.
func handleFrom(t *testing.T, ctx context.Context, srv *Server, appPriv, method string, params ...string) *nip46.ResponseEvent {
	t.Helper()
	app, _ := nip46.NewLocalKey(appPriv)
	ev, _, err := nip46.NewRequestEvent(app.PrivKeyHex(), srv.TransportPubKey(), method, params, nip46.EncryptionNIP44V2)
	if err != nil {
		t.Error(err)
		return &nip46.ResponseEvent{Response: nip46.Response{Error: err.Error()}}
	}
	_ = ev.Sign(app.PrivKeyHex())
	req, err := nip46.ParseRequestEvent(ev, userPriv)
	if err != nil {
		t.Error(err)
		return &nip46.ResponseEvent{Response: nip46.Response{Error: err.Error()}}
	}
	resp, err := srv.Handle(ctx, req, nip46.EncryptionNIP44V2)
	if err != nil {
		t.Error(err)
		return &nip46.ResponseEvent{Response: nip46.Response{Error: err.Error()}}
	}
	parsed, err := nip46.ParseResponseEvent(resp, app.PrivKeyHex())
	if err != nil {
		t.Error(err)
		return &nip46.ResponseEvent{Response: nip46.Response{Error: err.Error()}}
	}
	return parsed
}

// quota allows limit calls of method, with a gap between check and spend
// that a racing request would slip through without the server's lock.
func quota(method string, limit int32) Policy {
	var used atomic.Int32
	return PolicyFunc(func(_ context.Context, c *Call) error {
		if c.Method != method {
			return nil
		}
		if used.Load() >= limit {
			return nip46.Deny("quota spent")
		}
		time.Sleep(20 * time.Millisecond)
		used.Add(1)
		return nil
	})
}

// concurrentEncrypts sends n encrypts at once from the client appPriv and
// counts those allowed.
func concurrentEncrypts(t *testing.T, srv *Server, appPriv string, n int) int32 {
	t.Helper()
	peer, _ := nip46.NewLocalKey(peerPriv)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := handleFrom(t, context.Background(), srv, appPriv, nip46.MethodNIP44Encrypt, peer.PubKey(), "x"); r.Error == "" {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	return ok.Load()
}

// A client's quota is spent once per request, also under concurrent
// requests from that client; a quota that covers them all lets them all
// through.
func TestPolicyQuotaSpentOnce(t *testing.T) {
	if got := concurrentEncrypts(t, policyServer(t, quota(nip46.MethodNIP44Encrypt, 1)), peerPriv, 2); got != 1 {
		t.Fatalf("encrypts allowed with a quota of 1: %d", got)
	}
	if got := concurrentEncrypts(t, policyServer(t, quota(nip46.MethodNIP44Encrypt, 3)), peerPriv, 3); got != 3 {
		t.Fatalf("encrypts allowed with a quota of 3: %d", got)
	}
}

// otherAppPriv is a second client key.
const otherAppPriv = "0000000000000000000000000000000000000000000000000000000000000009"

// While one client's policy blocks (a prompt), another client's requests
// still run, and the blocked client's next request waits, giving up with its
// context.
func TestPolicyBlockedClientHoldsOnlyItself(t *testing.T) {
	block := make(chan struct{})
	entered := make(chan struct{})
	app, _ := nip46.NewLocalKey(peerPriv)
	srv := policyServer(t, PolicyFunc(func(_ context.Context, c *Call) error {
		if c.Client == app.PubKey() && c.Method == nip46.MethodSignEvent {
			close(entered)
			<-block
		}
		return nil
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handle(t, context.Background(), srv, nip46.MethodSignEvent, `{"kind":1,"content":"x","tags":[],"created_at":1700000000}`)
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if r := handleFrom(t, ctx, srv, otherAppPriv, nip46.MethodPing); r.Result != "pong" {
		t.Errorf("another client blocked by a prompt: %+v", r)
	}
	if r := handleFrom(t, ctx, srv, otherAppPriv, nip46.MethodGetPublicKey); r.Error != "" {
		t.Errorf("another client's second request: %+v", r)
	}
	cancel()
	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if r := handle(t, short, srv, nip46.MethodPing); r.Error == "" {
		t.Errorf("the blocked client's next request ran beside it: %+v", r)
	}
	cancelShort()
	close(block)
	<-done
	if r := handle(t, context.Background(), srv, nip46.MethodPing); r.Result != "pong" {
		t.Errorf("the client after its prompt returned: %+v", r)
	}
}

// Two clients' quotas are separate: each spends its own once.
func TestPolicyQuotaPerClient(t *testing.T) {
	var mu sync.Mutex
	used := map[string]int{}
	srv := policyServer(t, PolicyFunc(func(_ context.Context, c *Call) error {
		mu.Lock()
		n := used[c.Client]
		mu.Unlock()
		if n >= 1 {
			return nip46.Deny("quota spent")
		}
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		used[c.Client]++
		mu.Unlock()
		return nil
	}))
	var a, b int32
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a = concurrentEncrypts(t, srv, peerPriv, 2) }()
	go func() { defer wg.Done(); b = concurrentEncrypts(t, srv, otherAppPriv, 2) }()
	wg.Wait()
	if a != 1 || b != 1 {
		t.Fatalf("allowed per client: %d and %d, want 1 and 1", a, b)
	}
	if n := len(srv.clientLocks); n != 0 {
		t.Errorf("%d client locks left after the requests", n)
	}
}
