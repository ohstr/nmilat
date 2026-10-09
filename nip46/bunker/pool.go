package bunker

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

const (
	maxBackoff = 30 * time.Second
	// adhocDialTimeout bounds waiting for a relay that only a pairing URI
	// named.
	adhocDialTimeout = 5 * time.Second
)

// RelayStatus is whether one relay currently has a live connection.
type RelayStatus struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
	// Connecting is true until the relay's first dial attempt resolves.
	Connecting bool `json:"connecting,omitempty"`
}

// pool keeps one subscribed connection per relay, reconnecting with
// backoff, and hands every event to onEvent on its own goroutine.
type pool struct {
	filter  *nip01.SubscriptionFilterGroup
	onEvent func(conn *relayclient.Connection, ev *nip01.Event)
	logf    func(format string, args ...any)

	mu        sync.Mutex
	order     []string
	running   map[string]bool
	conns     map[string]*relayclient.Connection
	attempted map[string]bool
	connected chan struct{} // closed and replaced whenever a relay connects
	wg        sync.WaitGroup
}

func newPool(filter *nip01.SubscriptionFilterGroup, onEvent func(*relayclient.Connection, *nip01.Event), logf func(string, ...any)) *pool {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &pool{
		filter:    filter,
		onEvent:   onEvent,
		logf:      logf,
		running:   map[string]bool{},
		conns:     map[string]*relayclient.Connection{},
		attempted: map[string]bool{},
		connected: make(chan struct{}),
	}
}

// add starts serving relay until ctx ends, unless it already runs.
func (p *pool) add(ctx context.Context, relay string) error {
	u, err := url.Parse(relay)
	if err != nil {
		return fmt.Errorf("invalid relay %q: %w", relay, err)
	}
	key := u.String()
	p.mu.Lock()
	if p.running[key] {
		p.mu.Unlock()
		return nil
	}
	p.running[key] = true
	p.order = append(p.order, key)
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.run(ctx, u)
		p.mu.Lock()
		delete(p.running, key)
		delete(p.attempted, key)
		for i, k := range p.order {
			if k == key {
				p.order = append(p.order[:i], p.order[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
	}()
	return nil
}

// wait blocks until every relay goroutine has returned.
func (p *pool) wait() { p.wg.Wait() }

func (p *pool) run(ctx context.Context, u *url.URL) {
	key := u.String()
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := relayclient.Connect(ctx, u)
		if err != nil {
			// Wake waiters too, so one waiting on this relay sees it failed.
			p.mu.Lock()
			p.attempted[key] = true
			close(p.connected)
			p.connected = make(chan struct{})
			p.mu.Unlock()
			p.logf("relay %s: connect failed: %v", u, err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second
		p.serve(ctx, key, conn)
	}
}

// serve subscribes with SubscribeWithID, whose stream outlives EOSE, and
// dispatches until the connection drops or ctx ends.
func (p *pool) serve(ctx context.Context, key string, conn *relayclient.Connection) {
	defer conn.Close()
	subID := uuid.NewString()
	if !conn.SubscribeWithID(subID, p.filter) {
		return
	}
	events := conn.Events(subID)

	p.mu.Lock()
	p.attempted[key] = true
	p.conns[key] = conn
	close(p.connected)
	p.connected = make(chan struct{})
	p.mu.Unlock()
	p.logf("relay %s: connected", key)
	defer func() {
		p.mu.Lock()
		delete(p.conns, key)
		p.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-conn.Errors():
			if !ok {
				return
			}
			p.logf("relay %s: %v", key, err)
			if errors.Is(err, relayclient.ErrConnectionClosed) {
				return
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			go p.onEvent(conn, ev.Event)
		}
	}
}

// broadcast sends ev to every connected relay and reports how many took it.
func (p *pool) broadcast(ev *nip01.Event) int {
	p.mu.Lock()
	conns := make([]*relayclient.Connection, 0, len(p.conns))
	for _, c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	sent := 0
	for _, c := range conns {
		if c.Send(ev) {
			sent++
		}
	}
	return sent
}

// waitAny blocks until at least one relay is connected.
func (p *pool) waitAny(ctx context.Context) error {
	for {
		p.mu.Lock()
		n, ch := len(p.conns), p.connected
		p.mu.Unlock()
		if n > 0 {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// conn returns relay's live connection, waiting up to timeout for it. A
// relay whose latest dial attempt failed is reported down at once.
func (p *pool) conn(ctx context.Context, relay string, timeout time.Duration) (*relayclient.Connection, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		c, ok := p.conns[relay]
		failed := !ok && p.attempted[relay]
		ch := p.connected
		p.mu.Unlock()
		if ok {
			return c, nil
		}
		if failed {
			return nil, fmt.Errorf("relay %s is unreachable", relay)
		}
		select {
		case <-ch:
		case <-deadline.C:
			return nil, fmt.Errorf("timed out connecting to relay %s", relay)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// sendTo sends ev on each of relays, adding any the pool isn't serving
// for the rest of life's span. A relay that doesn't come up within
// adhocDialTimeout is dropped again, so a dead host named only by a
// pairing URI isn't retried forever. Relays are tried concurrently, so
// the fastest one delivers first.
func (p *pool) sendTo(ctx, life context.Context, relays []string, ev *nip01.Event) (sent int, tried []string) {
	seen := map[string]bool{}
	results := make(chan bool, len(relays))
	pending := 0
	for _, raw := range relays {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		key := u.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		tried = append(tried, key)
		pending++
		go func() {
			p.mu.Lock()
			known := p.running[key]
			p.mu.Unlock()
			var stop context.CancelFunc
			if !known {
				var adhoc context.Context
				adhoc, stop = context.WithCancel(life)
				_ = p.add(adhoc, key)
			}
			c, err := p.conn(ctx, key, adhocDialTimeout)
			if err != nil {
				if stop != nil {
					stop()
				}
				p.logf("relay %s: %v", key, err)
				results <- false
				return
			}
			if stop != nil {
				// A relay that came up stays for life's span.
				context.AfterFunc(life, stop)
			}
			results <- c.Send(ev)
		}()
	}
	for range pending {
		if <-results {
			sent++
		}
	}
	return sent, tried
}

// statuses reports every relay the pool has been asked to serve, in order.
func (p *pool) statuses() []RelayStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]RelayStatus, 0, len(p.order))
	for _, key := range p.order {
		_, connected := p.conns[key]
		out = append(out, RelayStatus{URL: key, Connected: connected, Connecting: !connected && !p.attempted[key]})
	}
	return out
}
