package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
)

const (
	poolMaxBackoff = 30 * time.Second
	// poolAdhocTimeout bounds waiting for a relay SendTo had to add.
	poolAdhocTimeout = 5 * time.Second
	// defaultDedupeSize is how many recent event ids Dedupe remembers.
	defaultDedupeSize = 50_000
)

// PoolConfig configures a Pool.
type PoolConfig struct {
	// Filter is the subscription every relay serves. Required.
	Filter *nip01.SubscriptionFilterGroup
	// OnEvent receives each event, on its own goroutine, with the
	// connection it arrived on (to reply on the same relay).
	OnEvent func(conn *Connection, ev *nip01.Event)

	// Signer answers NIP-42 AUTH on every connection.
	Signer Signer
	// ResyncInterval, when positive, re-sends the subscription that often,
	// so stored events missed while a relay was slow or a connection
	// half-dead come back. Without Dedupe, OnEvent sees them again.
	ResyncInterval time.Duration
	// Dedupe drops events whose id OnEvent has recently seen, from any
	// relay or resync. DedupeSize bounds the memory; 0 means 50,000 ids.
	Dedupe     bool
	DedupeSize int

	// Logf receives connection messages.
	Logf func(format string, args ...any)
}

// RelayStatus is whether one relay currently has a live connection.
type RelayStatus struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
	// Connecting is true until the relay's first dial attempt resolves.
	Connecting bool `json:"connecting,omitempty"`
}

// Pool keeps one subscribed connection per relay, reconnecting with
// backoff (1s doubling to 30s) and re-subscribing after each reconnect.
// Safe for concurrent use.
type Pool struct {
	cfg  PoolConfig
	seen *idSet

	mu        sync.Mutex
	order     []string
	running   map[string]bool
	conns     map[string]*Connection
	attempted map[string]bool
	changed   chan struct{} // closed and replaced on every connect or failed dial
	wg        sync.WaitGroup
}

// NewPool validates cfg and returns an idle Pool; Add starts relays.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Filter == nil {
		return nil, errors.New("pool: PoolConfig.Filter is required")
	}
	if cfg.OnEvent == nil {
		cfg.OnEvent = func(*Connection, *nip01.Event) {}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	p := &Pool{
		cfg:       cfg,
		running:   map[string]bool{},
		conns:     map[string]*Connection{},
		attempted: map[string]bool{},
		changed:   make(chan struct{}),
	}
	if cfg.Dedupe {
		size := cfg.DedupeSize
		if size <= 0 {
			size = defaultDedupeSize
		}
		p.seen = newIDSet(size)
	}
	return p, nil
}

// Add serves relay until ctx ends, unless the pool already serves it.
func (p *Pool) Add(ctx context.Context, relay string) error {
	u, err := url.Parse(relay)
	if err != nil {
		return fmt.Errorf("pool: invalid relay %q: %w", relay, err)
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

// Wait blocks until every relay's context has ended and its goroutine
// returned.
func (p *Pool) Wait() { p.wg.Wait() }

// signal wakes everyone waiting on a connection change. Callers hold p.mu.
func (p *Pool) signal() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool) run(ctx context.Context, u *url.URL) {
	key := u.String()
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := NewConnection(ctx, u, &ConnectionConfig{Signer: p.cfg.Signer})
		if err != nil {
			p.mu.Lock()
			p.attempted[key] = true
			p.signal()
			p.mu.Unlock()
			p.cfg.Logf("relay %s: connect failed: %v", u, err)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, poolMaxBackoff)
			continue
		}
		backoff = time.Second
		p.serve(ctx, key, conn)
	}
}

// serve subscribes with SubscribeWithID, whose stream outlives EOSE, and
// dispatches until the connection drops or ctx ends. Every subscription
// on the connection is the pool's, so one Events("") reader serves them
// across resyncs.
func (p *Pool) serve(ctx context.Context, key string, conn *Connection) {
	defer conn.Close()
	subID := uuid.NewString()
	if !conn.SubscribeWithID(subID, p.cfg.Filter) {
		return
	}
	events := conn.Events("")

	p.mu.Lock()
	p.attempted[key] = true
	p.conns[key] = conn
	p.signal()
	p.mu.Unlock()
	p.cfg.Logf("relay %s: connected", key)
	defer func() {
		p.mu.Lock()
		delete(p.conns, key)
		p.mu.Unlock()
	}()

	var resync <-chan time.Time
	if p.cfg.ResyncInterval > 0 {
		t := time.NewTicker(p.cfg.ResyncInterval)
		defer t.Stop()
		resync = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.Closed():
			return
		case err, ok := <-conn.Errors():
			if !ok {
				return
			}
			p.cfg.Logf("relay %s: %v", key, err)
			if errors.Is(err, ErrConnectionClosed) {
				return
			}
		case <-resync:
			conn.CloseSubscription(subID)
			subID = uuid.NewString()
			if !conn.SubscribeWithID(subID, p.cfg.Filter) {
				return
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			if p.seen != nil && !p.seen.add(ev.Event.ID) {
				continue
			}
			go p.cfg.OnEvent(conn, ev.Event)
		}
	}
}

// Broadcast sends ev to every connected relay and reports how many took it.
func (p *Pool) Broadcast(ev *nip01.Event) int {
	p.mu.Lock()
	conns := make([]*Connection, 0, len(p.conns))
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

// WaitAny blocks until at least one relay is connected.
func (p *Pool) WaitAny(ctx context.Context) error {
	for {
		p.mu.Lock()
		n, ch := len(p.conns), p.changed
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

// Conn returns relay's live connection, waiting up to timeout for it. A
// relay whose latest dial attempt failed is reported down at once.
func (p *Pool) Conn(ctx context.Context, relay string, timeout time.Duration) (*Connection, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		p.mu.Lock()
		c, ok := p.conns[relay]
		failed := !ok && p.attempted[relay]
		ch := p.changed
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

// SendTo sends ev on each of relays, concurrently. A relay the pool isn't
// serving is added for life's span; one that doesn't come up within 5s is
// dropped again, so a dead host isn't retried forever. It reports how many
// relays took ev and which it tried.
func (p *Pool) SendTo(ctx, life context.Context, relays []string, ev *nip01.Event) (sent int, tried []string) {
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
				_ = p.Add(adhoc, key)
			}
			c, err := p.Conn(ctx, key, poolAdhocTimeout)
			if err != nil {
				if stop != nil {
					stop()
				}
				p.cfg.Logf("relay %s: %v", key, err)
				results <- false
				return
			}
			if stop != nil {
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

// Statuses reports every relay the pool serves, in the order added.
func (p *Pool) Statuses() []RelayStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]RelayStatus, 0, len(p.order))
	for _, key := range p.order {
		_, connected := p.conns[key]
		out = append(out, RelayStatus{URL: key, Connected: connected, Connecting: !connected && !p.attempted[key]})
	}
	return out
}

// idSet remembers the last size ids added.
type idSet struct {
	mu   sync.Mutex
	set  map[string]struct{}
	ring []string
	next int
}

func newIDSet(size int) *idSet {
	return &idSet{set: make(map[string]struct{}, size), ring: make([]string, size)}
}

// add records id and reports whether it was new.
func (s *idSet) add(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[id]; ok {
		return false
	}
	if old := s.ring[s.next]; old != "" {
		delete(s.set, old)
	}
	s.ring[s.next] = id
	s.set[id] = struct{}{}
	s.next = (s.next + 1) % len(s.ring)
	return true
}
