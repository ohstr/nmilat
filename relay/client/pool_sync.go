package client

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

// serve keeps the pool's subscription alive on conn until the connection
// drops or ctx ends. With a Signer it first waits for AUTH to settle. Each
// sync round opens a live subscription and pages every filter's stored
// events to the end; a round the relay closes is retried with backoff, or
// as soon as AUTH succeeds when the relay asked for it.
func (p *Pool) serve(ctx context.Context, key string, conn *Connection) {
	defer conn.Close()

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

	if p.cfg.Signer != nil && !p.waitAuth(ctx, key, conn) {
		return
	}

	s := &poolSync{p: p, conn: conn}
	if !s.start(true) {
		return
	}
	if s.idle() {
		p.synced(key)
	}

	var resync <-chan time.Time
	if p.cfg.ResyncInterval > 0 {
		t := time.NewTicker(p.cfg.ResyncInterval)
		defer t.Stop()
		resync = t.C
	}
	backoff := time.Second
	var retry <-chan time.Time
	var authed <-chan struct{}

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
			if s.idle() && retry == nil && authed == nil {
				if !s.start(false) {
					return
				}
				if s.idle() {
					p.synced(key)
				}
			}
		case <-retry:
			retry, authed = nil, nil
			if !s.start(true) {
				return
			}
		case <-authed:
			retry, authed = nil, nil
			if !s.start(true) {
				return
			}
		case msg, ok := <-conn.Read():
			if !ok {
				return
			}
			switch m := msg.(type) {
			case *wire.EventSubscriptionResponse:
				s.event(m)
			case *wire.EOSESubscriptionResponse:
				complete, ok := s.eose(m.SubscriptionID)
				if !ok {
					return
				}
				if complete {
					p.synced(key)
					backoff = time.Second
				}
			case *wire.ClosedSubscriptionResponse:
				if !s.closed(m.SubscriptionID) {
					continue
				}
				p.setClosed(key, m.Message)
				p.cfg.Logf("relay %s: subscription closed: %s", key, m.Message)
				if p.cfg.Signer != nil && authGated(m.Message) && conn.AuthState() == AuthStateNone {
					authed = conn.AuthSettled()
				}
				retry = time.After(backoff)
				backoff = min(backoff*2, poolMaxBackoff)
			}
		}
	}
}

// waitAuth waits up to AuthWait for conn's NIP-42 handshake. It reports
// false if the connection or ctx ended first.
func (p *Pool) waitAuth(ctx context.Context, key string, conn *Connection) bool {
	t := time.NewTimer(p.cfg.AuthWait)
	defer t.Stop()
	select {
	case <-conn.AuthSettled():
		if conn.AuthState() == AuthStateFailed {
			p.cfg.Logf("relay %s: auth failed: %s", key, conn.AuthMessage())
		}
	case <-t.C:
	case <-ctx.Done():
		return false
	case <-conn.Closed():
		return false
	}
	return true
}

// deliver hands ev to OnEvent unless Dedupe has seen it.
func (p *Pool) deliver(conn *Connection, ev *nip01.Event) {
	if p.seen != nil && !p.seen.add(ev.ID) {
		return
	}
	go p.cfg.OnEvent(conn, ev)
}

// synced records a complete sync of relay key.
func (p *Pool) synced(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rs := p.state[key]; rs != nil {
		rs.lastEOSE, rs.closed = time.Now(), ""
	}
}

// setClosed records the relay's reason for closing the pool's subscription.
func (p *Pool) setClosed(key, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rs := p.state[key]; rs != nil {
		rs.closed = msg
	}
}

// authGated reports whether a CLOSED message refuses for want of AUTH.
func authGated(msg string) bool {
	return strings.HasPrefix(msg, restrictedClosePrefix) || strings.HasPrefix(msg, authRequiredClosePrefix)
}

// poolSync is one connection's subscriptions: a live one, and one page at
// a time of the current sync round, walking the filters in order.
type poolSync struct {
	p      *Pool
	conn   *Connection
	liveID string
	pagers []*pager
	pageID string
	buf    []*nip01.Event
}

// start begins a sync round, reopening the live subscription when withLive
// is set or none is open. It reports false once the connection is gone.
func (s *poolSync) start(withLive bool) bool {
	filters := s.p.cfg.Filter.GetAll()
	if withLive || s.liveID == "" {
		if s.liveID != "" {
			s.conn.CloseSubscription(s.liveID)
		}
		// Stored events come from the pages; limit 1 keeps the live
		// subscription's initial answer small without narrowing what
		// arrives later.
		live := nip01.NewSubscriptionFilterGroup()
		for _, f := range filters {
			c := *f
			c.Limit, c.BeforeID = 1, ""
			live.Add(&c)
		}
		s.liveID = uuid.NewString()
		if !s.conn.SubscribeWithID(s.liveID, live) {
			return false
		}
	}

	now := uint64(time.Now().Unix())
	s.pagers = s.pagers[:0]
	for _, f := range filters {
		c := *f
		if c.Until == 0 || c.Until > now {
			c.Until = now
		}
		s.pagers = append(s.pagers, newPager(&c, s.p.cfg.PageSize))
	}
	return s.nextPage()
}

// nextPage requests the next page, moving through the filters in order.
// When none remain the round is complete and idle reports true.
func (s *poolSync) nextPage() bool {
	s.pageID = ""
	for len(s.pagers) > 0 {
		if f := s.pagers[0].next(); f != nil {
			s.pageID, s.buf = uuid.NewString(), s.buf[:0]
			return s.conn.SubscribeWithID(s.pageID, nip01.NewSubscriptionFilterGroup(f))
		}
		s.pagers = s.pagers[1:]
	}
	return true
}

// idle reports whether no sync round is in progress.
func (s *poolSync) idle() bool { return s.pageID == "" }

func (s *poolSync) event(m *wire.EventSubscriptionResponse) {
	switch m.SubscriptionID {
	case "":
	case s.pageID:
		s.buf = append(s.buf, m.Event)
	case s.liveID:
		s.p.deliver(s.conn, m.Event)
	}
}

// eose finishes the current page and requests the next. complete reports
// that this EOSE ended the round; ok is false once the connection is gone.
func (s *poolSync) eose(id string) (complete, ok bool) {
	if id == "" || id != s.pageID {
		return false, true
	}
	// After EOSE the relay keeps a REQ open for new events; the live
	// subscription already covers those.
	s.conn.CloseSubscription(id)
	for _, ev := range s.pagers[0].feed(s.buf) {
		s.p.deliver(s.conn, ev)
	}
	if !s.nextPage() {
		return false, false
	}
	return s.idle(), true
}

// closed reports whether id was one of this connection's subscriptions
// and, if so, drops the whole round so it can be retried.
func (s *poolSync) closed(id string) bool {
	if id == "" || (id != s.pageID && id != s.liveID) {
		return false
	}
	if s.pageID != "" && s.pageID != id {
		s.conn.CloseSubscription(s.pageID)
	}
	if s.liveID != "" && s.liveID != id {
		s.conn.CloseSubscription(s.liveID)
	}
	s.pageID, s.liveID, s.pagers = "", "", nil
	return true
}
