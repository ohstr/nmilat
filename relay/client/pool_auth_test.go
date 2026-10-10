package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/wire"
)

// authRelay is a fake relay that serves nothing until NIP-42 AUTH
// succeeds, caps every query at maxLimit and ignores BeforeID, like most
// relays. It challenges on connect, or only when a REQ arrives before
// AUTH, and accepts an AUTH after authDelay (or rejects it with reject).
type authRelay struct {
	t                  *testing.T
	maxLimit           int
	challengeOnConnect bool
	authDelay          time.Duration
	reject             bool
	// open serves without AUTH and never challenges.
	open bool
	// eoseBeforeAuth answers a REQ before AUTH with an empty EOSE instead
	// of a CLOSED.
	eoseBeforeAuth bool

	mu            sync.Mutex
	events        []*nip01.Event // newest first
	authedAt      time.Time
	reqBeforeAuth int
	live          map[*authRelayConn]map[string]*nip01.SubscriptionFilterGroup
}

type authRelayConn struct {
	mu sync.Mutex
	ws *websocket.Conn
}

func (c *authRelayConn) send(m json.Marshaler) {
	b, err := m.MarshalJSON()
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.WriteMessage(websocket.TextMessage, b)
}

func newAuthRelay(t *testing.T, r *authRelay, events ...*nip01.Event) *url.URL {
	r.t = t
	r.live = map[*authRelayConn]map[string]*nip01.SubscriptionFilterGroup{}
	r.events = append(r.events, events...)
	sort.Slice(r.events, func(i, j int) bool { return r.events[i].CreatedAt > r.events[j].CreatedAt })

	const challenge = "pool-auth"
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ws, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		c := &authRelayConn{ws: ws}
		r.mu.Lock()
		r.live[c] = map[string]*nip01.SubscriptionFilterGroup{}
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			delete(r.live, c)
			r.mu.Unlock()
		}()

		challenged := r.challengeOnConnect
		if challenged {
			c.send(&wire.AuthChallengeResponse{Challenge: challenge})
		}
		var authed bool
		var authMu sync.Mutex
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				return
			}
			switch p := payload.Packet.(type) {
			case *wire.AuthPacket:
				if err := nip42.ValidateAuthEvent(p.Event.Kind, p.Event.Tags, p.Event.CreatedAt, challenge, "ws://"+req.Host); err != nil {
					t.Errorf("AUTH event: %v", err)
				}
				id := p.Event.ID
				go func() {
					time.Sleep(r.authDelay)
					if r.reject {
						c.send(&wire.OkSubscriptionResponse{EventID: id, Accepted: false, Message: "restricted: not a member"})
						return
					}
					authMu.Lock()
					authed = true
					authMu.Unlock()
					r.mu.Lock()
					r.authedAt = time.Now()
					r.mu.Unlock()
					c.send(&wire.OkSubscriptionResponse{EventID: id, Accepted: true})
				}()
			case *wire.RequestPacket:
				authMu.Lock()
				ok := authed || r.open
				authMu.Unlock()
				if !ok {
					r.mu.Lock()
					r.reqBeforeAuth++
					r.mu.Unlock()
					if !challenged {
						challenged = true
						c.send(&wire.AuthChallengeResponse{Challenge: challenge})
					}
					if r.eoseBeforeAuth {
						c.send(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
					} else {
						c.send(&wire.ClosedSubscriptionResponse{SubscriptionID: p.SubscriptionID, Message: "auth-required: sign in first"})
					}
					continue
				}
				for _, ev := range r.query(p.Filters) {
					b, _ := json.Marshal(ev)
					c.send(&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: b})
				}
				c.send(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
				r.mu.Lock()
				r.live[c][p.SubscriptionID] = p.Filters
				r.mu.Unlock()
			case *wire.ClosePacket:
				r.mu.Lock()
				delete(r.live[c], p.SubscriptionID)
				r.mu.Unlock()
			}
		}
	}))
	t.Cleanup(srv.Close)
	return dialURL(t, srv)
}

// query answers each filter newest first, at most maxLimit (or the
// filter's own smaller limit) per filter.
func (r *authRelay) query(g *nip01.SubscriptionFilterGroup) []*nip01.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	var out []*nip01.Event
	for _, f := range g.GetAll() {
		limit := r.maxLimit
		if f.Limit > 0 && f.Limit < limit {
			limit = f.Limit
		}
		n := 0
		for _, ev := range r.events {
			if n == limit {
				break
			}
			if !f.Match(ev) {
				continue
			}
			n++
			if !seen[ev.ID] {
				seen[ev.ID] = true
				out = append(out, ev)
			}
		}
	}
	return out
}

// push stores ev and sends it to every open subscription it matches.
func (r *authRelay) push(ev *nip01.Event) {
	r.mu.Lock()
	r.events = append([]*nip01.Event{ev}, r.events...)
	type target struct {
		c  *authRelayConn
		id string
	}
	var targets []target
	for c, subs := range r.live {
		for id, g := range subs {
			if g.Match(ev) {
				targets = append(targets, target{c, id})
			}
		}
	}
	r.mu.Unlock()
	b, _ := json.Marshal(ev)
	for _, tg := range targets {
		tg.c.send(&wire.EventSubscriptionResponse{SubscriptionID: tg.id, EventBytes: b})
	}
}

func (r *authRelay) state() (authedAt time.Time, reqBeforeAuth int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authedAt, r.reqBeforeAuth
}

// storedNotes signs n kind-1 notes a second apart, the newest a minute ago.
func storedNotes(t *testing.T, n int) []*nip01.Event {
	base := uint64(time.Now().Unix()) - 60
	out := make([]*nip01.Event, n)
	for i := range out {
		out[i] = signedNote(t, 1, base-uint64(i), "stored")
	}
	return out
}

func (l *eventLog) hasAll(evs []*nip01.Event) bool {
	for _, ev := range evs {
		if l.count(ev.ID) == 0 {
			return false
		}
	}
	return true
}

// checkAuthedSync runs a Pool against r and checks that every stored
// event and a live one arrive, and that LastEOSE is only set once AUTH
// succeeded and every page was read.
func checkAuthedSync(t *testing.T, r *authRelay, authWait time.Duration) (reqBeforeAuth int) {
	stored := storedNotes(t, 25)
	u := newAuthRelay(t, r, stored...)
	var log eventLog
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), OnEvent: log.add, Signer: &remoteSigner{key: testPrivKey}, AuthWait: authWait, PageSize: 10, Dedupe: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, u.String())

	var synced time.Time
	waitUntil(t, "a complete sync", func() bool {
		synced = p.Statuses()[0].LastEOSE
		return !synced.IsZero()
	})
	authedAt, before := r.state()
	if authedAt.IsZero() || synced.Before(authedAt) {
		t.Errorf("LastEOSE %v, AUTH accepted at %v: want the sync to end after AUTH", synced, authedAt)
	}
	waitUntil(t, "all 25 stored events, past the 10-event cap", func() bool { return log.hasAll(stored) })
	if st := p.Statuses()[0]; st.Closed != "" {
		t.Errorf("Closed = %q after a complete sync, want it cleared", st.Closed)
	}

	live := signedNote(t, 1, uint64(time.Now().Unix()), "live")
	r.push(live)
	waitUntil(t, "a live event", func() bool { return log.count(live.ID) == 1 })
	return before
}

// The relay challenges on connect: the pool must wait for AUTH instead of
// sending a REQ the relay closes.
func TestPoolWaitsForAuthBeforeSubscribing(t *testing.T) {
	r := &authRelay{maxLimit: 10, challengeOnConnect: true, authDelay: 300 * time.Millisecond}
	if before := checkAuthedSync(t, r, 5*time.Second); before != 0 {
		t.Errorf("%d REQs reached the relay before AUTH, want 0", before)
	}
}

// The relay only challenges when a REQ arrives: the pool must
// re-subscribe once AUTH succeeds.
func TestPoolResubscribesAfterAuthRequiredClose(t *testing.T) {
	r := &authRelay{maxLimit: 10, authDelay: 100 * time.Millisecond}
	if before := checkAuthedSync(t, r, 50*time.Millisecond); before == 0 {
		t.Error("no REQ was closed before AUTH; the test didn't exercise the re-subscribe")
	}
}

// The relay answers a REQ before AUTH with an empty EOSE and challenges
// late: the pool must sync again once AUTH succeeds.
func TestPoolResyncsAfterLateAuth(t *testing.T) {
	r := &authRelay{maxLimit: 10, eoseBeforeAuth: true, authDelay: 100 * time.Millisecond}
	if before := checkAuthedSync(t, r, 5*time.Second); before == 0 {
		t.Error("no REQ was answered before AUTH; the test didn't exercise the late AUTH")
	}
}

// A relay that never challenges: a Signer must not hold the subscription
// back.
func TestPoolWithSignerDoesNotWaitOnRelaysWithoutAuth(t *testing.T) {
	r := &authRelay{maxLimit: 10, open: true}
	u := newAuthRelay(t, r, storedNotes(t, 3)...)
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), Signer: &remoteSigner{key: testPrivKey}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	_ = p.Add(ctx, u.String())
	waitUntil(t, "a complete sync", func() bool { return !p.Statuses()[0].LastEOSE.IsZero() })
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("first sync took %v; the pool waited for an AUTH that never came", took)
	}
}

// Without Dedupe, one sync still hands each stored event on once, though
// the live subscription and the pages both see the newest ones.
func TestPoolDeliversEachStoredEventOncePerSync(t *testing.T) {
	r := &authRelay{maxLimit: 10, open: true}
	stored := storedNotes(t, 5)
	u := newAuthRelay(t, r, stored...)
	var log eventLog
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), OnEvent: log.add})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, u.String())
	waitUntil(t, "a complete sync", func() bool { return !p.Statuses()[0].LastEOSE.IsZero() })
	waitUntil(t, "every stored event", func() bool { return log.hasAll(stored) })
	time.Sleep(200 * time.Millisecond)
	for _, ev := range stored {
		if n := log.count(ev.ID); n != 1 {
			t.Errorf("%s delivered %d times, want 1", ev.Content, n)
		}
	}
}

// A relay that never accepts AUTH: the status shows why, and LastEOSE
// stays unset.
func TestPoolReportsClosedSubscription(t *testing.T) {
	r := &authRelay{maxLimit: 10, challengeOnConnect: true, reject: true}
	u := newAuthRelay(t, r, storedNotes(t, 3)...)
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), Signer: &remoteSigner{key: testPrivKey}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, u.String())

	waitUntil(t, "the closed subscription in the status", func() bool {
		return strings.HasPrefix(p.Statuses()[0].Closed, "auth-required:")
	})
	if st := p.Statuses()[0]; !st.LastEOSE.IsZero() || !st.Connected {
		t.Errorf("status = %+v, want connected with no LastEOSE", st)
	}
}

// Every filter in the group is paged past the relay's cap, and LastEOSE
// survives a reconnect.
func TestPoolPagesEachFilterAndKeepsLastEOSE(t *testing.T) {
	u, _ := startRealRelay(t, 5)
	base := uint64(time.Now().Unix()) - 60
	var stored []*nip01.Event
	for i := range 12 {
		stored = append(stored, signedNote(t, 1, base-uint64(i), "one"), signedNote(t, 7, base-uint64(i), "seven"))
	}
	publish(t, u, stored...)

	proxy := newCutProxy(t, u.Host)
	via := &url.URL{Scheme: "ws", Host: proxy.ln.Addr().String()}
	var log eventLog
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}}, &nip01.SubscriptionFilter{Kinds: []int{7}})
	var p *Pool
	var connects atomic.Int32
	atReconnect := make(chan time.Time, 1)
	// Read LastEOSE as the second connection comes up, before it syncs.
	logf := func(format string, _ ...any) {
		if format == "relay %s: connected" && connects.Add(1) == 2 {
			atReconnect <- p.Statuses()[0].LastEOSE
		}
	}
	p, _ = NewPool(PoolConfig{Filter: filter, OnEvent: log.add, PageSize: 5, Logf: logf})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, via.String())

	waitUntil(t, "all 24 events across both filters", func() bool { return log.hasAll(stored) })
	waitUntil(t, "a complete sync", func() bool { return !p.Statuses()[0].LastEOSE.IsZero() })
	first := p.Statuses()[0].LastEOSE

	proxy.cut()
	select {
	case got := <-atReconnect:
		if !got.Equal(first) {
			t.Errorf("LastEOSE on reconnect = %v, want it kept at %v", got, first)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect")
	}
}
