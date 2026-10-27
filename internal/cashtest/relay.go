package cashtest

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
	"github.com/ohstr/nmilat/wire"
)

// Relay is an in-process NIP-01 websocket relay with fault hooks.
//
// It stores regular and replaceable events (the newest per author and kind for
// kinds 10000-19999), never ephemeral ones (20000-29999), answers REQ with the
// stored matches then EOSE, and delivers every accepted event to the live
// subscriptions it matches. The hooks act on that delivery, deterministically:
// Drop withholds an event from subscribers, Duplicate delivers it twice (to
// subscribers and OnEvent listeners alike), Reorder
// holds deliveries and releases them in reverse, RefuseFrom answers a publish
// OK false.
type Relay struct {
	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	stored    []*nip01.Event
	conns     map[*relayConn]struct{}
	accepted  []*nip01.Event
	listeners []func(*Relay, *nip01.Event)

	drop, duplicate, refuse func(*nip01.Event) bool
	reorder                 int
	held                    []*nip01.Event

	minPow  int
	powSeen map[string]int64
	powNow  func() time.Time
}

type relayConn struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
	subsMu  sync.Mutex
	subs    map[string]*nip01.SubscriptionFilterGroup
}

func (c *relayConn) write(v json.Marshaler) bool {
	b, err := v.MarshalJSON()
	if err != nil {
		return false
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteMessage(websocket.TextMessage, b) == nil
}

// NewRelay starts a relay, closed when the test ends.
func NewRelay(t testing.TB) *Relay {
	t.Helper()
	r := &Relay{t: t, conns: map[*relayConn]struct{}{}}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

// URL is the relay's ws:// address.
func (r *Relay) URL() string { return "ws" + strings.TrimPrefix(r.srv.URL, "http") }

// Drop withholds from subscribers every accepted event f matches (nil: none).
// The event is still accepted and still reaches OnEvent listeners.
func (r *Relay) Drop(f func(*nip01.Event) bool) { r.mu.Lock(); r.drop = f; r.mu.Unlock() }

// Duplicate delivers every event f matches twice to each subscriber and to each
// OnEvent listener, as a relay that hands a Hub one request twice would.
func (r *Relay) Duplicate(f func(*nip01.Event) bool) { r.mu.Lock(); r.duplicate = f; r.mu.Unlock() }

// Reorder holds deliveries until n are held, then releases them newest first.
// 0 or 1 delivers in order. Events still held when the test ends are never sent.
func (r *Relay) Reorder(n int) { r.mu.Lock(); r.reorder = n; r.mu.Unlock() }

// RefuseFrom refuses every publish f matches with OK false: the event is not
// stored, not delivered and not seen by listeners.
func (r *Relay) RefuseFrom(f func(*nip01.Event) bool) { r.mu.Lock(); r.refuse = f; r.mu.Unlock() }

// OnEvent registers f to be called, in its own goroutine, with every event the
// relay accepts. A fake Hub listens on its inbox relays this way.
func (r *Relay) OnEvent(f func(*Relay, *nip01.Event)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, f)
}

// Accepted returns every event the relay accepted, in order.
func (r *Relay) Accepted() []*nip01.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*nip01.Event(nil), r.accepted...)
}

// Publish offers ev to the relay as a client publish would, and reports whether it
// was accepted, with the refusal message otherwise.
func (r *Relay) Publish(ev *nip01.Event) (bool, string) {
	r.mu.Lock()
	if r.refuse != nil && r.refuse(ev) {
		r.mu.Unlock()
		return false, "blocked: refused by test"
	}
	if msg := r.powRefusalLocked(ev); msg != "" {
		r.mu.Unlock()
		return false, msg
	}
	r.accepted = append(r.accepted, ev)
	switch k := ev.Kind; {
	case k >= 20000 && k < 30000:
	case k >= 10000 && k < 20000:
		kept := r.stored[:0]
		for _, old := range r.stored {
			if old.Kind != k || old.PubKey != ev.PubKey {
				kept = append(kept, old)
			}
		}
		r.stored = append(kept, ev)
	default:
		r.stored = append(r.stored, ev)
	}
	listeners := make([]func(*Relay, *nip01.Event), len(r.listeners))
	copy(listeners, r.listeners)
	copies := 1
	if r.duplicate != nil && r.duplicate(ev) {
		copies = 2
	}
	deliveries := r.queueLocked(ev)
	conns := make([]*relayConn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	for _, d := range deliveries {
		for _, c := range conns {
			c.deliver(d)
		}
	}
	for _, f := range listeners {
		for range copies {
			go f(r, ev)
		}
	}
	return true, ""
}

// queueLocked applies the delivery hooks to one accepted event and returns what
// to deliver now.
func (r *Relay) queueLocked(ev *nip01.Event) []*nip01.Event {
	if r.drop != nil && r.drop(ev) {
		return nil
	}
	out := []*nip01.Event{ev}
	if r.duplicate != nil && r.duplicate(ev) {
		out = append(out, ev)
	}
	if r.reorder <= 1 {
		return out
	}
	r.held = append(r.held, out...)
	if len(r.held) < r.reorder {
		return nil
	}
	released := make([]*nip01.Event, 0, len(r.held))
	for i := len(r.held) - 1; i >= 0; i-- {
		released = append(released, r.held[i])
	}
	r.held = nil
	return released
}

func (c *relayConn) deliver(ev *nip01.Event) {
	c.subsMu.Lock()
	var ids []string
	for id, f := range c.subs {
		if f.Match(ev) {
			ids = append(ids, id)
		}
	}
	c.subsMu.Unlock()
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	for _, id := range ids {
		c.write(&wire.EventSubscriptionResponse{SubscriptionID: id, EventBytes: b})
	}
}

func (r *Relay) serve(w http.ResponseWriter, req *http.Request) {
	if r.serveNIP11(w, req) {
		return
	}
	upgrader := websocket.Upgrader{}
	ws, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	c := &relayConn{ws: ws, subs: map[string]*nip01.SubscriptionFilterGroup{}}
	r.mu.Lock()
	r.conns[c] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.conns, c)
		r.mu.Unlock()
		_ = ws.Close()
	}()

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var payload wire.RelayPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		switch p := payload.Packet.(type) {
		case *wire.RequestPacket:
			r.mu.Lock()
			var matches []*nip01.Event
			for _, ev := range r.stored {
				if p.Filters.Match(ev) {
					matches = append(matches, ev)
				}
			}
			r.mu.Unlock()
			// Registered before the stored events are sent, so nothing published in
			// between is missed; EOSE then says the subscription is live.
			c.subsMu.Lock()
			c.subs[p.SubscriptionID] = p.Filters
			c.subsMu.Unlock()
			for _, ev := range matches {
				b, err := json.Marshal(ev)
				if err != nil {
					continue
				}
				c.write(&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: b})
			}
			c.write(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
		case *wire.ClosePacket:
			c.subsMu.Lock()
			delete(c.subs, p.SubscriptionID)
			c.subsMu.Unlock()
		case *wire.EventPacket:
			if p.Event == nil {
				continue
			}
			if err := p.Event.Verify(nip01.WithoutPowCheck()); err != nil {
				c.write(&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: false, Message: "invalid: " + err.Error()})
				continue
			}
			ok, msg := r.Publish(p.Event)
			c.write(&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: ok, Message: msg})
		}
	}
}
