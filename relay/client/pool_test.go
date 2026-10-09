package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/wire"
)

// startRealRelay serves an in-process nmilat relay capping queries at
// maxLimit events.
func startRealRelay(t *testing.T, maxLimit int) (*url.URL, *httptest.Server) {
	t.Helper()
	f, err := os.CreateTemp("", "pool-relay-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	rl, err := relay.New(f.Name(), &nip11.Metadata{Name: "test", Limitation: nip11.Limitation{MaxLimit: maxLimit, MaxMessageLength: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rl)
	t.Cleanup(func() {
		srv.Close()
		_ = rl.Close()
	})
	u, _ := url.Parse("ws" + srv.URL[len("http"):])
	return u, srv
}

func publish(t *testing.T, u *url.URL, events ...*nip01.Event) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Connect(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, ev := range events {
		ok, err := conn.Publish(ctx, ev)
		if err != nil || !ok.Accepted {
			t.Fatalf("publish %s: %+v %v", ev.ID, ok, err)
		}
	}
}

func signedNote(t *testing.T, kind int, at uint64, content string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: kind, CreatedAt: at, Content: content, Tags: [][]string{}}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	return ev
}

type eventLog struct {
	mu  sync.Mutex
	ids []string
}

func (l *eventLog) add(_ *Connection, ev *nip01.Event) {
	l.mu.Lock()
	l.ids = append(l.ids, ev.ID)
	l.mu.Unlock()
}

func (l *eventLog) count(id string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, x := range l.ids {
		if x == id {
			n++
		}
	}
	return n
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func kindFilter(kind int) *nip01.SubscriptionFilterGroup {
	return nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{kind}})
}

func TestPoolDeliversFromEveryRelay(t *testing.T) {
	a, _ := startRealRelay(t, 100)
	b, _ := startRealRelay(t, 100)
	var log eventLog
	p, err := NewPool(PoolConfig{Filter: kindFilter(1), OnEvent: log.add})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_ = p.Add(ctx, a.String())
	_ = p.Add(ctx, b.String())
	_ = p.Add(ctx, a.String()) // duplicate: ignored
	if err := p.WaitAny(ctx); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "both relays connected", func() bool {
		st := p.Statuses()
		return len(st) == 2 && st[0].Connected && st[1].Connected
	})

	onA := signedNote(t, 1, uint64(time.Now().Unix()), "on a")
	onB := signedNote(t, 1, uint64(time.Now().Unix()), "on b")
	publish(t, a, onA)
	publish(t, b, onB)
	waitUntil(t, "events from both relays", func() bool { return log.count(onA.ID) == 1 && log.count(onB.ID) == 1 })

	cancel()
	p.Wait()
	if st := p.Statuses(); len(st) != 0 {
		t.Errorf("statuses after stop = %+v", st)
	}
}

// cutProxy forwards TCP to target until cut drops every connection, the
// way a network blip would. httptest can't: it stops tracking a
// connection once the websocket upgrade hijacks it.
type cutProxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newCutProxy(t *testing.T, target string) *cutProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close(); p.cut() })
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, in, out)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
		}
	}()
	return p
}

func (p *cutProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func TestPoolReconnectsAndResubscribes(t *testing.T) {
	u, _ := startRealRelay(t, 100)
	proxy := newCutProxy(t, u.Host)
	via := &url.URL{Scheme: "ws", Host: proxy.ln.Addr().String()}
	var log eventLog
	var connects atomic.Int32
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), OnEvent: log.add, Logf: func(format string, args ...any) {
		if format == "relay %s: connected" {
			connects.Add(1)
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, via.String())
	waitUntil(t, "first connect", func() bool { return connects.Load() == 1 })

	proxy.cut()
	waitUntil(t, "reconnect", func() bool { return connects.Load() >= 2 && p.Statuses()[0].Connected })

	ev := signedNote(t, 1, uint64(time.Now().Unix()), "after reconnect")
	publish(t, u, ev)
	waitUntil(t, "event after reconnect", func() bool { return log.count(ev.ID) >= 1 })
}

func TestPoolResyncAndDedupe(t *testing.T) {
	u, _ := startRealRelay(t, 100)
	stored := signedNote(t, 1, uint64(time.Now().Unix())-60, "stored")
	publish(t, u, stored)

	for _, dedupe := range []bool{false, true} {
		t.Run(fmt.Sprintf("dedupe=%v", dedupe), func(t *testing.T) {
			var log eventLog
			p, _ := NewPool(PoolConfig{Filter: kindFilter(1), OnEvent: log.add, ResyncInterval: 100 * time.Millisecond, Dedupe: dedupe})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_ = p.Add(ctx, u.String())
			waitUntil(t, "stored event", func() bool { return log.count(stored.ID) >= 1 })
			time.Sleep(450 * time.Millisecond) // a few resyncs
			got := log.count(stored.ID)
			if dedupe && got != 1 {
				t.Errorf("seen %d times with Dedupe, want 1", got)
			}
			if !dedupe && got < 2 {
				t.Errorf("seen %d times without Dedupe, want a resync to resend it", got)
			}
		})
	}
}

func TestPoolSendToAndConn(t *testing.T) {
	served, _ := startRealRelay(t, 100)
	other, _ := startRealRelay(t, 100)
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, served.String())
	if err := p.WaitAny(ctx); err != nil {
		t.Fatal(err)
	}

	ev := signedNote(t, 1, uint64(time.Now().Unix()), "send to")
	sent, tried := p.SendTo(ctx, ctx, []string{served.String(), other.String(), other.String(), "ws://127.0.0.1:1"}, ev)
	if sent != 2 || len(tried) != 3 {
		t.Fatalf("sent %d tried %v, want 2 of 3", sent, tried)
	}
	waitUntil(t, "dead ad-hoc relay dropped", func() bool { return len(p.Statuses()) == 2 })

	// SendTo only queues the event; poll until the relay has stored it.
	waitUntil(t, "event on the ad-hoc relay", func() bool {
		readCtx, readCancel := context.WithTimeout(ctx, time.Second)
		defer readCancel()
		got, err := ReadEventsFromRelay(readCtx, other, kindFilter(1))
		return err == nil && len(got) == 1 && got[0].ID == ev.ID
	})
	if n := p.Broadcast(signedNote(t, 1, uint64(time.Now().Unix()), "broadcast")); n != 2 {
		t.Errorf("Broadcast reached %d relays, want 2", n)
	}
	if _, err := p.Conn(ctx, "ws://never-added.example", 50*time.Millisecond); err == nil {
		t.Error("Conn to a relay the pool doesn't serve succeeded")
	}
}

func TestPoolSignsAuth(t *testing.T) {
	signer := &remoteSigner{key: testPrivKey}
	server := newAuthChallengeServer(t, "pool-challenge", 2*time.Second, func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse {
		return &wire.OkSubscriptionResponse{EventID: ap.Event.ID, Accepted: true}
	})
	p, _ := NewPool(PoolConfig{Filter: kindFilter(1), Signer: signer})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = p.Add(ctx, dialURL(t, server).String())
	waitUntil(t, "AUTH signed through the pool", func() bool { return signer.calls.Load() >= 1 })
}

func TestNewPoolNeedsFilter(t *testing.T) {
	if _, err := NewPool(PoolConfig{}); err == nil {
		t.Error("NewPool without a filter succeeded")
	}
}

func TestIDSetForgetsOldest(t *testing.T) {
	s := newIDSet(2)
	if !s.add("a") || !s.add("b") || s.add("a") {
		t.Fatal("basic add")
	}
	s.add("c") // evicts a
	if !s.add("a") {
		t.Error("a should have been forgotten")
	}
	if s.add("c") {
		t.Error("c should still be remembered")
	}
}

func TestReadAllEventsFromRelayPagesThroughTies(t *testing.T) {
	u, _ := startRealRelay(t, 50)
	base := uint64(time.Now().Unix()) - 3600
	var all []*nip01.Event
	for i := range 120 { // more same-second events than one page holds
		all = append(all, signedNote(t, 1, base, fmt.Sprintf("tie %d", i)))
	}
	for i := range 110 {
		all = append(all, signedNote(t, 1, base+1+uint64(i), fmt.Sprintf("spread %d", i)))
	}
	all = append(all, signedNote(t, 7, base, "other kind"))
	publish(t, u, all...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, restricted, err := ReadAllEventsFromRelay(ctx, u, &nip01.SubscriptionFilter{Kinds: []int{1}}, 100, nil)
	if err != nil || restricted {
		t.Fatalf("err %v restricted %v", err, restricted)
	}
	if len(got) != 230 || len(uniqueIDs(got)) != 230 {
		t.Fatalf("read %d events (%d unique), want 230", len(got), len(uniqueIDs(got)))
	}

	capped, _, err := ReadAllEventsFromRelay(ctx, u, &nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 70}, 30, nil)
	if err != nil || len(capped) != 70 {
		t.Fatalf("capped read %d, %v; want 70", len(capped), err)
	}
}

func uniqueIDs(evs []*nip01.Event) map[string]bool {
	m := map[string]bool{}
	for _, e := range evs {
		m[e.ID] = true
	}
	return m
}

// newPlainRelay answers REQs from events honoring only kinds, until and
// limit: no BeforeID, like most relays.
func newPlainRelay(t *testing.T, events []*nip01.Event) *url.URL {
	t.Helper()
	sorted := append([]*nip01.Event(nil), events...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt != sorted[j].CreatedAt {
			return sorted[i].CreatedAt > sorted[j].CreatedAt
		}
		return sorted[i].ID < sorted[j].ID
	})
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if json.Unmarshal(data, &payload) != nil {
				continue
			}
			req, ok := payload.Packet.(*wire.RequestPacket)
			if !ok {
				continue
			}
			f := req.Filters.GetAll()[0]
			sent := 0
			for _, ev := range sorted {
				if f.Until > 0 && ev.CreatedAt > f.Until {
					continue
				}
				if f.Limit > 0 && sent >= f.Limit {
					break
				}
				b, _ := (&wire.EventSubscriptionResponse{SubscriptionID: req.SubscriptionID, Event: ev}).MarshalJSON()
				_ = conn.WriteMessage(websocket.TextMessage, b)
				sent++
			}
			b, _ := (&wire.EOSESubscriptionResponse{SubscriptionID: req.SubscriptionID}).MarshalJSON()
			_ = conn.WriteMessage(websocket.TextMessage, b)
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse("ws" + srv.URL[len("http"):])
	return u
}

// On a relay without BeforeID, a page of nothing new steps until back a
// second rather than looping, and the read still ends.
func TestReadAllEventsFromRelayWithoutBeforeID(t *testing.T) {
	var events []*nip01.Event
	for i := range 12 {
		events = append(events, signedNote(t, 1, 1000, fmt.Sprintf("tie %d", i)))
	}
	for i := range 5 {
		events = append(events, signedNote(t, 1, 900-uint64(i), fmt.Sprintf("older %d", i)))
	}
	u := newPlainRelay(t, events)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, _, err := ReadAllEventsFromRelay(ctx, u, &nip01.SubscriptionFilter{Kinds: []int{1}}, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := uniqueIDs(got)
	if len(ids) != len(got) {
		t.Error("duplicates returned")
	}
	// The first page holds 5 of the 12 ties; the rest of that second is
	// skipped, as documented, and every older event is still read.
	for _, ev := range events[12:] {
		if !ids[ev.ID] {
			t.Errorf("older event %q missing", ev.Content)
		}
	}
	if len(got) != 10 {
		t.Errorf("read %d events, want 5 ties + 5 older", len(got))
	}
}
