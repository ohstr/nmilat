package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/wire"
)

// replyRelay is an in-process relay with a hub behind it that answers a request
// only on the relay it arrived on (NIP-CASH §Addressing the Response). refuse
// makes it reject every EVENT, as a relay that will not carry the request does.
type replyRelay struct {
	srv    *httptest.Server
	refuse bool

	mu        sync.Mutex
	subs      map[*websocket.Conn]string
	published int
}

func newReplyRelay(t *testing.T, refuse bool, reply *nip01.Event) *replyRelay {
	t.Helper()
	r := &replyRelay{refuse: refuse, subs: map[*websocket.Conn]string{}}
	upgrader := websocket.Upgrader{}
	var writeMu sync.Mutex
	write := func(conn *websocket.Conn, v json.Marshaler) {
		b, err := v.MarshalJSON()
		if err != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteMessage(websocket.TextMessage, b)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		defer func() {
			r.mu.Lock()
			delete(r.subs, conn)
			r.mu.Unlock()
			_ = conn.Close()
		}()
		for {
			_, data, err := conn.ReadMessage()
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
				r.subs[conn] = p.SubscriptionID
				r.mu.Unlock()
				write(conn, &wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
			case *wire.EventPacket:
				if r.refuse {
					write(conn, &wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: false, Message: "blocked: test"})
					continue
				}
				// Count before the OK, which may return the client's publish at once.
				r.mu.Lock()
				r.published++
				r.mu.Unlock()
				write(conn, &wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true})
				r.mu.Lock()
				targets := make(map[*websocket.Conn]string, len(r.subs))
				for c, id := range r.subs {
					targets[c] = id
				}
				r.mu.Unlock()
				for c, id := range targets {
					write(c, &wire.EventSubscriptionResponse{SubscriptionID: id, Event: reply})
				}
			}
		}
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *replyRelay) url() string { return wsURL(r.srv) }

func (r *replyRelay) publishedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.published
}

func testReply(replyTo string) *nip01.Event {
	return &nip01.Event{
		ID:        strings.Repeat("e", 64),
		Kind:      transport.KindPrivateResponse,
		Content:   "ciphertext",
		CreatedAt: uint64(time.Now().Unix()),
		Tags:      [][]string{{"p", replyTo}},
	}
}

// T11-35, E-ENV-06.
// NIP-CASH §Addressing the Response: the hub replies on the relay the request
// arrived on, so the client must listen on the relay it sent to. The first relay
// takes the subscription but refuses the request; the request goes out on the
// second, and the reply comes back there and nowhere else.
func TestSubscribeAndPublish_ListensOnTheRelayItSentTo(t *testing.T) {
	replyTo := strings.Repeat("b", 64)
	refusing := newReplyRelay(t, true, testReply(replyTo))
	serving := newReplyRelay(t, false, testReply(replyTo))
	s := &BatchSession{relays: []string{refusing.url(), serving.url()}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fan, err := s.subscribeAndPublish(ctx, replyTo, &outgoing{ev: nip01.NewEvent(transport.KindPrivateRequest, "req")})
	if err != nil {
		t.Fatalf("subscribeAndPublish: %v", err)
	}
	defer fan.stop()
	if serving.publishedCount() != 1 {
		t.Fatalf("the serving relay took %d requests, want 1", serving.publishedCount())
	}

	select {
	case got, ok := <-fan.out:
		if !ok || got == nil || got.ID != testReply(replyTo).ID {
			t.Fatalf("got %+v (open %v), want the reply from the relay the request went to", got, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply: the client was not listening on the relay it sent the request to")
	}
}

// The same reply event from two relays is one chunk (NIP-CASH §Chunked Replies),
// not a repeated chunk that voids the reply.
func TestCollectReply_SameEventFromTwoRelaysIsOneChunk(t *testing.T) {
	limits := transport.DefaultLimits()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	p := statusPacked(nonce, time.Now().Add(5*time.Second).Unix(), "x1", "x2")
	var replyKey [32]byte
	copy(replyKey[:], strings.Repeat("t", 32))
	s := hostileSession(limits, strings.Repeat("b", 64))

	first := sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 1, Total: 2,
		Results: []transport.Result{{ID: "x1", ResultType: "cash_status", Result: []byte(`{}`)}},
	})
	first.ID = strings.Repeat("1", 64)
	second := sealChunk(t, replyKey, limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: nonce, Seq: 2, Total: 2,
		Results: []transport.Result{{ID: "x2", ResultType: "cash_status", Result: []byte(`{}`)}},
	})
	second.ID = strings.Repeat("2", 64)

	ch := make(chan *nip01.Event, 3)
	ch <- first
	ch <- first
	ch <- second
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := s.collectReply(ctx, ch, replyKey, p, 0)
	if err != nil {
		t.Fatalf("a chunk delivered by two relays voided the reply: %v", err)
	}
	if len(got) != 2 || !got[0].Succeeded() || !got[1].Succeeded() {
		t.Fatalf("outcomes = %+v, want both items answered", got)
	}
}

// A relay that refuses the request answers OK false, not an error. That is a
// failure to send, reported at once, not a request to wait out not_after on.
func TestSubscribeAndPublish_ARefusedRequestIsNotSent(t *testing.T) {
	replyTo := strings.Repeat("b", 64)
	refusing := newReplyRelay(t, true, testReply(replyTo))
	s := &BatchSession{relays: []string{refusing.url()}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.subscribeAndPublish(ctx, replyTo, &outgoing{ev: nip01.NewEvent(transport.KindPrivateRequest, "req")})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v, want the relay's refusal", err)
	}
}

// T11-34.
// A relay registers a subscription and handles an event on two connections in
// no fixed order. This one takes its time over the REQ and answers the request
// at once, which is when a client that published without waiting for the
// subscription lost the reply. The client must wait for EOSE before publishing.
func TestSubscribeAndPublish_WaitsForTheSubscriptionBeforePublishing(t *testing.T) {
	replyTo := strings.Repeat("b", 64)
	reply := testReply(replyTo)
	upgrader := websocket.Upgrader{}
	var mu sync.Mutex
	subs := map[*websocket.Conn]string{}
	var writeMu sync.Mutex
	write := func(c *websocket.Conn, v json.Marshaler) {
		b, _ := v.MarshalJSON()
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = c.WriteMessage(websocket.TextMessage, b)
	}
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
			switch p := payload.Packet.(type) {
			case *wire.RequestPacket:
				time.Sleep(300 * time.Millisecond) // a slow REQ
				mu.Lock()
				subs[conn] = p.SubscriptionID
				mu.Unlock()
				write(conn, &wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
			case *wire.EventPacket:
				write(conn, &wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true})
				mu.Lock()
				for c, id := range subs { // the reply goes to whoever is subscribed NOW
					write(c, &wire.EventSubscriptionResponse{SubscriptionID: id, Event: reply})
				}
				mu.Unlock()
			}
		}
	}))
	t.Cleanup(srv.Close)
	s := &BatchSession{relays: []string{wsURL(srv)}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fan, err := s.subscribeAndPublish(ctx, replyTo, &outgoing{ev: nip01.NewEvent(transport.KindPrivateRequest, "req")})
	if err != nil {
		t.Fatalf("subscribeAndPublish: %v", err)
	}
	defer fan.stop()
	select {
	case got, ok := <-fan.out:
		if !ok || got == nil || got.ID != reply.ID {
			t.Fatalf("got %+v (open %v), want the reply", got, ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply: the request overtook its own subscription")
	}
}
