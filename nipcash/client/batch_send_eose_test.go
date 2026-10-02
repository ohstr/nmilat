package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/wire"
)

// EOSE marks the end of STORED events. Every reply to a private-transport request
// is published after the request, so every reply arrives after EOSE — which makes
// "stop at EOSE" the one behaviour guaranteed to miss all of them.
//
// This is the bug the first live end-to-end run hit: replies subscribed with
// Connection.Subscribe, which closes its channel at EOSE by design, so the hub
// answered correctly and the client read every item as omitted — "may or may not
// have been redeemed" for bills that had in fact been paid. Nothing caught it
// before a real relay, because nothing here spoke to a relay at all.
//
// The fake relay below sends EOSE first and the reply after, in that order, which
// is the only ordering a real relay produces.

// newEOSEThenEventRelay starts an in-process relay that answers a REQ with EOSE
// and then, after it, one matching event.
//
// sawREQ closes once a REQ has been received, so a test can prove the
// subscription was actually established rather than passing on a coincidence.
func newEOSEThenEventRelay(t *testing.T, event *nip01.Event) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	sawREQ := make(chan struct{})
	var once bool

	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		write := func(v json.Marshaler) bool {
			b, err := v.MarshalJSON()
			if err != nil {
				return false
			}
			return conn.WriteMessage(websocket.TextMessage, b) == nil
		}

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}
			p, ok := payload.Packet.(*wire.RequestPacket)
			if !ok {
				continue
			}
			if !once {
				once = true
				close(sawREQ)
			}
			// EOSE FIRST. A client that treats this as "the subscription is
			// finished" never sees the event below.
			if !write(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID}) {
				return
			}
			if !write(&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, Event: event}) {
				return
			}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, sawREQ
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func TestSubscribeReplies_DeliversEventsPublishedAfterEOSE(t *testing.T) {
	reply := &nip01.Event{
		ID:        strings.Repeat("a", 64),
		Kind:      transport.KindPrivateResponse,
		Content:   "ciphertext",
		CreatedAt: uint64(time.Now().Unix()),
		Tags:      [][]string{{"p", strings.Repeat("b", 64)}},
	}
	srv, sawREQ := newEOSEThenEventRelay(t, reply)

	s := &BatchSession{relays: []string{wsURL(srv)}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, stop, err := s.subscribeReplies(ctx, strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("subscribeReplies: %v", err)
	}
	defer stop()

	select {
	case <-sawREQ:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never received a REQ — the subscription was not established")
	}

	select {
	case got, ok := <-events:
		if !ok {
			t.Fatal("the reply channel CLOSED at EOSE — every reply arrives after EOSE, so this strands all of them and each item reads as omitted")
		}
		if got == nil || got.ID != reply.ID {
			t.Fatalf("delivered the wrong event: %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply delivered within 5s, although the relay sent one after EOSE")
	}
}

// A CLOSED for this subscription really does end it, and must close the channel —
// otherwise a caller waits out its full timeout for replies that can never come.
// The counterpart to the test above: EOSE must NOT end the subscription, CLOSED
// must.
func TestSubscribeReplies_ClosedEndsTheSubscription(t *testing.T) {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}
			if p, ok := payload.Packet.(*wire.RequestPacket); ok {
				b, _ := (&wire.ClosedSubscriptionResponse{
					SubscriptionID: p.SubscriptionID,
					Message:        "blocked: testing",
				}).MarshalJSON()
				if conn.WriteMessage(websocket.TextMessage, b) != nil {
					return
				}
			}
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &BatchSession{relays: []string{wsURL(srv)}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events, stop, err := s.subscribeReplies(ctx, strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("subscribeReplies: %v", err)
	}
	defer stop()

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("a CLOSED subscription delivered an event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CLOSED did not end the subscription — a caller would wait out its whole timeout for replies that can never arrive")
	}
}
