package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

// newFakeRelayServer starts an in-process WebSocket server that drains the
// client's REQ and replies with a single EVENT followed by EOSE, so the test
// doesn't depend on a real relay running on the network.
func newFakeRelayServer(t *testing.T, event *nip01.Event) *httptest.Server {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the client's REQ packet and echo back its subscription ID,
		// like a real relay would, rather than a hardcoded one — the client
		// only ever learns its own subscription ID (a fresh UUID per
		// Subscribe call), so a fixed ID here would never match.
		var reqData []byte
		if _, reqData, err = conn.ReadMessage(); err != nil {
			return
		}
		var payload wire.RelayPayload
		if err := json.Unmarshal(reqData, &payload); err != nil {
			return
		}
		reqPacket, ok := payload.Packet.(*wire.RequestPacket)
		if !ok {
			return
		}
		subID := reqPacket.SubscriptionID

		eventBytes, err := json.Marshal(event)
		if err != nil {
			return
		}

		evResp := &wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: eventBytes}
		evJSON, err := evResp.MarshalJSON()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, evJSON); err != nil {
			return
		}

		eoseResp := &wire.EOSESubscriptionResponse{SubscriptionID: subID}
		eoseJSON, err := eoseResp.MarshalJSON()
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.TextMessage, eoseJSON)

		// Keep the connection open briefly so the client finishes reading
		// before we tear the server down.
		time.Sleep(200 * time.Millisecond)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestReadRemote(t *testing.T) {
	event := nip01.NewEvent(35502, "test content",
		[]string{"a", "xc1q5e9um2jt5ekar5e2upnp0pq6vm3mhmtz4cvfma"},
	)
	if err := event.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
		t.Fatalf("failed to sign test event: %v", err)
	}

	server := newFakeRelayServer(t, event)

	relayURL, err := url.Parse(strings.Replace(server.URL, "http", "ws", 1))
	if err != nil {
		t.Fatalf("failed to parse relay URL: %v", err)
	}

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{
		Kinds: []int{35502},
		Tags: map[string][]string{
			"a": {"xc1q5e9um2jt5ekar5e2upnp0pq6vm3mhmtz4cvfma"},
		},
		Limit: 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := ReadEventsFromRelay(ctx, relayURL, filters)
	if err != nil {
		t.Fatalf("ReadEventsFromRelay failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ID != event.ID {
		t.Fatalf("expected event ID %s, got %s", event.ID, events[0].ID)
	}
}

// newFakeInteractiveRelayServer starts an in-process WebSocket server that
// keeps reading client packets for the lifetime of the connection, replying
// to REQ with EVENT+EOSE (echoing back the client's own subscription ID,
// like a real relay), to EVENT with OK, and to CLOSE with CLOSED.
func newFakeInteractiveRelayServer(t *testing.T, event *nip01.Event) *httptest.Server {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				return
			}

			switch p := payload.Packet.(type) {
			case *wire.RequestPacket:
				eventBytes, err := json.Marshal(event)
				if err != nil {
					return
				}
				evResp := &wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: eventBytes}
				evJSON, err := evResp.MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, evJSON); err != nil {
					return
				}

				eoseResp := &wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID}
				eoseJSON, err := eoseResp.MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, eoseJSON); err != nil {
					return
				}

			case *wire.EventPacket:
				okResp := &wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true, Message: "ok"}
				okJSON, err := okResp.MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, okJSON); err != nil {
					return
				}

			case *wire.ClosePacket:
				closedResp := &wire.ClosedSubscriptionResponse{SubscriptionID: p.SubscriptionID, Message: "closed"}
				closedJSON, err := closedResp.MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, closedJSON); err != nil {
					return
				}
			}
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestConnection_Publish(t *testing.T) {
	event := nip01.NewEvent(1, "hello")
	if err := event.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
		t.Fatalf("failed to sign test event: %v", err)
	}

	server := newFakeInteractiveRelayServer(t, event)
	relayURL, err := url.Parse(strings.Replace(server.URL, "http", "ws", 1))
	if err != nil {
		t.Fatalf("failed to parse relay URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Connect(ctx, relayURL)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	res, err := conn.Publish(ctx, event)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if !res.Accepted || res.EventID != event.ID {
		t.Fatalf("unexpected OK response: %+v", res)
	}
}

func TestConnection_Subscribe(t *testing.T) {
	event := nip01.NewEvent(35502, "test content")
	if err := event.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
		t.Fatalf("failed to sign test event: %v", err)
	}

	server := newFakeInteractiveRelayServer(t, event)
	relayURL, err := url.Parse(strings.Replace(server.URL, "http", "ws", 1))
	if err != nil {
		t.Fatalf("failed to parse relay URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Connect(ctx, relayURL)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{35502}})

	subID, events, done := conn.Subscribe(filters)
	if subID == "" {
		t.Fatal("expected a non-empty subscription ID")
	}

	var got []*nip01.Event
loop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				break loop
			}
			got = append(got, ev.Event)
		case <-done:
			break loop
		case <-ctx.Done():
			t.Fatal("timed out waiting for events")
		}
	}

	if len(got) != 1 || got[0].ID != event.ID {
		t.Fatalf("unexpected events: %+v", got)
	}

	// The original bug: Subscribe generated a subscription ID internally but
	// never returned it, making CloseSubscription unreachable for anything
	// started via Subscribe. Confirm the returned ID actually works.
	if !conn.CloseSubscription(subID) {
		t.Fatal("expected CloseSubscription to succeed with Subscribe's returned ID")
	}
}
