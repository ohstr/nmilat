package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/wire"
)

// newMembershipGatedRelayServer starts an in-process relay that behaves
// like a real MembershipRequired relay: it challenges on connect, closes
// any REQ as "restricted: ..." until a valid AUTH event arrives (checked
// the same way relay/packet.go's processAuth does -- ValidateAuthEvent
// plus signature verification), and only then answers REQ with event (if
// non-nil) followed by EOSE. AUTH and REQ are handled in whichever order
// they actually arrive, same as a real relay reading one connection's
// packets in receive order -- this doesn't assume the client sends one
// before the other.
func newMembershipGatedRelayServer(t *testing.T, challenge string, event *nip01.Event) *httptest.Server {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		challengeJSON, err := (&wire.AuthChallengeResponse{Challenge: challenge}).MarshalJSON()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, challengeJSON); err != nil {
			return
		}

		authed := false
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
			case *wire.AuthPacket:
				if err := nip42.ValidateAuthEvent(p.Event.Kind, p.Event.Tags, p.Event.CreatedAt, challenge, "ws://"+r.Host); err != nil {
					t.Errorf("server-side ValidateAuthEvent: %v", err)
				}
				if err := p.Event.Verify(); err != nil {
					t.Errorf("server-side Verify: %v", err)
				}
				authed = true
				okJSON, err := (&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true, Message: "auth-success"}).MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, okJSON); err != nil {
					return
				}

			case *wire.RequestPacket:
				if !authed {
					closedJSON, err := (&wire.ClosedSubscriptionResponse{
						SubscriptionID: p.SubscriptionID,
						Message:        "restricted: valid NIP-43 membership required",
					}).MarshalJSON()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, closedJSON); err != nil {
						return
					}
					continue
				}

				if event != nil {
					eventBytes, err := json.Marshal(event)
					if err != nil {
						return
					}
					evJSON, err := (&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: eventBytes}).MarshalJSON()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, evJSON); err != nil {
						return
					}
				}
				eoseJSON, err := (&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID}).MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, eoseJSON); err != nil {
					return
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestReadEventsFromRelayWithAuth_NoKeyMatchesPlainRead(t *testing.T) {
	event := nip01.NewEvent(1, "hello")
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	server := newFakeRelayServer(t, event)
	u := dialURL(t, server)

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, u, filters, "")
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth(no key) error = %v", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- this relay never sent a restricted CLOSED")
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("ReadEventsFromRelayWithAuth(no key) events = %v, want [%s]", events, event.ID)
	}
}

func TestReadEventsFromRelayWithAuth_RetriesOnceAfterAuthenticating(t *testing.T) {
	const challenge = "membership-gate-challenge"
	event := nip01.NewEvent(1, "members only")
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	server := newMembershipGatedRelayServer(t, challenge, event)
	u := dialURL(t, server)

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, u, filters, testPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth error = %v", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- the retry succeeded, it should report the final attempt's own outcome")
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %v, want exactly [%s] after authenticating and retrying", events, event.ID)
	}
}

// TestReadEventsFromRelayWithAuth_GivesUpAfterWindowIfNeverAuthenticated
// covers a challenge whose handshake never actually settles -- the retry
// must still fire once authRetryWindow elapses, rather than hanging past
// it, honoring ctx the way TestReadRemote_NoEOSE_RespectsContextDeadline
// already guards for the plain (non-auth) path.
func TestReadEventsFromRelayWithAuth_GivesUpAfterWindowIfNeverAuthenticated(t *testing.T) {
	old := authRetryWindow
	authRetryWindow = 100 * time.Millisecond
	t.Cleanup(func() { authRetryWindow = old })

	server := newMembershipGatedRelayServer(t, "never-answered-challenge", nil)
	u := dialURL(t, server)
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = ReadEventsFromRelayWithAuth(ctx, u, filters, testPrivKey)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ReadEventsFromRelayWithAuth did not return within 3s -- the retry wait may not be honoring authRetryWindow/ctx")
	}
}

// newRelayThatDiesRightAfterTheRestrictedClose starts an in-process relay
// reproducing a real relay's observed behavior: it challenges on connect
// and closes a REQ as restricted exactly like
// newMembershipGatedRelayServer, but on its FIRST connection, the moment
// it has both (a) answered that REQ and (b) validated the client's AUTH
// event, it sends a WS close frame instead of the OK the client is
// waiting on -- root cause not reproduced here (the real relay's own
// cause was never pinned down either, see ReadEventsFromRelayWithAuth's
// doc comment), just the observable effect: the connection dies during
// exactly the window ReadEventsFromRelayWithAuth waits in. The ordering
// is forced deterministically (not left to whichever of REQ/AUTH happens
// to arrive first on the wire) so this test isn't racy: a validated AUTH
// that arrives before REQ is answered is held back until the REQ's own
// CLOSED has actually been sent. Its second connection (what a redial
// produces) behaves normally throughout.
func newRelayThatDiesRightAfterTheRestrictedClose(t *testing.T, challenge string, event *nip01.Event) *httptest.Server {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	var connCount atomic.Int32
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		isFirstConn := connCount.Add(1) == 1

		challengeJSON, err := (&wire.AuthChallengeResponse{Challenge: challenge}).MarshalJSON()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, challengeJSON); err != nil {
			return
		}

		authed := false
		reqAnswered := false
		pendingAuthEventID := ""
		die := func() {
			msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
			_ = conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
		}

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
			case *wire.AuthPacket:
				if err := nip42.ValidateAuthEvent(p.Event.Kind, p.Event.Tags, p.Event.CreatedAt, challenge, "ws://"+r.Host); err != nil {
					t.Errorf("server-side ValidateAuthEvent: %v", err)
				}
				if err := p.Event.Verify(); err != nil {
					t.Errorf("server-side Verify: %v", err)
				}
				if isFirstConn {
					if reqAnswered {
						die()
						return
					}
					// REQ hasn't been answered yet -- hold this and fire
					// once it is, rather than racing send order on the wire.
					pendingAuthEventID = p.Event.ID
					continue
				}
				authed = true
				okJSON, err := (&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true, Message: "auth-success"}).MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, okJSON); err != nil {
					return
				}

			case *wire.RequestPacket:
				if !authed {
					closedJSON, err := (&wire.ClosedSubscriptionResponse{
						SubscriptionID: p.SubscriptionID,
						Message:        "restricted: valid NIP-43 membership required",
					}).MarshalJSON()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, closedJSON); err != nil {
						return
					}
					reqAnswered = true
					if isFirstConn && pendingAuthEventID != "" {
						die()
						return
					}
					continue
				}

				if event != nil {
					eventBytes, err := json.Marshal(event)
					if err != nil {
						return
					}
					evJSON, err := (&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: eventBytes}).MarshalJSON()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, evJSON); err != nil {
						return
					}
				}
				eoseJSON, err := (&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID}).MarshalJSON()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, eoseJSON); err != nil {
					return
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// TestReadEventsFromRelayWithAuth_RedialsAfterConnectionDiesMidWait is the
// regression test for the real-world failure this package's own report
// described: every authenticated read of a private/restricted target
// failed with "connection closed" because the wait between attempts
// didn't notice its connection had died, and the retry ran against a
// connection that was already gone. With the fix, the same scenario
// redials and authenticates fresh instead of surfacing that error.
func TestReadEventsFromRelayWithAuth_RedialsAfterConnectionDiesMidWait(t *testing.T) {
	const challenge = "dies-right-after-restricted-close"
	event := nip01.NewEvent(1, "members only, reached via redial")
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	server := newRelayThatDiesRightAfterTheRestrictedClose(t, challenge, event)
	u := dialURL(t, server)

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, u, filters, testPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth error = %v, want it to redial past the dead connection and succeed", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- the redial's own retry succeeded")
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %v, want exactly [%s] after redialing", events, event.ID)
	}
}

// TestReadEventsFromRelayWithAuth_RetriesEOSEServedBeforeAuth: the relay
// answers a REQ anonymously with a silently filtered EOSE (as NIP-29 does
// for private groups), but the client reads the AUTH OK first. The result
// was served anonymously, so it must still be retried.
func TestReadEventsFromRelayWithAuth_RetriesEOSEServedBeforeAuth(t *testing.T) {
	const challenge = "late-challenge"
	event := nip01.NewEvent(1, "private group metadata")
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}

	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		write := func(m interface{ MarshalJSON() ([]byte, error) }) {
			b, err := m.MarshalJSON()
			if err == nil {
				_ = conn.WriteMessage(websocket.TextMessage, b)
			}
		}
		authed := false
		pendingSub := ""
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
				if !authed {
					// Challenge only now, so the REQ is guaranteed to precede AUTH.
					pendingSub = p.SubscriptionID
					write(&wire.AuthChallengeResponse{Challenge: challenge})
					continue
				}
				eventBytes, _ := json.Marshal(event)
				write(&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: eventBytes})
				write(&wire.EOSESubscriptionResponse{SubscriptionID: p.SubscriptionID})
			case *wire.AuthPacket:
				authed = true
				write(&wire.OkSubscriptionResponse{EventID: p.Event.ID, Accepted: true})
				if pendingSub != "" {
					write(&wire.EOSESubscriptionResponse{SubscriptionID: pendingSub})
					pendingSub = ""
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, _, err := ReadEventsFromRelayWithAuth(ctx, dialURL(t, server), filters, testPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth error = %v", err)
	}
	if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events = %v, want [%s] from the authenticated retry", events, event.ID)
	}
}

func TestReadEventsFromRelayWithAuth_NonRestrictedCloseIsNotRetried(t *testing.T) {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	var reqCount int
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var payload wire.RelayPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return
		}
		rp, ok := payload.Packet.(*wire.RequestPacket)
		if !ok {
			return
		}
		reqCount++

		closedJSON, err := (&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "error: unsupported filter",
		}).MarshalJSON()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, closedJSON)

		time.Sleep(200 * time.Millisecond)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	u := dialURL(t, server)
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, u, filters, testPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth error = %v", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- this CLOSED wasn't the \"restricted: ...\" kind")
	}
	if len(events) != 0 {
		t.Errorf("events = %v, want none", events)
	}
	if reqCount != 1 {
		t.Errorf("server saw %d REQ, want exactly 1 -- a non-restricted CLOSED must not trigger a retry", reqCount)
	}
}
