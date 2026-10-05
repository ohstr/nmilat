package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/wire"
)

// newAuthChallengeServer starts an in-process relay that immediately sends
// a NIP-42 AUTH challenge on connect, then hands whatever the client sends
// back (if anything, within readTimeout) to onAuthEvent for a reply.
// readTimeout fires (ok=false) rather than blocking forever when the
// client never answers -- the no-PrivateKey case this file tests for.
func newAuthChallengeServer(t *testing.T, challenge string, readTimeout time.Duration, onAuthEvent func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse) *httptest.Server {
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

		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return // deadline hit, or client closed -- onAuthEvent is simply never called
		}

		var payload wire.RelayPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return
		}
		ap, ok := payload.Packet.(*wire.AuthPacket)
		if !ok {
			return
		}

		resp := onAuthEvent(ap)
		if resp == nil {
			return
		}
		respJSON, err := resp.MarshalJSON()
		if err != nil {
			return
		}
		_ = conn.WriteMessage(websocket.TextMessage, respJSON)

		time.Sleep(100 * time.Millisecond)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func dialURL(t *testing.T, server *httptest.Server) *url.URL {
	u, err := url.Parse("ws" + server.URL[len("http"):])
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// waitForAuthState polls AuthState() until it stops being AuthStateNone or
// the timeout elapses, returning whatever the last observed state was --
// handleAuthChallenge/handleAuthResult run asynchronously off the read
// loop, so the state only settles some time after the server writes its
// response.
func waitForAuthState(c *Connection, timeout time.Duration) AuthState {
	deadline := time.Now().Add(timeout)
	for {
		if s := c.AuthState(); s != AuthStateNone {
			return s
		}
		if time.Now().After(deadline) {
			return c.AuthState()
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConnection_AnswersAuthChallengeAndRecordsSuccess(t *testing.T) {
	const challenge = "test-challenge-accept"

	var gotRelayURL string
	server := newAuthChallengeServer(t, challenge, 2*time.Second, func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse {
		gotRelayURL = ap.Event.GetTag("relay")[0]
		if err := nip42.ValidateAuthEvent(ap.Event.Kind, ap.Event.Tags, ap.Event.CreatedAt, challenge, gotRelayURL); err != nil {
			t.Errorf("server-side ValidateAuthEvent: %v", err)
		}
		if err := ap.Event.Verify(); err != nil {
			t.Errorf("server-side Verify: %v", err)
		}
		return &wire.OkSubscriptionResponse{EventID: ap.Event.ID, Accepted: true, Message: "auth-success"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	u := dialURL(t, server)
	conn, err := NewConnection(ctx, u, &ConnectionConfig{PrivateKey: testPrivKey})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := waitForAuthState(conn, 2*time.Second); got != AuthStateSucceeded {
		t.Fatalf("AuthState() = %v, want AuthStateSucceeded", got)
	}
	if got, want := conn.AuthMessage(), "auth-success"; got != want {
		t.Errorf("AuthMessage() = %q, want %q", got, want)
	}
	if gotRelayURL != u.String() {
		t.Errorf("auth event's relay tag = %q, want %q", gotRelayURL, u.String())
	}
}

func TestConnection_RecordsAuthRejection(t *testing.T) {
	const challenge = "test-challenge-reject"
	const rejectMessage = "restricted: valid NIP-43 membership required"

	server := newAuthChallengeServer(t, challenge, 2*time.Second, func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse {
		return &wire.OkSubscriptionResponse{EventID: ap.Event.ID, Accepted: false, Message: rejectMessage}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	u := dialURL(t, server)
	conn, err := NewConnection(ctx, u, &ConnectionConfig{PrivateKey: testPrivKey})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := waitForAuthState(conn, 2*time.Second); got != AuthStateFailed {
		t.Fatalf("AuthState() = %v, want AuthStateFailed", got)
	}
	if got := conn.AuthMessage(); got != rejectMessage {
		t.Errorf("AuthMessage() = %q, want %q", got, rejectMessage)
	}
}

// TestConnection_NoPrivateKeyLeavesChallengeUnanswered guards the "no
// behavior change" requirement: a Connection with no PrivateKey configured
// must not send anything back for an AUTH challenge, and AuthState() must
// stay None -- the challenge is still delivered on Read()/Events() like
// any other message, for a caller that wants to drive the handshake
// itself.
func TestConnection_NoPrivateKeyLeavesChallengeUnanswered(t *testing.T) {
	const challenge = "test-challenge-anonymous"

	onAuthEventCalled := make(chan struct{}, 1)
	server := newAuthChallengeServer(t, challenge, 300*time.Millisecond, func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse {
		onAuthEventCalled <- struct{}{}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	u := dialURL(t, server)
	conn, err := NewConnection(ctx, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The challenge still arrives on the ordinary incoming channel.
	select {
	case res := <-conn.Read():
		if _, ok := res.(*wire.AuthChallengeResponse); !ok {
			t.Fatalf("Read() delivered %T, want *wire.AuthChallengeResponse", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("challenge never arrived on Read()")
	}

	select {
	case <-onAuthEventCalled:
		t.Fatal("connection answered the AUTH challenge despite no PrivateKey being configured")
	case <-time.After(500 * time.Millisecond):
		// expected: nothing sent
	}

	if got := conn.AuthState(); got != AuthStateNone {
		t.Errorf("AuthState() = %v, want AuthStateNone", got)
	}
}
