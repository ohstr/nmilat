package relayreg_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	_ "github.com/ohstr/nmilat/nip29/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/utils"
)

const testPrivKey = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"

func TestNIP29IsDeclared(t *testing.T) {
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIP(29) {
			return
		}
	}
	t.Error("NIP-29 is not declared in the relay's supported NIPs")
}

// This package registers one shared validator across eight moderation kinds in
// a loop, so the risk is a kind silently missing from that loop. These cases
// drive several distinct kinds through a real relay to prove each is wired.
func TestRelayValidatesEachModerationKind(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	tests := []struct {
		name         string
		event        func() *nip01.Event
		wantAccepted bool
		wantInMsg    string
	}{
		{
			name:         "create-group is accepted",
			event:        func() *nip01.Event { return nip29.NewCreateGroup(pubkey, "huddle-1") },
			wantAccepted: true,
		},
		{
			name: "put-user without a p tag is rejected",
			event: func() *nip01.Event {
				return &nip01.Event{Kind: nip29.KindPutUser, PubKey: pubkey, Tags: [][]string{{"h", "g"}}}
			},
			wantAccepted: false,
			wantInMsg:    "p tag",
		},
		{
			name: "remove-user without a p tag is rejected",
			event: func() *nip01.Event {
				return &nip01.Event{Kind: nip29.KindRemoveUser, PubKey: pubkey, Tags: [][]string{{"h", "g"}}}
			},
			wantAccepted: false,
			wantInMsg:    "p tag",
		},
		{
			name: "create-invite without a code is rejected",
			event: func() *nip01.Event {
				return &nip01.Event{Kind: nip29.KindCreateInvite, PubKey: pubkey, Tags: [][]string{{"h", "g"}}}
			},
			wantAccepted: false,
			wantInMsg:    "code",
		},
		{
			name: "delete-event without an e tag is rejected",
			event: func() *nip01.Event {
				return &nip01.Event{Kind: nip29.KindDeleteEvent, PubKey: pubkey, Tags: [][]string{{"h", "g"}}}
			},
			wantAccepted: false,
			wantInMsg:    "e tag",
		},
		{
			name:         "a moderation event with no h tag is rejected",
			event:        func() *nip01.Event { return &nip01.Event{Kind: nip29.KindDeleteGroup, PubKey: pubkey} },
			wantAccepted: false,
			wantInMsg:    "h tag",
		},
		{
			name:         "leave request is accepted",
			event:        func() *nip01.Event { return nip29.NewLeaveRequest(pubkey, "huddle-1", "bye") },
			wantAccepted: true,
		},
		{
			name:         "join request without an h tag is rejected",
			event:        func() *nip01.Event { return &nip01.Event{Kind: nip29.KindJoinRequest, PubKey: pubkey} },
			wantAccepted: false,
			wantInMsg:    "h tag",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := newRelayConn(t)
			ev := tc.event()
			ev.CreatedAt = uint64(time.Now().Unix())
			accepted, message := publish(t, conn, sign(t, ev))
			if accepted != tc.wantAccepted {
				t.Fatalf("accepted = %v, want %v (message %q)", accepted, tc.wantAccepted, message)
			}
			if tc.wantInMsg != "" && !strings.Contains(message, tc.wantInMsg) {
				t.Errorf("rejection should mention %q, got %q", tc.wantInMsg, message)
			}
		})
	}
}

// buzz builds its huddle backing channel out of these kinds, so a relay that
// silently stopped validating them would break interop quietly.
func TestRelayAcceptsBuzzHuddleLifecycleEvents(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	for _, ev := range []*nip01.Event{
		nip29.NewCreateGroup(pubkey, "huddle-1"),
		nip29.NewEditMetadata(pubkey, "huddle-1", nip29.GroupMetadataParams{Name: "archived"}),
		nip29.NewLeaveRequest(pubkey, "huddle-1", ""),
	} {
		conn := newRelayConn(t)
		ev.CreatedAt = uint64(time.Now().Unix())
		accepted, message := publish(t, conn, sign(t, ev))
		if !accepted {
			t.Errorf("relay rejected buzz lifecycle kind %d: %q", ev.Kind, message)
		}
	}
}

// newRelayConn boots a real relay over a websocket. The wiring this package
// registers can only be observed end to end -- relay's validator registry is
// unexported -- so these tests publish events and read the relay's verdict
// rather than calling the nip package directly.
func newRelayConn(t *testing.T) *websocket.Conn {
	t.Helper()

	f, err := os.CreateTemp("", "relayreg-test.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	store, err := relay.NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000},
		relay.WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := relay.NewSessionHandler(store, metadata, nil, relay.WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanups run LIFO, so this fires first: close the socket, then wait for
	// the relay's session goroutine to actually finish. gorilla hijacks the
	// connection, so httptest.Server.Close() never waits for it -- and a
	// session that ends after the test has completed logs into a finished
	// *testing.T, which panics the whole package. That is an observed
	// intermittent failure, not a theoretical one.
	t.Cleanup(func() {
		_ = conn.Close()
		waitForSessionsToDrain(t, handler)
	})
	return conn
}

// waitForSessionsToDrain polls until the relay reports no live sessions,
// mirroring the waitForSessionCount helper relay's own tests use.
func waitForSessionsToDrain(t *testing.T, handler *relay.SessionHandler) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for handler.SessionCount() != 0 {
		if time.Now().After(deadline) {
			t.Errorf("relay still reports %d live session(s) after the socket closed", handler.SessionCount())
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// publish sends an EVENT and returns the relay's OK verdict and message. The
// deadline is generous on purpose: this suite runs alongside every other
// package under -race, and a tight one turns load into a spurious failure.
func publish(t *testing.T, conn *websocket.Conn, ev *nip01.Event) (bool, string) {
	t.Helper()
	if err := conn.WriteJSON([]any{"EVENT", ev}); err != nil {
		t.Fatalf("write EVENT: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	for {
		var raw []json.RawMessage
		if err := conn.ReadJSON(&raw); err != nil {
			t.Fatalf("read OK: %v", err)
		}
		if len(raw) == 0 {
			continue
		}
		var label string
		if err := json.Unmarshal(raw[0], &label); err != nil || label != "OK" {
			continue
		}
		if len(raw) < 4 {
			t.Fatalf("malformed OK frame: %v", raw)
		}
		var accepted bool
		var message string
		if err := json.Unmarshal(raw[2], &accepted); err != nil {
			t.Fatalf("parse OK verdict: %v", err)
		}
		if err := json.Unmarshal(raw[3], &message); err != nil {
			t.Fatalf("parse OK message: %v", err)
		}
		return accepted, message
	}
}

func sign(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev
}
