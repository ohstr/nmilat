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
	"github.com/ohstr/nmilat/nip53"
	_ "github.com/ohstr/nmilat/nip53/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/utils"
)

const testPrivKey = "0acd1245d4b0e9cae1a3b0e1a1e0cf3d1e5b2a7c8d9e0f1a2b3c4d5e6f70268c"

func TestNIP53IsDeclared(t *testing.T) {
	for _, id := range relay.RegisteredNIPs() {
		if id == nip11.NIP(53) {
			return
		}
	}
	t.Error("NIP-53 is not declared in the relay's supported NIPs")
}

func TestRelayAcceptsWellFormedMeetingSpace(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	conn := newRelayConn(t)

	ev := sign(t, nip53.NewMeetingSpace(nip53.MeetingSpaceParams{
		Pubkey:     pubkey,
		Identifier: "room-1",
		Room:       "Standup",
		Status:     nip53.SpaceStatusOpen,
		Service:    "wss://relay.example/huddle/room-1",
		Providers:  []nip53.Participant{{Pubkey: pubkey, Role: nip53.RoleHost}},
	}))

	accepted, message := publish(t, conn, ev)
	if !accepted {
		t.Fatalf("relay rejected a valid meeting space: %q", message)
	}
}

// The point of this test is the wiring, not the parser: nip53's own tests
// already cover the rule. What is asserted here is that the relay actually
// consults it, which nothing would otherwise catch.
func TestRelayRejectsMeetingSpaceWithoutService(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	conn := newRelayConn(t)

	ev := sign(t, nip53.NewMeetingSpace(nip53.MeetingSpaceParams{
		Pubkey:     pubkey,
		Identifier: "room-2",
		Room:       "Standup",
		Status:     nip53.SpaceStatusOpen,
		Providers:  []nip53.Participant{{Pubkey: pubkey, Role: nip53.RoleHost}},
	}))

	accepted, message := publish(t, conn, ev)
	if accepted {
		t.Fatal("relay accepted a meeting space with no service url")
	}
	if !strings.Contains(message, "service") {
		t.Errorf("rejection should name the missing tag, got %q", message)
	}
}

func TestRelayRejectsPresenceInTwoRoomsAtOnce(t *testing.T) {
	pubkey, err := utils.GetPublicKey(testPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	roomA, err := nip53.SpaceATag(pubkey, "room-1")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	roomB, err := nip53.SpaceATag(pubkey, "room-2")
	if err != nil {
		t.Fatalf("SpaceATag: %v", err)
	}
	conn := newRelayConn(t)

	ev := sign(t, &nip01.Event{
		Kind:      nip53.KindRoomPresence,
		PubKey:    pubkey,
		CreatedAt: uint64(time.Now().Unix()),
		Tags:      [][]string{{"a", roomA}, {"a", roomB}},
	})

	accepted, _ := publish(t, conn, ev)
	if accepted {
		t.Fatal("relay accepted presence claiming two rooms at once")
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
