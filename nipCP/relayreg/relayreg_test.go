package relayreg_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nipCP"
	_ "github.com/ohstr/nmilat/nipCP/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
)

func newRelayConn(t *testing.T) *websocket.Conn {
	t.Helper()
	f, err := os.CreateTemp("", "nipcp-relayreg-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	store, err := relay.NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000}, relay.WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	handler := relay.NewSessionHandler(store, &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1 << 20}}, nil, relay.WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		deadline := time.Now().Add(10 * time.Second)
		for handler.SessionCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
	return conn
}

func publish(t *testing.T, conn *websocket.Conn, ev *nip01.Event) (bool, string) {
	t.Helper()
	if err := conn.WriteJSON([]any{"EVENT", ev}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var raw []json.RawMessage
		if err := conn.ReadJSON(&raw); err != nil {
			t.Fatal(err)
		}
		var kind string
		if len(raw) < 4 || json.Unmarshal(raw[0], &kind) != nil || kind != "OK" {
			continue
		}
		var ok bool
		var msg string
		_ = json.Unmarshal(raw[2], &ok)
		_ = json.Unmarshal(raw[3], &msg)
		return ok, msg
	}
}

// T17-01 (relay half of CP-EV-01): a signed 9525 is refused; a gift wrap is
// stored.
func TestRelayRefusesBarePocketEntry(t *testing.T) {
	conn := newRelayConn(t)
	priv, _ := cashtest.Keypair(t)
	ev, err := nip01.NewSignedEvent(nipCP.KindPocketEntry, "", priv, []string{"w", strings.Repeat("1", 64)})
	if err != nil {
		t.Fatal(err)
	}
	ok, msg := publish(t, conn, ev)
	if ok || msg != "blocked: kind 9525 travels only inside a gift wrap" {
		t.Fatalf("bare 9525: %v %q", ok, msg)
	}
	other, err := nip01.NewSignedEvent(1, "hi", priv)
	if err != nil {
		t.Fatal(err)
	}
	if ok, msg := publish(t, conn, other); !ok {
		t.Fatalf("kind 1 refused: %s", msg)
	}
	found := false
	for _, n := range relay.RegisteredNIPs() {
		if n.String() == "CP" {
			found = true
		}
	}
	if !found {
		t.Fatal("NIP-CP not declared")
	}
}
