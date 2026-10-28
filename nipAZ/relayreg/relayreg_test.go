package relayreg_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipAZ"
	_ "github.com/ohstr/nmilat/nipAZ/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
)

func newRelayConn(t *testing.T) *websocket.Conn {
	t.Helper()
	f, err := os.CreateTemp("", "nipaz-relayreg-*.db")
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

// T17-05 (S-AZ-21): the AltZap kinds are the set {9520, 9521, 9523}, not a
// range. A bare signed event of one of them is refused "invalid:"; one of
// 9519, 9522 (a Cash Zap) or 9524 is not looked at by nipAZ/relayreg and is
// stored; and nipAZ's relay validators refuse a 9522 handed to them as an
// AltZap.
func TestRelayValidatesExactlyTheAltZapKinds(t *testing.T) {
	conn := newRelayConn(t)
	priv, _ := cashtest.Keypair(t)
	for _, tc := range []struct {
		kind   int
		stored bool
	}{{9519, true}, {9520, false}, {9521, false}, {9522, true}, {9523, false}, {9524, true}} {
		ev, err := nip01.NewSignedEvent(tc.kind, "", priv)
		if err != nil {
			t.Fatal(err)
		}
		ok, msg := publish(t, conn, ev)
		if ok != tc.stored || (!ok && !strings.HasPrefix(msg, "invalid:")) {
			t.Errorf("kind %d: ok=%v %q, want stored=%v", tc.kind, ok, msg, tc.stored)
		}
	}

	cashZap, err := nip01.NewSignedEvent(9522, "", priv, []string{"p", strings.Repeat("1", 64)}, []string{"amount", "1000"})
	if err != nil {
		t.Fatal(err)
	}
	if err := nipAZ.ValidateAltZapRequestForRelay(cashZap); !errors.Is(err, nip57.ErrWrongKind) {
		t.Errorf("9522 as an AltZap request: %v", err)
	}
	if err := nipAZ.ValidateAltZapReceiptForRelay(cashZap); !errors.Is(err, nip57.ErrWrongKind) {
		t.Errorf("9522 as an AltZap receipt: %v", err)
	}

	found := false
	for _, n := range relay.RegisteredNIPs() {
		if n.String() == "AZ" {
			found = true
		}
	}
	if !found {
		t.Fatal("NIP-AZ not declared")
	}
}
