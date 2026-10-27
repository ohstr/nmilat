package relayreg_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	_ "github.com/ohstr/nmilat/nipCP/relayreg"
	_ "github.com/ohstr/nmilat/nipCZ/relayreg"
	"github.com/ohstr/nmilat/nipcw"
	_ "github.com/ohstr/nmilat/nipcw/relayreg"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/testlogger"
)

func newRelay(t *testing.T) (*relay.SessionHandler, string) {
	t.Helper()
	f, err := os.CreateTemp("", "nipcw-relayreg-*.db")
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
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for handler.SessionCount() != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
	return handler, srv.URL
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

func followSet(t *testing.T, priv string, createdAt time.Time) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: nipcw.KindFollowSet, CreatedAt: uint64(createdAt.Unix()), Tags: [][]string{{"d", "circle"}}}
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// T17-02 (S-CW-44) through the relay: a follow set dated now is stored, one
// an hour ahead is refused "invalid: created_at too far in the future".
func TestRelayRefusesFutureFollowSet(t *testing.T) {
	_, url := newRelay(t)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	priv, _ := cashtest.Keypair(t)
	if ok, msg := publish(t, conn, followSet(t, priv, time.Now())); !ok {
		t.Fatalf("current follow set refused: %s", msg)
	}
	ok, msg := publish(t, conn, followSet(t, priv, time.Now().Add(time.Hour)))
	if ok || msg != "invalid: created_at too far in the future" {
		t.Fatalf("future follow set: %v %q", ok, msg)
	}
}

// T17-06: the NIP-11 document lists CP, CW and CZ when their relayreg
// packages are imported.
func TestNIP11ListsCashNIPs(t *testing.T) {
	_, url := newRelay(t)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var doc struct {
		SupportedNips []any `json:"supported_nips"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("NIP-11: %v: %s", err, data)
	}
	for _, want := range []string{"CP", "CW", "CZ"} {
		if !slices.Contains(doc.SupportedNips, any(want)) {
			t.Errorf("supported_nips %v lacks %q", doc.SupportedNips, want)
		}
	}
}
