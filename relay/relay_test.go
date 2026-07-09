package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
)

func newTestRelay(t testing.TB) *Relay {
	f, err := os.CreateTemp("", "relay-new-test.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	metadata := &nip11.Metadata{
		Name:       "test-relay",
		Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024},
	}

	rl, err := New(f.Name(), metadata)
	if err != nil {
		t.Fatalf("relay.New failed: %v", err)
	}
	t.Cleanup(func() { rl.Close() })

	return rl
}

func TestNew_ServesNip11Document(t *testing.T) {
	rl := newTestRelay(t)
	srv := httptest.NewServer(rl)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", nip11.ContentTypeHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var doc nip11.Metadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("failed to decode NIP-11 document: %v", err)
	}
	if doc.Name != "test-relay" {
		t.Errorf("expected relay name %q, got %q", "test-relay", doc.Name)
	}
}

func TestNew_StillUpgradesWebSocket(t *testing.T) {
	rl := newTestRelay(t)
	srv := httptest.NewServer(rl)
	t.Cleanup(srv.Close)

	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("expected websocket upgrade to succeed, got: %v", err)
	}
	conn.Close()
}
