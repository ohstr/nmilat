package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
)

func dialWithOrigin(t testing.TB, wsURL, origin string) error {
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

// waitForSessionCount polls until handler reports want sessions, or fails
// the test after 2s. gorilla/websocket hijacks the underlying TCP
// connection on upgrade, so httptest.Server.Close()'s own WaitGroup treats
// a session's connection as already accounted for the instant it's
// hijacked -- it does NOT wait for that session's read/write goroutines to
// actually exit. Without this synchronization, a session from one test can
// still be running when the next test starts, racing on whatever memory
// its next allocation happens to reuse.
func waitForSessionCount(t testing.TB, handler *SessionHandler, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for handler.SessionCount() != want {
		if time.Now().After(deadline) {
			t.Fatalf("expected %d sessions, got %d", want, handler.SessionCount())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWithSessionAllowedOrigins_RestrictsCORS(t *testing.T) {
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil,
		WithLogger(testlogger.New(t)),
		WithSessionAllowedOrigins("https://allowed.example"),
	)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	if err := dialWithOrigin(t, wsURL, "https://allowed.example"); err != nil {
		t.Errorf("expected the allowed origin to connect, got: %v", err)
	}

	if err := dialWithOrigin(t, wsURL, "https://not-allowed.example"); err == nil {
		t.Error("expected a non-allowed origin to be rejected")
	}

	waitForSessionCount(t, handler, 0)
}

func TestWithSessionAllowedOrigins_DefaultAllowsAny(t *testing.T) {
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	if err := dialWithOrigin(t, wsURL, "https://anything.example"); err != nil {
		t.Errorf("expected default config to allow any origin, got: %v", err)
	}

	waitForSessionCount(t, handler, 0)
}

func TestSession_GettersAndSessionCount(t *testing.T) {
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	if got := handler.SessionCount(); got != 0 {
		t.Fatalf("expected 0 sessions before connecting, got %d", got)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer waitForSessionCount(t, handler, 0)
	defer func() { _ = conn.Close() }()

	// Give the server a moment to register the session.
	waitForSessionCount(t, handler, 1)

	var gotID int64
	var gotInfo *ClientInfo
	handler.sessions.Range(func(_, v interface{}) bool {
		s := v.(*Session)
		gotID = s.ID()
		gotInfo = s.Info()
		return false
	})

	if gotID == 0 {
		t.Error("expected Session.ID() to return a non-zero session ID")
	}
	if gotInfo == nil || gotInfo.RemoteAddr == "" {
		t.Errorf("expected Session.Info() to return populated ClientInfo, got %+v", gotInfo)
	}
	// AuthedPubkey is empty until NIP-42 AUTH completes.
	handler.sessions.Range(func(_, v interface{}) bool {
		s := v.(*Session)
		if s.AuthedPubkey() != "" {
			t.Errorf("expected AuthedPubkey to be empty before auth, got %q", s.AuthedPubkey())
		}
		return false
	})
}
