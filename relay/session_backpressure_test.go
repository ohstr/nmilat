package relay

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
)

// shrinkBufferListener wraps a net.Listener so every accepted connection
// gets a small OS-level TCP read/write buffer. Default buffers on this
// environment's loopback interface absorb multiple megabytes before a
// stalled reader produces any backpressure; shrinking both ends to 1024
// bytes makes "the peer stops reading" reproduce genuine backpressure
// within a couple hundred small messages instead.
type shrinkBufferListener struct {
	net.Listener
}

func (l *shrinkBufferListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(1024)
		_ = tc.SetWriteBuffer(1024)
	}
	return c, nil
}

// createBackpressureWS is like createWS, but serves over a
// shrinkBufferListener and also shrinks the dialed client connection's own
// read buffer, so a client that stops reading reliably jams the connection
// within a couple hundred small messages instead of depending on this
// environment's own (large, inconsistent) default socket buffer sizes.
func createBackpressureWS(t testing.TB, store *EventStore) *websocket.Conn {
	conn, _ := createBackpressureWSWithOpts(t, store)
	return conn
}

// createBackpressureWSWithOpts is createBackpressureWS, but also takes
// SessionOptions and returns the handler so a test can inspect session
// state (e.g. waitForSessionCount) directly.
func createBackpressureWSWithOpts(t testing.TB, store *EventStore, opts ...SessionOption) (*websocket.Conn, *SessionHandler) {
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	allOpts := append([]SessionOption{WithLogger(testlogger.New(t))}, opts...)
	handler := NewSessionHandler(store, metadata, nil, allOpts...)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	_ = srv.Listener.Close()
	srv.Listener = &shrinkBufferListener{ln}
	srv.Start()
	t.Cleanup(srv.Close)

	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(1024)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		waitForSessionCount(t, handler, 0)
	})
	return conn, handler
}

// readUntil reads ClientPayload frames from conn (bounded by deadline)
// until fn returns true for one of them, calling fn for every frame seen
// along the way. Returns false if the deadline is hit first.
func readUntil(t testing.TB, conn *websocket.Conn, deadline time.Time, fn func(wire.SubscriptionResponse) bool) bool {
	t.Helper()
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		_ = conn.SetReadDeadline(time.Now().Add(remaining))
		var payload wire.ClientPayload
		if err := conn.ReadJSON(&payload); err != nil {
			return false
		}
		if fn(payload.SubscriptionResponse) {
			return true
		}
	}
}

// TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection
// reproduces the delivery stall (issue-evaluation.md) at report-realistic
// scale: 3 fresh events on the filter under test, not the 55+
// TestSubscriptionBackpressureDelaysButNeverLosesEvents needs.
//
// Every subscription on one websocket connection shares one outgoing pipe
// (Session.incoming, drained by one goroutine, one blocking conn.WriteJSON
// call at a time), so a large undrained backlog on one subscription jams
// delivery to an unrelated, otherwise-idle subscription on the same
// connection.
//
// Mirrors the report's own methodology instead of reading from the
// stalled connection and expecting a timeout (a full FIFO buffer would
// just return queued backlog and prove nothing): compares delivery of the
// same events via the stalled connection against a brand-new connection
// opened afterward.
//
// Also caught EventStore.FindEventBytes's transaction-scope bug (see
// TestFindEventBytesSurvivesLaterWrites) the first few times this was
// written; fixed now, so this only exercises the timing/fairness issue.
func TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection(t *testing.T) {
	backlog := CreateEvents(t, 150, 1)
	store := newStoreWithEvents(t, backlog)

	stalled := createBackpressureWS(t, store)

	// sub-backlog: a pre-existing 150-event kind-1 backlog, comfortably
	// enough small messages to jam the shrunk connection (empirically,
	// ~87 messages of similar size is enough for a clean block).
	if err := stalled.WriteJSON(wire.NewRequestPacket("sub-backlog", CreateFilter([]int{1}, 500))); err != nil {
		t.Fatal(err)
	}
	// sub-probe: a completely separate, otherwise-empty filter on the SAME
	// connection. Nothing matches it yet.
	if err := stalled.WriteJSON(wire.NewRequestPacket("sub-probe", CreateFilter([]int{9999}, 10))); err != nil {
		t.Fatal(err)
	}

	// Deliberately never read from `stalled` up to this point, giving the
	// relay time to actually jam on sub-backlog's own delivery.
	time.Sleep(500 * time.Millisecond)

	// Publish a small number of fresh events matching sub-probe's filter
	// from a separate connection, using OK acceptance as the start of the
	// clock (matching the report's own measurement methodology).
	publisher := createBackpressureWS(t, store)
	probe := CreateEvents(t, 3, 9999)
	for _, ev := range probe {
		if err := publisher.WriteJSON(wire.NewEventPacket(ev)); err != nil {
			t.Fatal(err)
		}
	}
	for range probe {
		var payload wire.ClientPayload
		if err := publisher.ReadJSON(&payload); err != nil {
			t.Fatal(err)
		}
		ok, isOK := payload.SubscriptionResponse.(*wire.OkSubscriptionResponse)
		if !isOK || !ok.Accepted {
			t.Fatalf("probe event not accepted: %#v", payload.SubscriptionResponse)
		}
	}

	// The report's own comparison: a brand-new connection/subscription
	// against the same probe filter, opened *after* the probe events were
	// published, with nothing backlogged. It should observe them promptly.
	retry := createBackpressureWS(t, store)
	if err := retry.WriteJSON(wire.NewRequestPacket("sub-retry", CreateFilter([]int{9999}, 10))); err != nil {
		t.Fatal(err)
	}
	seenOnRetry := make(map[string]bool)
	ok := readUntil(t, retry, time.Now().Add(2*time.Second), func(sr wire.SubscriptionResponse) bool {
		if ev, isEvent := sr.(*wire.EventSubscriptionResponse); isEvent {
			seenOnRetry[ev.Event.ID] = true
		}
		return len(seenOnRetry) == len(probe)
	})
	if !ok {
		t.Fatalf("retry connection: only observed %d/%d probe events promptly", len(seenOnRetry), len(probe))
	}

	// Meanwhile `stalled` still hasn't delivered the probe events -- its
	// pipe is jammed behind sub-backlog. Confirm nothing is lost: draining
	// it now delivers everything exactly once.
	total := len(backlog) + len(probe)
	seen := make(map[string]int)
	eoseCount := 0
	drainDeadline := time.Now().Add(30 * time.Second)
	for len(seen) < total {
		remaining := time.Until(drainDeadline)
		if remaining <= 0 {
			t.Fatalf("stalled connection: timed out draining, got %d/%d events (eose=%d)", len(seen), total, eoseCount)
		}
		_ = stalled.SetReadDeadline(time.Now().Add(remaining))
		var payload wire.ClientPayload
		if err := stalled.ReadJSON(&payload); err != nil {
			t.Fatalf("stalled connection: read error while draining (got %d/%d events so far): %v", len(seen), total, err)
		}
		switch r := payload.SubscriptionResponse.(type) {
		case *wire.EventSubscriptionResponse:
			seen[r.Event.ID]++
		case *wire.EOSESubscriptionResponse:
			eoseCount++
		case *wire.NoticeSubscriptionResponse:
			t.Fatalf("stalled connection: unexpected NOTICE: %+v", r)
		case *wire.ClosedSubscriptionResponse:
			t.Fatalf("stalled connection: unexpected CLOSED: %+v", r)
		}
	}

	for _, ev := range backlog {
		if seen[ev.ID] != 1 {
			t.Fatalf("backlog event %s delivered %d times via the stalled connection, want exactly 1", ev.ID, seen[ev.ID])
		}
	}
	for _, ev := range probe {
		if seen[ev.ID] != 1 {
			t.Fatalf("probe event %s delivered %d times via the stalled connection, want exactly 1", ev.ID, seen[ev.ID])
		}
	}
	if eoseCount != 2 {
		t.Fatalf("got %d EOSE messages via the stalled connection, want exactly 2 (one per subscription)", eoseCount)
	}
}

// TestDataWriteTimeoutClosesAPermanentlyStuckReaderInsteadOfHangingForever
// is the regression test for the fix itself (config.go's
// defaultDataWriteTimeout, session.go's sendPacket): a reader that's
// genuinely gone, not just slow, used to jam a connection's outgoing pipe
// forever with no error, no log, no recovery.
//
// Configures short DataWriteTimeout/ControlWriteTimeout *and*
// Ping/PongTimeout (production defaults are far more generous) so the
// whole test finishes fast. Both matter: the write timeout alone only
// unblocks the outgoing goroutine -- a client that also never sends
// anything leaves the read side stuck until its own deadline (seeded from
// PongTimeout) expires, and Session.Close only runs once that read
// returns. Full teardown for a totally dead peer depends on both.
func TestDataWriteTimeoutClosesAPermanentlyStuckReaderInsteadOfHangingForever(t *testing.T) {
	backlog := CreateEvents(t, 150, 1)
	store := newStoreWithEvents(t, backlog)

	stalled, handler := createBackpressureWSWithOpts(t, store,
		WithSessionWriteTimeouts(300*time.Millisecond, 200*time.Millisecond),
		WithSessionPingConfig(1*time.Hour, 500*time.Millisecond)) // ping interval irrelevant here; only the initial PongTimeout-seeded read deadline matters

	if err := stalled.WriteJSON(wire.NewRequestPacket("sub-backlog", CreateFilter([]int{1}, 500))); err != nil {
		t.Fatal(err)
	}

	// Never read from `stalled` again. waitForSessionCount fails the test
	// if the session doesn't close within its own 2s budget -- comfortably
	// more than this test's sub-second configured timeouts need.
	waitForSessionCount(t, handler, 0)
}
