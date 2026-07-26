package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestConnection_HandleDoesNotLeakWhenErrorsUnread is a regression guard for
// handle()'s read-error path: every other channel operation in this file
// (outgoing, incoming, subscription dispatch) escapes via
// closeCh/ctx.Done() if nobody's listening, but the `c.errors <-` sends in
// handle()'s read loop and pingLoop used to be unconditional blocking
// sends. That's exactly what happens during ordinary shutdown -- the owner
// cancels ctx and stops its own error-consuming loop, then the read loop
// notices the now-dead socket and tries to report it -- so a caller that
// isn't actively draining Errors() at that exact moment left the goroutine
// blocked forever with nothing left to unblock it.
//
// This drives that exact sequence deterministically (abrupt server-side
// close, Errors() never read) many times over, rather than relying on
// hitting the original race by luck, and asserts the goroutine count
// returns to baseline instead of growing by roughly one per iteration.
func TestConnection_HandleDoesNotLeakWhenErrorsUnread(t *testing.T) {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// Give the client's Dial time to finish processing the handshake
		// response before yanking the connection out from under it --
		// otherwise this races Connect() itself into failing instead of
		// succeeding and failing later on its first read, which is the
		// sequence under test.
		time.Sleep(20 * time.Millisecond)
		// An abrupt close (no close frame) so the client's ReadJSON fails
		// with a plain net error, not a recognized close error -- landing
		// in handle()'s `default:` branch (connection.go), the same one
		// the original bug report's goroutine dump pointed at.
		conn.Close()
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	u, err := url.Parse("ws" + server.URL[len("http"):])
	if err != nil {
		t.Fatal(err)
	}

	baseline := settledGoroutineCount()

	const iterations = 20
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn, err := Connect(ctx, u)
		if err != nil {
			cancel()
			t.Fatalf("Connect() iteration %d error = %v", i, err)
		}
		// Deliberately never read conn.Errors() -- the failure mode under
		// test is exactly what happens when nobody's listening anymore by
		// the time the read error arrives.
		time.Sleep(40 * time.Millisecond) // let the server-side close land
		cancel()
		conn.Close()
	}

	final := settledGoroutineCount()
	// A handful of goroutines transiently in flight (GC/runtime workers,
	// httptest's own connections) is normal; a leak here reliably shows up
	// as roughly +iterations, one stuck per connection.
	if final > baseline+5 {
		t.Errorf("goroutine count after %d connect/error cycles = %d (baseline %d) -- handle()'s errors<- send appears to be leaking a goroutine per iteration", iterations, final, baseline)
	}
}

// settledGoroutineCount samples runtime.NumGoroutine() after giving
// recently-unblocked goroutines a chance to actually finish exiting --
// closing a connection or cancelling its context only wakes a blocked
// goroutine, it doesn't make it vanish from the count until the scheduler
// actually runs it to completion.
func settledGoroutineCount() int {
	for i := 0; i < 10; i++ {
		runtime.Gosched()
		time.Sleep(20 * time.Millisecond)
	}
	runtime.GC()
	return runtime.NumGoroutine()
}
