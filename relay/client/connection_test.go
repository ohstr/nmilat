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
	"github.com/ohstr/nmilat/nip01"
)

// testPrivKey is an arbitrary, never-funded key used only to sign throwaway
// events for these tests -- same one nip01's own event tests use.
const testPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// TestConnection_HandleDoesNotLeakWhenErrorsUnread is a regression guard for
// handle()'s error-reporting sends: every other channel operation in this
// file (outgoing, incoming, subscription dispatch) escapes via
// closeCh/ctx.Done() if nobody's listening, but the `c.errors <-` sends in
// handle()'s read loop and pingLoop used to be unconditional blocking
// sends. That's exactly what happens during ordinary shutdown -- the owner
// cancels ctx and stops its own error-consuming loop, then the connection
// notices the now-dead socket a moment later and tries to report it -- so a
// caller that isn't actively draining Errors() at that exact moment left
// the goroutine blocked forever with nothing left to unblock it.
//
// Each case drives a different one of the (previously) unconditional sends
// deterministically, rather than relying on hitting the original race by
// luck, and asserts the goroutine count returns to baseline instead of
// growing by roughly one per iteration.
func TestConnection_HandleDoesNotLeakWhenErrorsUnread(t *testing.T) {
	cases := []struct {
		name string
		// serverBehavior runs in the server's upgrade handler and decides
		// how the connection dies from the server's side.
		serverBehavior func(conn *websocket.Conn)
	}{
		{
			// No close frame -- ReadJSON fails with a plain net error,
			// landing in handle()'s `default:` branch. This is the
			// original bug report's exact goroutine dump (blocked at
			// connection.go's read-loop default case).
			name: "abrupt close (unrecognized read error)",
			serverBehavior: func(conn *websocket.Conn) {
				conn.Close()
			},
		},
		{
			// A real close frame -- ReadJSON fails with a recognized
			// websocket.IsCloseError, landing in handle()'s separate
			// `case websocket.IsCloseError(...)` branch, which had the
			// exact same unconditional-send bug as `default:` but is a
			// distinct code path worth guarding independently.
			name: "clean close (recognized close error)",
			serverBehavior: func(conn *websocket.Conn) {
				msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
				conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
				conn.Close()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			upgrader := websocket.Upgrader{}
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				// Give the client's Dial time to finish processing the
				// handshake response before yanking the connection out from
				// under it -- otherwise this races Connect() itself into
				// failing instead of succeeding and failing later on its
				// first read, which is the sequence under test.
				time.Sleep(20 * time.Millisecond)
				tc.serverBehavior(conn)
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
				// Deliberately never read conn.Errors() -- the failure mode
				// under test is exactly what happens when nobody's
				// listening anymore by the time the error arrives.
				time.Sleep(40 * time.Millisecond) // let the server-side close land
				cancel()
				conn.Close()
			}

			final := settledGoroutineCount()
			// A handful of goroutines transiently in flight (GC/runtime
			// workers, httptest's own connections) is normal; a leak here
			// reliably shows up as roughly +iterations, one stuck per
			// connection.
			if final > baseline+5 {
				t.Errorf("goroutine count after %d connect/error cycles = %d (baseline %d) -- an errors<- send appears to be leaking a goroutine per iteration", iterations, final, baseline)
			}
		})
	}
}

// TestConnection_HandleDoesNotLeakOnWriteTimeout guards the write-loop's own
// `c.errors <- fmt.Errorf("write: %w", err)` send (connection.go's writer
// goroutine) -- a separate code path from the read-loop cases above, hit
// when Send()/CloseSubscription() etc. hand the writer a packet but the
// actual network write itself fails (here, forced via a deliberately
// sub-microsecond WriteTimeout rather than relying on ever actually filling
// a kernel send buffer, which would be both slow and flaky across
// environments).
func TestConnection_HandleDoesNotLeakOnWriteTimeout(t *testing.T) {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Read (and discard) until the client disconnects, rather than
		// blocking on r.Context() -- gorilla's Upgrade hijacks the
		// connection, and a hijacked request's Context() doesn't get
		// cancelled just because the peer closed the TCP connection, which
		// otherwise leaves this handler goroutine (and this subtest's
		// httptest.Server) running well past the client side finishing.
		// A real read loop like this also doesn't get in the way of
		// forcing the client's write to fail: the deliberately
		// sub-microsecond WriteTimeout below expires before any real
		// write syscall can complete, read by a peer or not.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	u, err := url.Parse("ws" + server.URL[len("http"):])
	if err != nil {
		t.Fatal(err)
	}

	ev, err := nip01.NewSignedEvent(1, "hello", testPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	baseline := settledGoroutineCount()

	const iterations = 20
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		// A write deadline this tight has already passed by the time the
		// actual write syscall runs, regardless of buffer state or
		// environment -- deterministic, unlike waiting to exhaust a real
		// kernel send buffer.
		cfg := &ConnectionConfig{WriteTimeout: time.Nanosecond}
		conn, err := NewConnection(ctx, u, cfg)
		if err != nil {
			cancel()
			t.Fatalf("NewConnection() iteration %d error = %v", i, err)
		}
		conn.Send(ev)
		// Deliberately never read conn.Errors() -- let the writer's own
		// error send race against nobody listening.
		time.Sleep(40 * time.Millisecond)
		cancel()
		conn.Close()
	}

	final := settledGoroutineCount()
	if final > baseline+5 {
		t.Errorf("goroutine count after %d write-timeout cycles = %d (baseline %d) -- the writer's errors<- send appears to be leaking a goroutine per iteration", iterations, final, baseline)
	}
}

// TestConnection_ErrorsDeliveredWhenListened is the fix's other half: making
// the errors<- sends escape via closeCh/ctx.Done() when nobody's listening
// must not come at the cost of ever dropping a real error when a caller
// *is* actively reading Errors() -- select doesn't favor one ready case
// over another, but nothing here should make the errors<- case anything
// other than the only ready one when the connection is still open and a
// reader is waiting.
func TestConnection_ErrorsDeliveredWhenListened(t *testing.T) {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
		conn.Close()
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	u, err := url.Parse("ws" + server.URL[len("http"):])
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := Connect(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case err := <-conn.Errors():
		if err == nil {
			t.Error("Errors() delivered a nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Errors() never delivered the read error -- the fix may have over-guarded the send and dropped it instead of just adding an escape hatch")
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
