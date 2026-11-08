// Package testlogger wires a zerolog.Logger into testing.T/B so that
// production code's own log lines (session lifecycle, verification,
// migrations, etc.) show up correctly attributed to the (sub)test that
// triggered them -- hidden on pass, surfaced automatically on failure or
// with `go test -v` -- instead of being silenced or dumped raw to stdout.
//
// This package is exported (not under internal/) so consumers of this SDK
// can inject the same t.Log-routed logger into their own tests via
// relay.WithLogger / relay.WithEventStoreLogger, not just nmilat's own
// test suite.
package testlogger

import (
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

// writer forwards to t.Log until the test's cleanup runs, then drops lines.
// A goroutine the test started can outlive it (a hijacked WebSocket handler
// logging "session ended", which httptest.Server.Close does not wait for),
// and t.Log after the test completes races testing's own bookkeeping (and
// panics). The mutex makes the cleanup's flip happen-before any later Write.
type writer struct {
	t    testing.TB
	mu   sync.Mutex
	done bool
}

func (w *writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return len(p), nil
	}
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func (w *writer) stop() {
	w.mu.Lock()
	w.done = true
	w.mu.Unlock()
}

// New returns a zerolog.Logger that routes every log line through t.Log,
// formatted as human-readable console output rather than raw JSON. Lines
// written after t's cleanups start running are dropped, so a goroutine that
// outlives the test can keep logging safely. New must be called from the
// test's own goroutine (it registers a t.Cleanup).
func New(t testing.TB) zerolog.Logger {
	w := &writer{t: t}
	t.Cleanup(w.stop)
	console := zerolog.ConsoleWriter{Out: w, NoColor: true}
	return zerolog.New(console).With().Timestamp().Logger()
}
