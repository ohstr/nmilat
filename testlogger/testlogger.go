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
	"testing"

	"github.com/rs/zerolog"
)

type writer struct {
	t testing.TB
}

func (w writer) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// New returns a zerolog.Logger that routes every log line through t.Log,
// formatted as human-readable console output rather than raw JSON.
func New(t testing.TB) zerolog.Logger {
	console := zerolog.ConsoleWriter{Out: writer{t: t}, NoColor: true}
	return zerolog.New(console).With().Timestamp().Logger()
}
