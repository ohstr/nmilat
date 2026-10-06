package relay

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/rs/zerolog"
)

// TestNewSessionHandler_WarnsWhenNIP29RegisteredWithoutURL and its sibling
// below are the regression test for an operator footgun found while
// investigating a real report: a relay hosting NIP-29 groups with no
// nip11.url configured has every private group (the default on creation)
// invisible even to its own creator, because NIP-42 AUTH silently fails
// its relay-tag check against an empty URL. Nothing short of reading the
// NIP-42 spec closely would tell an operator that -- so NewSessionHandler
// now warns at startup instead of leaving it to be discovered the hard
// way.
//
// RegisterNIP(29) has no unregister (relay/capabilities.go's own doc
// comment), so this registration is process-wide and permanent for the
// rest of this test binary -- harmless here since no other test in this
// package asserts NIP 29's absence from the registry.
func TestNewSessionHandler_WarnsWhenNIP29RegisteredWithoutURL(t *testing.T) {
	RegisterNIP(29)

	store, err := NewEventStore(filepath.Join(t.TempDir(), "test.db"), &nip11.Limitation{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	NewSessionHandler(store, &nip11.Metadata{}, nil, WithLogger(logger))

	if !strings.Contains(logBuf.String(), "nip11.url is not set") {
		t.Errorf("startup log = %q, want a warning about nip11.url being unset", logBuf.String())
	}
}

func TestNewSessionHandler_NoWarnWhenURLSet(t *testing.T) {
	RegisterNIP(29)

	store, err := NewEventStore(filepath.Join(t.TempDir(), "test.db"), &nip11.Limitation{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)

	NewSessionHandler(store, &nip11.Metadata{URL: "wss://relay.example.com"}, nil, WithLogger(logger))

	if strings.Contains(logBuf.String(), "nip11.url is not set") {
		t.Errorf("startup log = %q, want no nip11.url warning once it's configured", logBuf.String())
	}
}
