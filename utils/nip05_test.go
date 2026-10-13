package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const nip05TestPubkey = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"

func nip05TestServer(t *testing.T, wantName string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/nostr.json" || r.URL.Query().Get("name") != wantName {
			t.Errorf("unexpected request: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{
			"names": {"bob": "` + nip05TestPubkey + `", "_": "` + nip05TestPubkey + `", "bad": "xyz"},
			"relays": {"` + nip05TestPubkey + `": ["wss://relay.example.com"]}
		}`))
	}))
}

func resolveTestNip05(t *testing.T, server *httptest.Server, id string) (string, []string, error) {
	t.Helper()
	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	return ResolveNip05(context.Background(), client, id)
}

func TestResolveNip05(t *testing.T) {
	for _, tc := range []struct{ id, name string }{
		{"bob@example.com", "bob"},
		{"Bob@example.com", "Bob"}, // case-insensitive match
		{"example.com", "_"},
		{"_@example.com", "_"},
	} {
		server := nip05TestServer(t, tc.name)
		pubkey, relays, err := resolveTestNip05(t, server, tc.id)
		server.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if pubkey != nip05TestPubkey {
			t.Errorf("%s: pubkey = %s", tc.id, pubkey)
		}
		if len(relays) != 1 || relays[0] != "wss://relay.example.com" {
			t.Errorf("%s: relays = %v", tc.id, relays)
		}
	}
}

func TestResolveNip05Errors(t *testing.T) {
	for _, tc := range []struct{ id, name string }{
		{"alice@example.com", "alice"}, // not listed
		{"bad@example.com", "bad"},     // not a pubkey
	} {
		server := nip05TestServer(t, tc.name)
		_, _, err := resolveTestNip05(t, server, tc.id)
		server.Close()
		if err == nil {
			t.Errorf("%s: expected an error", tc.id)
		}
	}
	if _, _, err := ResolveNip05(context.Background(), http.DefaultClient, "@example.com"); err == nil {
		t.Error("empty name: expected an error")
	}
}
