package nip98

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/ohstr/nmilat/nipLS"
)

// Sign through a remote signer: nipLS.Client verifies the event it gets
// back, NIP-13 proof of work included, so the anti-replay tag must not be
// a "nonce".
func TestSign_ThroughNIPLSClient(t *testing.T) {
	key, err := nipLS.NewLocalKey(testPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := nipLS.NewServer(nipLS.ServerConfig{Key: key, Policy: nipLS.AllowAll})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b := net.Pipe()
	go srv.ServeConn(ctx, a)
	c, err := nipLS.NewClient(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	for _, payload := range [][]byte{nil, []byte(`{"a":1}`)} {
		h, err := Sign(ctx, c, publicURL, "POST", payload)
		if err != nil {
			t.Fatalf("payload %q: %v", payload, err)
		}
		r := httptest.NewRequest("POST", publicURL, nil)
		r.Header.Set("Authorization", h)
		opts := Options{AllowedPubkeys: []string{key.PubKey()}, Body: payload, RequirePayload: payload != nil, Seen: NewSeenIDs(0)}
		if got, err := Verify(r, opts); err != nil || got != key.PubKey() {
			t.Fatalf("payload %q: %q, %v", payload, got, err)
		}
	}
}
