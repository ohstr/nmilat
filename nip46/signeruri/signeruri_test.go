package signeruri

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip46/bunker"
	"github.com/ohstr/nmilat/nipLS"
	"github.com/ohstr/nmilat/relay"
)

const userPriv = "0000000000000000000000000000000000000000000000000000000000000003"

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func note() *nip01.Event {
	return &nip01.Event{Kind: 1, Content: "hi", Tags: [][]string{}, CreatedAt: 1700000000}
}

func signAndClose(t *testing.T, s nip46.Signer) {
	t.Helper()
	ev := note()
	if err := s.Sign(ctx5(t), ev); err != nil {
		t.Fatal(err)
	}
	if err := ev.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := s.(io.Closer).Close(); err != nil {
		t.Error(err)
	}
}

// startLocal serves a NIP-LS signer and returns its socket path.
func startLocal(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "suri")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	k, _ := nipLS.NewLocalKey(userPriv)
	srv, err := nipLS.NewServer(nipLS.ServerConfig{Key: k, Policy: nipLS.AllowAll})
	if err != nil {
		t.Fatal(err)
	}
	l, err := nipLS.Listen(path, nipLS.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

// startBunker serves a NIP-46 signer on an in-process relay and returns a
// fresh bunker:// URI for it.
func startBunker(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "suri-relay-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	rl, err := relay.New(f.Name(), &nip11.Metadata{Name: "test", Limitation: nip11.Limitation{MaxMessageLength: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(rl)
	t.Cleanup(func() { hs.Close(); _ = rl.Close() })
	k, _ := nip46.NewLocalKey(userPriv)
	srv, err := bunker.NewServer(bunker.ServerConfig{
		Key: k, Relays: []string{"ws://" + hs.Listener.Addr().String()},
		Policy: bunker.PolicyFunc(func(context.Context, *bunker.Call) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st := srv.RelayStatuses(); len(st) > 0 && st[0].Connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay never connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	uri, err := srv.NewBunkerURI(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

// T16-19 (LS-ADDR-02).
func TestDialRoutesByScheme(t *testing.T) {
	path := startLocal(t)
	for _, uri := range []string{nipLS.FormatURI(path), "unix://" + path, path} {
		s, err := Dial(ctx5(t), uri, bunker.ClientOptions{})
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if _, ok := s.(*nipLS.Client); !ok {
			t.Fatalf("%s gave a %T", uri, s)
		}
		signAndClose(t, s)
	}

	s, err := Dial(ctx5(t), startBunker(t), bunker.ClientOptions{Perms: "sign_event:1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*bunker.Client); !ok {
		t.Fatalf("bunker:// gave a %T", s)
	}
	signAndClose(t, s)

	for _, bad := range []string{"bunker+unix://relative.sock", "relative.sock", "bunker+unix://" + path + "?secret=x"} {
		if s, err := Dial(ctx5(t), bad, bunker.ClientOptions{}); err == nil || s != nil {
			t.Errorf("%s: %v, %v", bad, s, err)
		}
	}
	for _, bad := range []string{"https://example.com/signer", "nostrconnect://" + path} {
		if s, err := Dial(ctx5(t), bad, bunker.ClientOptions{}); !errors.Is(err, ErrUnsupportedScheme) || s != nil {
			t.Errorf("%s: %v, %v", bad, s, err)
		}
	}
	// A failed dial returns a nil interface, not a typed nil.
	if s, err := Dial(ctx5(t), "bunker://nothex?relay=wss://r", bunker.ClientOptions{}); err == nil || s != nil {
		t.Errorf("bad bunker URI: %v, %v", s, err)
	}
}
