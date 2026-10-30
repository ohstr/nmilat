package nip98

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
)

const (
	publicURL = "https://api.example.org/v1/items?watch=1"
	otherPriv = "5c2a8d1f3b6e47a90c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7"
)

var fixedNow = time.Unix(1_800_000_000, 0)

func clock() time.Time { return fixedNow }

// signed builds a header the way Sign does, then lets mutate change the
// event before (resign) or after signing.
func signed(t *testing.T, priv string, mutate func(*nip01.Event), resign bool) string {
	t.Helper()
	ev, err := newEvent(publicURL, "POST", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt = uint64(fixedNow.Unix())
	if mutate != nil && resign {
		mutate(ev)
	}
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if mutate != nil && !resign {
		mutate(ev)
	}
	h, err := encode(ev)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func setTag(name, value string) func(*nip01.Event) {
	return func(ev *nip01.Event) {
		for _, tag := range ev.Tags {
			if tag[0] == name {
				tag[1] = value
				return
			}
		}
		ev.Tags = append(ev.Tags, []string{name, value})
	}
}

// The request as it reaches a server behind a tunnel: plain http, an
// internal Host. Only ExpectURL can say what the client signed for.
func backendRequest(method, header string) *http.Request {
	r := httptest.NewRequest(method, "http://backend.internal:8080/v1/items?watch=1", strings.NewReader(`{"a":1}`))
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func strictOpts(seen *SeenIDs) Options {
	return Options{
		Body:           []byte(`{"a":1}`),
		RequirePayload: true,
		Window:         60 * time.Second,
		Seen:           seen,
		ExpectURL:      publicURL,
		ExpectMethod:   "POST",
		Now:            clock,
	}
}

func TestVerifyStrict_Refusals(t *testing.T) {
	sumOf := func(b string) string { s := sha256.Sum256([]byte(b)); return hex.EncodeToString(s[:]) }
	cases := []struct {
		name   string
		header string
		method string
		opts   func(Options) Options
		want   error
	}{
		{name: "accepted", header: signed(t, testPrivKey, nil, false)},
		{name: "no header", header: "", want: ErrMissingAuthHeader},
		{name: "not base64", header: "Nostr %%%", want: ErrMissingAuthHeader},
		{name: "not json", header: "Nostr " + base64.StdEncoding.EncodeToString([]byte("{")), want: ErrInvalidNIP98Event},
		{name: "wrong kind", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.Kind = 1 }, true), want: ErrInvalidNIP98Event},
		{name: "forged: tag changed after signing", header: signed(t, testPrivKey, setTag("u", "https://work.example.org/other"), false), want: ErrInvalidNIP98Event},
		{name: "forged: pubkey swapped", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.PubKey = mustPubkey(t, otherPriv) }, false), want: ErrInvalidNIP98Event},
		{name: "two minutes old", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt -= 120 }, true), want: ErrEventExpired},
		{name: "61 s old", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt -= 61 }, true), want: ErrEventExpired},
		{name: "60 s old is in", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt -= 60 }, true)},
		{name: "two minutes ahead", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt += 120 }, true), want: ErrEventExpired},
		{name: "created_at overflow", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt = 1 << 63 }, true), want: ErrEventExpired},
		{name: "narrower window", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt -= 20 }, true),
			opts: func(o Options) Options { o.Window = 10 * time.Second; return o }, want: ErrEventExpired},
		{name: "wrong u", header: signed(t, testPrivKey, setTag("u", "https://work.example.org/api/v1/namespaces/x-work/pods?watch=1"), true), want: ErrURLMismatch},
		{name: "u without query", header: signed(t, testPrivKey, setTag("u", "https://api.example.org/v1/items"), true), want: ErrURLMismatch},
		{name: "u http, not https", header: signed(t, testPrivKey, setTag("u", strings.Replace(publicURL, "https", "http", 1)), true), want: ErrURLMismatch},
		{name: "the request's own URL is not what was expected", header: signed(t, testPrivKey, setTag("u", "http://backend.internal:8080/v1/items?watch=1"), true), want: ErrURLMismatch},
		{name: "no u", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.Tags = ev.Tags[1:] }, true), want: ErrInvalidNIP98Event},
		{name: "wrong method tag", header: signed(t, testPrivKey, setTag("method", "GET"), true), want: ErrMethodMismatch},
		{name: "request method differs", header: signed(t, testPrivKey, nil, false), method: "PUT", want: ErrMethodMismatch},
		{name: "expected method differs", header: signed(t, testPrivKey, setTag("method", "PUT"), true), method: "PUT", want: ErrMethodMismatch},
		{name: "method case", header: signed(t, testPrivKey, setTag("method", "post"), true), want: ErrMethodMismatch},
		{name: "no payload tag", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.Tags = append(ev.Tags[:2], ev.Tags[3:]...) }, true), want: ErrMissingPayloadTag},
		{name: "payload of another body", header: signed(t, testPrivKey, setTag("payload", sumOf(`{"a":2}`)), true), want: ErrPayloadMismatch},
		{name: "a second, wrong payload tag", header: signed(t, testPrivKey, func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{"payload", sumOf("x")}) }, true), want: ErrPayloadMismatch},
		{name: "body swapped by the server's caller", header: signed(t, testPrivKey, nil, false),
			opts: func(o Options) Options { o.Body = []byte(`{"a":2}`); return o }, want: ErrPayloadMismatch},
		{name: "not an allowed pubkey", header: signed(t, otherPriv, nil, false),
			opts: func(o Options) Options { o.AllowedPubkeys = []string{mustPubkey(t, testPrivKey)}; return o }, want: ErrWrongPubkey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = "POST"
			}
			opts := strictOpts(NewSeenIDs(0))
			if tc.opts != nil {
				opts = tc.opts(opts)
			}
			r := backendRequest(method, tc.header)
			var pub string
			var err error
			if len(opts.AllowedPubkeys) > 0 {
				pub, err = Verify(r, opts)
			} else {
				pub, err = VerifyAnyPubkey(r, opts)
			}
			if tc.want == nil {
				if err != nil || pub != mustPubkey(t, testPrivKey) {
					t.Fatalf("got %q, %v; want accepted", pub, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if opts.Seen.Len() != 0 {
				t.Fatal("a refused event took a place in the replay cache")
			}
		})
	}
}

func TestVerifyStrict_ReplayRefused(t *testing.T) {
	seen := NewSeenIDs(0)
	h := signed(t, testPrivKey, nil, false)
	if _, err := VerifyAnyPubkey(backendRequest("POST", h), strictOpts(seen)); err != nil {
		t.Fatal(err)
	}
	// The same header again, at once and at the window's last second.
	for _, d := range []time.Duration{0, 30 * time.Second, 60 * time.Second} {
		o := strictOpts(seen)
		o.Now = func() time.Time { return fixedNow.Add(d) }
		if _, err := VerifyAnyPubkey(backendRequest("POST", h), o); !errors.Is(err, ErrReplayed) {
			t.Fatalf("replay +%s: %v, want ErrReplayed", d, err)
		}
	}
	// Past the window it is refused as expired, never accepted again.
	o := strictOpts(seen)
	o.Now = func() time.Time { return fixedNow.Add(61 * time.Second) }
	if _, err := VerifyAnyPubkey(backendRequest("POST", h), o); !errors.Is(err, ErrEventExpired) {
		t.Fatalf("after the window: %v", err)
	}
	// Another login of the same request, same second: its own salt, its own id.
	h2 := signed(t, testPrivKey, nil, false)
	if _, err := VerifyAnyPubkey(backendRequest("POST", h2), strictOpts(seen)); err != nil {
		t.Fatalf("a second login was taken for a replay: %v", err)
	}
	// Without a cache the same header passes twice: replay refusal is opt-in.
	for range 2 {
		o := strictOpts(nil)
		if _, err := VerifyAnyPubkey(backendRequest("POST", h), o); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyStrict_ConcurrentReplayOnlyOneWins(t *testing.T) {
	seen := NewSeenIDs(0)
	h := signed(t, testPrivKey, nil, false)
	var ok, replayed atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := VerifyAnyPubkey(backendRequest("POST", h), strictOpts(seen))
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrReplayed):
				replayed.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || replayed.Load() != 31 {
		t.Fatalf("accepted %d, replayed %d; want 1 and 31", ok.Load(), replayed.Load())
	}
}

func TestSeenIDs_BoundedAndSwept(t *testing.T) {
	s := NewSeenIDs(2)
	now := fixedNow
	if err := s.Use("a", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Use("b", now.Add(2*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := s.Use("c", now.Add(time.Minute), now); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache took a new id: %v", err)
	}
	if err := s.Use("a", now.Add(time.Minute), now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay in a full cache: %v", err)
	}
	// After a's lifetime a sweep frees its place; b stays spent.
	later := now.Add(time.Minute)
	if err := s.Use("c", later.Add(time.Minute), later); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if err := s.Use("b", later.Add(time.Minute), later); !errors.Is(err, ErrReplayed) {
		t.Fatalf("b forgotten early: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("len %d", s.Len())
	}
}

func TestVerify_DefaultWindowIs60s(t *testing.T) {
	o := Options{Now: clock}
	for _, d := range []int64{-60, 60} {
		h := signed(t, testPrivKey, func(ev *nip01.Event) { ev.CreatedAt = uint64(fixedNow.Unix() + d) }, true)
		r := httptest.NewRequest("POST", publicURL, nil)
		r.Header.Set("Authorization", h)
		if _, err := VerifyAnyPubkey(r, o); err != nil {
			t.Fatalf("%+d s: %v", d, err)
		}
	}
}

// Sign goes through any event signer: a key here, or a NIP-46/NIP-LS one.
func TestSign_ThroughSigner(t *testing.T) {
	key, err := nip46.NewLocalKey(testPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, payload := range [][]byte{nil, {}, []byte(`{"a":1}`)} {
		h, err := Sign(ctx, key, publicURL, "POST", payload)
		if err != nil {
			t.Fatal(err)
		}
		ev := decodeHeader(t, h)
		if ev.Kind != KindHTTPAuth || ev.PubKey != key.PubKey() {
			t.Fatalf("event %+v", ev)
		}
		var salt, pl int
		for _, tag := range ev.Tags {
			switch tag[0] {
			case "salt":
				salt++
			case "payload":
				pl++
			}
		}
		if salt != 1 || (payload == nil) != (pl == 0) {
			t.Fatalf("payload %q: tags %v", payload, ev.Tags)
		}
		r := httptest.NewRequest("POST", publicURL, nil)
		r.Header.Set("Authorization", h)
		opts := Options{AllowedPubkeys: []string{key.PubKey()}, Body: payload, RequirePayload: payload != nil, Seen: NewSeenIDs(0)}
		if got, err := Verify(r, opts); err != nil || got != key.PubKey() {
			t.Fatalf("payload %q: %q, %v", payload, got, err)
		}
	}
	if _, err := Sign(ctx, nil, publicURL, "GET", nil); !errors.Is(err, ErrNoSigner) {
		t.Fatal(err)
	}
	if _, err := Sign(ctx, failingSigner{}, publicURL, "GET", nil); err == nil {
		t.Fatal("a signer's refusal became a header")
	}
}

type failingSigner struct{}

func (failingSigner) Sign(context.Context, *nip01.Event) error { return fmt.Errorf("denied") }

func decodeHeader(t *testing.T, h string) *nip01.Event {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
	if err != nil {
		t.Fatal(err)
	}
	var ev nip01.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	return &ev
}

func mustPubkey(t *testing.T, priv string) string {
	t.Helper()
	ev := &nip01.Event{}
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev.PubKey
}
