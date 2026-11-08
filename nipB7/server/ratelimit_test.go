package server

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipB7"
	"github.com/ohstr/nmilat/relay/ratelimit"
)

func TestRateLimitIsOffByDefault(t *testing.T) {
	f := newFixture(t, nil)
	if f.srv.opt.RateLimit != nil {
		t.Fatal("RateLimit set by default")
	}
	if f.srv.opt.MaxBlobBytes != 100<<20 || f.srv.opt.MaxUploadsPerSigner != 2 || f.srv.opt.MaxUploads != 8 {
		t.Fatalf("defaults changed: %d bytes, %d per signer, %d uploads", f.srv.opt.MaxBlobBytes, f.srv.opt.MaxUploadsPerSigner, f.srv.opt.MaxUploads)
	}
	blob := []byte("unlimited")
	for range 30 {
		wantStatus(t, f.upload(memberPriv, blob), http.StatusOK)
		wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(blob), "", nil, nil), http.StatusOK)
	}
}

func TestRateLimitAskedPerIPThenPerSigner(t *testing.T) {
	type call struct {
		upload bool
		pubkey string
	}
	var mu sync.Mutex
	var calls []call
	f := newFixture(t, func(o *Options) {
		o.RateLimit = func(r *http.Request, upload bool, pubkey string) (time.Duration, bool) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, call{upload, pubkey})
			return 0, true
		}
	})
	blob := []byte("asked")
	wantStatus(t, f.upload(memberPriv, blob), http.StatusOK)
	wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(blob), "", nil, nil), http.StatusOK)
	member := pub(t, memberPriv)
	want := []call{{true, ""}, {true, member}, {false, ""}}
	if len(calls) != len(want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls %v, want %v", calls, want)
		}
	}
}

func TestRateLimitRefusesWith429(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.RateLimit = func(*http.Request, bool, string) (time.Duration, bool) { return 2500 * time.Millisecond, false }
	})
	blob := []byte("refused")
	for i, resp := range []*http.Response{
		f.upload(memberPriv, blob),
		f.do(http.MethodGet, "/media/"+hashOf(blob), "", nil, nil),
		f.do(http.MethodDelete, "/media/"+hashOf(blob), "", nil, nil),
	} {
		wantStatus(t, resp, http.StatusTooManyRequests)
		if got := resp.Header.Get("Retry-After"); got != "3" {
			t.Fatalf("Retry-After %q, want 3", got)
		}
		want := ratelimit.Message(ratelimit.Download)
		if i == 0 {
			want = ratelimit.Message(ratelimit.Upload)
		}
		if got := resp.Header.Get(nipB7.HeaderReason); got != want {
			t.Fatalf("reason %q, want %q", got, want)
		}
	}
}

func TestRateLimitWithLimiter(t *testing.T) {
	lim, err := ratelimit.New(ratelimit.Config{
		Upload:   ratelimit.Limit{PerPubkey: ratelimit.Rate{Events: 2, Per: time.Hour}},
		Download: ratelimit.Limit{PerIP: ratelimit.Rate{Events: 3, Per: time.Hour}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, func(o *Options) { o.RateLimit = lim.AllowBlossom })
	blobs := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	wantStatus(t, f.upload(memberPriv, blobs[0]), http.StatusOK)
	wantStatus(t, f.upload(memberPriv, blobs[1]), http.StatusOK)
	wantStatus(t, f.upload(memberPriv, blobs[2]), http.StatusTooManyRequests)
	// Another signer has its own budget.
	wantStatus(t, f.upload(adminPriv, blobs[2]), http.StatusOK)

	for range 3 {
		wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(blobs[0]), "", nil, nil), http.StatusOK)
	}
	wantStatus(t, f.do(http.MethodHead, "/media/"+hashOf(blobs[0]), "", nil, nil), http.StatusTooManyRequests)
}
