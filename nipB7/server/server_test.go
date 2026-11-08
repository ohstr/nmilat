package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipB7"
	"github.com/ohstr/nmilat/utils"
)

const (
	memberPriv   = "0000000000000000000000000000000000000000000000000000000000000001"
	strangerPriv = "0000000000000000000000000000000000000000000000000000000000000002"
	adminPriv    = "0000000000000000000000000000000000000000000000000000000000000003"
)

func pub(t *testing.T, priv string) string {
	t.Helper()
	pk, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type fixture struct {
	t   *testing.T
	ts  *httptest.Server
	srv *Server
}

func newFixture(t *testing.T, tweak func(*Options)) *fixture {
	t.Helper()
	store, err := NewDirStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	member, admin := pub(t, memberPriv), pub(t, adminPriv)
	opt := Options{
		Store:       store,
		PublicURL:   ts.URL,
		UploadPaths: []string{"/upload", "/media/upload"},
		BlobPrefix:  "/media",
		MayUpload:   func(pk string) bool { return pk == member || pk == admin },
		IsAdmin:     func(pk string) bool { return pk == admin },
		TempDir:     t.TempDir(),
	}
	if tweak != nil {
		tweak(&opt)
	}
	srv, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	srv.Register(mux)
	return &fixture{t: t, ts: ts, srv: srv}
}

// token signs a kind 24242 authorization; servers nil means this server.
func (f *fixture) token(priv, verb string, hashes, servers []string, expires time.Time) string {
	f.t.Helper()
	if servers == nil {
		servers = []string{strings.TrimPrefix(f.ts.URL, "http://")}
	}
	ev := nipB7.NewAuthorization(nipB7.AuthorizationParams{
		Pubkey: pub(f.t, priv), Verb: verb, Expiration: expires, Servers: servers, Hashes: hashes,
	})
	if err := ev.Sign(priv); err != nil {
		f.t.Fatal(err)
	}
	h, err := nipB7.EncodeAuthHeader(ev)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *fixture) do(method, path, auth string, body io.Reader, header map[string]string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.ts.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (f *fixture) upload(priv string, blob []byte) *http.Response {
	f.t.Helper()
	auth := f.token(priv, nipB7.VerbUpload, []string{hashOf(blob)}, nil, time.Now().Add(time.Minute))
	return f.do(http.MethodPut, "/upload", auth, bytes.NewReader(blob), map[string]string{"Content-Type": "text/plain"})
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d (%s), want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, resp.Header.Get(nipB7.HeaderReason), want)
	}
}

func TestUploadAndDownload(t *testing.T) {
	f := newFixture(t, nil)
	blob := []byte("hello blossom")
	resp := f.upload(memberPriv, blob)
	wantStatus(t, resp, http.StatusOK)

	var d nipB7.BlobDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil || d.Sha256 != hashOf(blob) || d.Size != int64(len(blob)) || d.Type != "text/plain" {
		t.Fatalf("descriptor %+v (%v)", d, err)
	}
	if d.URL != f.ts.URL+"/media/"+d.Sha256 {
		t.Fatalf("url %s", d.URL)
	}

	get := f.do(http.MethodGet, "/media/"+d.Sha256, "", nil, nil)
	wantStatus(t, get, http.StatusOK)
	if got, _ := io.ReadAll(get.Body); !bytes.Equal(got, blob) {
		t.Fatalf("downloaded %q", got)
	}
	if get.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("download lacks CORS")
	}

	withExt := f.do(http.MethodGet, "/media/"+d.Sha256+".txt", "", nil, nil)
	wantStatus(t, withExt, http.StatusOK)

	head := f.do(http.MethodHead, "/media/"+d.Sha256, "", nil, nil)
	wantStatus(t, head, http.StatusOK)
	if head.ContentLength != int64(len(blob)) {
		t.Fatalf("HEAD length %d", head.ContentLength)
	}

	part := f.do(http.MethodGet, "/media/"+d.Sha256, "", nil, map[string]string{"Range": "bytes=6-12"})
	wantStatus(t, part, http.StatusPartialContent)
	if got, _ := io.ReadAll(part.Body); string(got) != "blossom" {
		t.Fatalf("range read %q", got)
	}
	wantStatus(t, f.do(http.MethodGet, "/media/"+d.Sha256, "", nil, map[string]string{"Range": "bytes=100-200"}), http.StatusRequestedRangeNotSatisfiable)

	for _, p := range []string{"/media/nothash", "/media/" + d.Sha256 + ".toolongext", "/media/" + strings.ToUpper(d.Sha256), "/media/" + hashOf([]byte("absent"))} {
		wantStatus(t, f.do(http.MethodGet, p, "", nil, nil), http.StatusNotFound)
	}

	// The same blob again: same descriptor, a second owner, no error.
	wantStatus(t, f.upload(adminPriv, blob), http.StatusOK)
	if n := len(f.srv.locks); n != 0 {
		t.Fatalf("%d blob locks left after the requests finished", n)
	}
}

func TestUploadRefusals(t *testing.T) {
	f := newFixture(t, nil)
	blob := []byte("refused")
	sha := hashOf(blob)
	soon := time.Now().Add(time.Minute)
	put := func(auth string, header map[string]string) *http.Response {
		return f.do(http.MethodPut, "/upload", auth, bytes.NewReader(blob), header)
	}

	wantStatus(t, put("", nil), http.StatusUnauthorized)
	wantStatus(t, put(f.token(strangerPriv, nipB7.VerbUpload, []string{sha}, nil, soon), nil), http.StatusForbidden)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, []string{sha}, []string{"other.example"}, soon), nil), http.StatusForbidden)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, []string{sha}, []string{}, soon), nil), http.StatusForbidden)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, []string{sha}, nil, time.Now().Add(-time.Minute)), nil), http.StatusUnauthorized)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, nil, nil, soon), nil), http.StatusUnauthorized)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, []string{hashOf([]byte("else"))}, nil, soon), nil), http.StatusForbidden)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbGet, []string{sha}, nil, soon), nil), http.StatusUnauthorized)
	wantStatus(t, put(f.token(memberPriv, nipB7.VerbUpload, []string{sha}, nil, soon), map[string]string{nipB7.HeaderSHA256: hashOf([]byte("x"))}), http.StatusBadRequest)

	wantStatus(t, f.do(http.MethodGet, "/media/"+sha, "", nil, nil), http.StatusNotFound)
}

func TestUploadTooLarge(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxBlobBytes = 8 })
	wantStatus(t, f.upload(memberPriv, []byte("more than eight bytes")), http.StatusRequestEntityTooLarge)
}

// holdUpload starts an upload of blob signed by priv and holds it in flight,
// part of the body sent, until the returned finish sends the rest and
// returns the response; finish may be called more than once. A test that
// ends while the upload is held, a failed assertion included, aborts it
// before the server closes, so closing the server does not wait on it.
func (f *fixture) holdUpload(priv string, blob []byte) (finish func() *http.Response) {
	f.t.Helper()
	auth := f.token(priv, nipB7.VerbUpload, []string{hashOf(blob)}, nil, time.Now().Add(time.Minute))
	before := len(f.srv.slots)
	pr, pw := io.Pipe()
	done := make(chan *http.Response, 1)
	var (
		once sync.Once
		resp *http.Response
	)
	// Registered after newFixture's ts.Close, so it runs before it.
	f.t.Cleanup(func() {
		_ = pw.CloseWithError(errors.New("test ended"))
		once.Do(func() {
			select {
			case r := <-done:
				if r != nil {
					_ = r.Body.Close()
				}
			case <-time.After(5 * time.Second):
			}
		})
	})
	go func() {
		req, _ := http.NewRequest(http.MethodPut, f.ts.URL+"/upload", pr)
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- nil
			return
		}
		done <- resp
	}()
	_, _ = pw.Write(blob[:1])
	for deadline := time.Now().Add(5 * time.Second); len(f.srv.slots) == before; {
		if time.Now().After(deadline) {
			f.t.Fatal("held upload never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return func() *http.Response {
		f.t.Helper()
		once.Do(func() {
			_, _ = pw.Write(blob[1:])
			_ = pw.Close()
			resp = <-done
			if resp != nil {
				f.t.Cleanup(func() { _ = resp.Body.Close() })
			}
		})
		if resp == nil {
			f.t.Fatal("held upload failed")
		}
		return resp
	}
}

func wantTooManyUploads(t *testing.T, resp *http.Response) {
	t.Helper()
	wantStatus(t, resp, http.StatusTooManyRequests)
	if got := resp.Header.Get(nipB7.HeaderReason); got != "too many uploads in flight" {
		t.Fatalf("reason %q", got)
	}
}

func TestUploadsInFlightPerSigner(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxUploadsPerSigner = 1 })
	finish := f.holdUpload(memberPriv, []byte("slow upload"))

	wantTooManyUploads(t, f.upload(memberPriv, []byte("second")))

	wantStatus(t, finish(), http.StatusOK)
	wantStatus(t, f.upload(memberPriv, []byte("third")), http.StatusOK)
}

func TestUploadsInFlightOverall(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxUploads = 1 })
	finish := f.holdUpload(memberPriv, []byte("slow upload"))

	// Another signer, under its own per-signer cap, still finds no slot.
	wantTooManyUploads(t, f.upload(adminPriv, []byte("second")))
	f.srv.mu.Lock()
	n := f.srv.inFlight[pub(t, adminPriv)]
	f.srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("refused upload left %d in flight for its signer", n)
	}

	wantStatus(t, finish(), http.StatusOK)
	wantStatus(t, f.upload(adminPriv, []byte("third")), http.StatusOK)
}

// TestDefaultLimits checks the caps Options gets when it leaves them 0:
// 100 MiB a blob, 2 uploads in flight per signer, 8 overall.
func TestDefaultLimits(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MayUpload = nil })

	// A declared length over 100 MiB is refused before any body is sent:
	// the body never yields a byte, so reading it would hang.
	auth := f.token(memberPriv, nipB7.VerbUpload, []string{hashOf([]byte("big"))}, nil, time.Now().Add(time.Minute))
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	req, err := http.NewRequest(http.MethodPut, f.ts.URL+"/upload", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 100<<20 + 1
	req.Header.Set("Authorization", auth)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	wantStatus(t, resp, http.StatusRequestEntityTooLarge)
	if got := resp.Header.Get(nipB7.HeaderReason); got != fmt.Sprintf("blobs are limited to %d bytes", 100<<20) {
		t.Fatalf("reason %q", got)
	}

	// Two in flight per signer.
	privs := []string{memberPriv, strangerPriv, adminPriv, "0000000000000000000000000000000000000000000000000000000000000004", "0000000000000000000000000000000000000000000000000000000000000005"}
	var finishes []func() *http.Response
	hold := func(priv string, i int) {
		finishes = append(finishes, f.holdUpload(priv, []byte(fmt.Sprintf("held %s %d", priv[len(priv)-1:], i))))
	}
	hold(privs[0], 0)
	hold(privs[0], 1)
	wantTooManyUploads(t, f.upload(privs[0], []byte("third from one signer")))

	// Eight in flight overall, across signers each under their own cap.
	for _, priv := range privs[1:4] {
		hold(priv, 0)
		hold(priv, 1)
	}
	if n := len(f.srv.slots); n != 8 {
		t.Fatalf("%d uploads in flight, want 8", n)
	}
	wantTooManyUploads(t, f.upload(privs[4], []byte("ninth overall")))

	for _, finish := range finishes {
		wantStatus(t, finish(), http.StatusOK)
	}
	wantStatus(t, f.upload(privs[4], []byte("after the others")), http.StatusOK)
}

func TestMembersOnlyDownload(t *testing.T) {
	member := ""
	f := newFixture(t, func(o *Options) {
		member = pub(t, memberPriv)
		o.MayDownload = func(pk string) bool { return pk == member }
	})
	blob := []byte("members only")
	wantStatus(t, f.upload(memberPriv, blob), http.StatusOK)
	path := "/media/" + hashOf(blob)
	soon := time.Now().Add(time.Minute)

	wantStatus(t, f.do(http.MethodGet, path, "", nil, nil), http.StatusUnauthorized)
	wantStatus(t, f.do(http.MethodGet, path, f.token(strangerPriv, nipB7.VerbGet, nil, nil, soon), nil, nil), http.StatusForbidden)
	wantStatus(t, f.do(http.MethodGet, path, f.token(memberPriv, nipB7.VerbGet, []string{hashOf([]byte("other"))}, nil, soon), nil, nil), http.StatusForbidden)
	wantStatus(t, f.do(http.MethodGet, path, f.token(memberPriv, nipB7.VerbGet, nil, nil, soon), nil, nil), http.StatusOK)
}

func TestDelete(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		stranger := pub(t, strangerPriv)
		prev := o.MayUpload
		o.MayUpload = func(pk string) bool { return pk == stranger || prev(pk) }
	})
	soon := time.Now().Add(time.Minute)
	del := func(priv string, blob []byte) *http.Response {
		sha := hashOf(blob)
		return f.do(http.MethodDelete, "/media/"+sha, f.token(priv, nipB7.VerbDelete, []string{sha}, nil, soon), nil, nil)
	}

	shared := []byte("shared")
	wantStatus(t, f.upload(memberPriv, shared), http.StatusOK)
	wantStatus(t, f.upload(strangerPriv, shared), http.StatusOK)
	wantStatus(t, del(strangerPriv, shared), http.StatusOK)
	// Another uploader still holds it.
	wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(shared), "", nil, nil), http.StatusOK)
	wantStatus(t, del(strangerPriv, shared), http.StatusForbidden)
	wantStatus(t, del(memberPriv, shared), http.StatusOK)
	wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(shared), "", nil, nil), http.StatusNotFound)

	mine := []byte("mine")
	wantStatus(t, f.upload(memberPriv, mine), http.StatusOK)
	wantStatus(t, del(strangerPriv, mine), http.StatusForbidden)
	wantStatus(t, del(adminPriv, mine), http.StatusOK)
	wantStatus(t, f.do(http.MethodGet, "/media/"+hashOf(mine), "", nil, nil), http.StatusNotFound)

	// A delete token must name the hash.
	gone := []byte("named")
	wantStatus(t, f.upload(memberPriv, gone), http.StatusOK)
	wantStatus(t, f.do(http.MethodDelete, "/media/"+hashOf(gone), f.token(memberPriv, nipB7.VerbDelete, nil, nil, soon), nil, nil), http.StatusForbidden)
}

func TestPreflight(t *testing.T) {
	f := newFixture(t, nil)
	resp := f.do(http.MethodOptions, "/upload", "", nil, nil)
	wantStatus(t, resp, http.StatusNoContent)
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "PUT") {
		t.Fatal("preflight does not allow PUT")
	}
}
