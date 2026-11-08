package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if d.URL != f.ts.URL+"/media/"+d.Sha256+".txt" {
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

// TestDescriptorURLExtension checks BUD-02's file extension on a
// descriptor's url, and that the url serves the blob.
func TestDescriptorURLExtension(t *testing.T) {
	f := newFixture(t, nil)
	for _, c := range []struct {
		ctype, ext string
	}{
		{"image/png", ".png"},
		{"image/jpeg", ".jpg"},
		{"text/plain; charset=utf-8", ".txt"},
		{"application/octet-stream", ".bin"},
		{"application/x-nmilat-unknown", ".bin"},
		{"", ".bin"},
	} {
		blob := []byte("blob of type " + c.ctype)
		auth := f.token(memberPriv, nipB7.VerbUpload, []string{hashOf(blob)}, nil, time.Now().Add(time.Minute))
		header := map[string]string{}
		if c.ctype != "" {
			header["Content-Type"] = c.ctype
		}
		resp := f.do(http.MethodPut, "/upload", auth, bytes.NewReader(blob), header)
		wantStatus(t, resp, http.StatusOK)
		var d nipB7.BlobDescriptor
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatal(err)
		}
		if want := f.ts.URL + "/media/" + hashOf(blob) + c.ext; d.URL != want {
			t.Fatalf("type %q: url %s, want %s", c.ctype, d.URL, want)
		}

		get, err := http.Get(d.URL)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, get, http.StatusOK)
		got, _ := io.ReadAll(get.Body)
		_ = get.Body.Close()
		if !bytes.Equal(got, blob) {
			t.Fatalf("type %q: downloaded %q", c.ctype, got)
		}
		if c.ctype != "" && get.Header.Get("Content-Type") != c.ctype {
			t.Fatalf("type %q: served as %q", c.ctype, get.Header.Get("Content-Type"))
		}
	}
}

func TestExtension(t *testing.T) {
	for ctype, want := range map[string]string{
		"image/gif":        ".gif",
		"image/webp":       ".webp",
		"video/mp4":        ".mp4",
		"audio/mpeg":       ".mp3",
		"application/pdf":  ".pdf",
		"application/json": ".json",
		"IMAGE/PNG":        ".png",
		"not a type":       ".bin",
	} {
		if got := extension(ctype); got != want {
			t.Errorf("extension(%q) = %q, want %q", ctype, got, want)
		}
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

func TestUploadsInFlightPerSigner(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxUploadsPerSigner = 1 })
	blob := []byte("slow upload")
	auth := f.token(memberPriv, nipB7.VerbUpload, []string{hashOf(blob)}, nil, time.Now().Add(time.Minute))

	pr, pw := io.Pipe()
	done := make(chan *http.Response)
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
	_, _ = pw.Write(blob[:4])
	member := pub(t, memberPriv)
	for deadline := time.Now().Add(5 * time.Second); ; {
		f.srv.mu.Lock()
		n := f.srv.inFlight[member]
		f.srv.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first upload never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	wantStatus(t, f.upload(memberPriv, []byte("second")), http.StatusTooManyRequests)

	_, _ = pw.Write(blob[4:])
	_ = pw.Close()
	first := <-done
	if first == nil {
		t.Fatal("first upload failed")
	}
	defer func() { _ = first.Body.Close() }()
	wantStatus(t, first, http.StatusOK)
	wantStatus(t, f.upload(memberPriv, []byte("third")), http.StatusOK)
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
