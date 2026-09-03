package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"
const testHash = "acf592919bf86796c662468ff68c0fdf45780ca022b422157f5493bc6a51fb93"

func newAuth(t *testing.T, verb string) *nip01.Event {
	t.Helper()
	ev := nipB7.NewAuthorization(nipB7.AuthorizationParams{
		Verb:       verb,
		Content:    "test",
		Expiration: time.Now().Add(time.Hour),
	})
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func validDescriptorJSON(t *testing.T) []byte {
	t.Helper()
	d := nipB7.BlobDescriptor{
		URL:      "https://blossom.example/" + testHash,
		Sha256:   testHash,
		Size:     4,
		Type:     "text/plain",
		Uploaded: 1700000000,
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return b
}

// --- Get / GetFromServers / Head ---

func TestClientGetSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+testHash+".png" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("blobdata"))
	}))
	defer srv.Close()

	c := &Client{}
	resp, err := c.Get(context.Background(), srv.URL, testHash, GetOptions{Ext: "png"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "blobdata" {
		t.Errorf("body = %q, want blobdata", body)
	}
}

func TestClientGetSendsAuthHeader(t *testing.T) {
	auth := newAuth(t, nipB7.VerbGet)
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := &Client{}
	resp, err := c.Get(context.Background(), srv.URL, testHash, GetOptions{Auth: auth})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	_ = resp.Body.Close()

	decoded, err := nipB7.DecodeAuthHeader(gotHeader)
	if err != nil {
		t.Fatalf("DecodeAuthHeader() error = %v", err)
	}
	if decoded.ID != auth.ID {
		t.Errorf("decoded ID = %q, want %q", decoded.ID, auth.ID)
	}
}

func TestClientGetSetsRangeHeader(t *testing.T) {
	var gotRange string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		w.WriteHeader(http.StatusPartialContent)
	}))
	defer srv.Close()

	c := &Client{}
	resp, err := c.Get(context.Background(), srv.URL, testHash, GetOptions{Range: "bytes=0-99"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	_ = resp.Body.Close()
	if gotRange != "bytes=0-99" {
		t.Errorf("Range header = %q, want bytes=0-99", gotRange)
	}
}

func TestClientInvalidHashPropagatesBuildURLError(t *testing.T) {
	c := &Client{}
	ctx := context.Background()

	if _, err := c.Get(ctx, "https://blossom.example", "not-a-hash", GetOptions{}); !errors.Is(err, nipB7.ErrInvalidHash) {
		t.Errorf("Get: err = %v, want ErrInvalidHash", err)
	}
	if _, err := c.Head(ctx, "https://blossom.example", "not-a-hash", GetOptions{}); !errors.Is(err, nipB7.ErrInvalidHash) {
		t.Errorf("Head: err = %v, want ErrInvalidHash", err)
	}
	if err := c.Delete(ctx, "https://blossom.example", "not-a-hash", nil); !errors.Is(err, nipB7.ErrInvalidHash) {
		t.Errorf("Delete: err = %v, want ErrInvalidHash", err)
	}
}

func TestClientGetErrorWithReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nipB7.WriteError(w, http.StatusNotFound, "blob not found")
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Get(context.Background(), srv.URL, testHash, GetOptions{})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %v, want *HTTPError", err)
	}
	if httpErr.StatusCode != http.StatusNotFound || httpErr.Reason != "blob not found" {
		t.Errorf("httpErr = %+v", httpErr)
	}
}

func TestClientGetFromServersFallsBackOnFailure(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("found it"))
	}))
	defer good.Close()

	c := &Client{}
	resp, used, err := c.GetFromServers(context.Background(), []string{bad.URL, good.URL}, testHash, GetOptions{})
	if err != nil {
		t.Fatalf("GetFromServers() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if used != good.URL {
		t.Errorf("used = %q, want %q", used, good.URL)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "found it" {
		t.Errorf("body = %q", body)
	}
}

func TestClientGetFromServersAllFail(t *testing.T) {
	bad1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad1.Close()
	bad2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad2.Close()

	c := &Client{}
	_, _, err := c.GetFromServers(context.Background(), []string{bad1.URL, bad2.URL}, testHash, GetOptions{})
	if err == nil {
		t.Fatal("expected error when all servers fail")
	}
}

func TestClientGetFromServersEmptyList(t *testing.T) {
	c := &Client{}
	_, _, err := c.GetFromServers(context.Background(), nil, testHash, GetOptions{})
	if !errors.Is(err, ErrNoServers) {
		t.Errorf("err = %v, want ErrNoServers", err)
	}
}

func TestClientGetFromServersStopsOnContextCancel(t *testing.T) {
	var secondServerHit bool
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondServerHit = true
		_, _ = w.Write([]byte("ok"))
	}))
	defer second.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before the call

	c := &Client{}
	_, _, err := c.GetFromServers(ctx, []string{bad.URL, second.URL}, testHash, GetOptions{})
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if secondServerHit {
		t.Error("expected GetFromServers to stop after context cancellation, but it tried the second server")
	}
}

func TestClientHeadSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", "1234")
		w.Header().Set("Accept-Ranges", "bytes")
	}))
	defer srv.Close()

	c := &Client{}
	info, err := c.Head(context.Background(), srv.URL, testHash, GetOptions{})
	if err != nil {
		t.Fatalf("Head() error = %v", err)
	}
	if info.ContentType != "image/png" || info.ContentLength != 1234 || !info.AcceptRanges {
		t.Errorf("info = %+v", info)
	}
}

func TestClientHeadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Head(context.Background(), srv.URL, testHash, GetOptions{})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Errorf("err = %v", err)
	}
}

// --- Upload / HeadUpload / Media / HeadMedia ---

func TestClientUploadSuccess(t *testing.T) {
	auth := newAuth(t, nipB7.VerbUpload)
	var gotBody []byte
	var gotContentType string
	var gotAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/upload" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		gotBody, _ = io.ReadAll(r.Body)
		gotContentType = r.Header.Get("Content-Type")
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(validDescriptorJSON(t))
	}))
	defer srv.Close()

	c := &Client{}
	descriptor, err := c.Upload(context.Background(), srv.URL, UploadRequest{
		Body:        strings.NewReader("data"),
		Size:        4,
		ContentType: "text/plain",
		Auth:        auth,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	if descriptor.Sha256 != testHash {
		t.Errorf("descriptor.Sha256 = %q, want %q", descriptor.Sha256, testHash)
	}
	if string(gotBody) != "data" {
		t.Errorf("gotBody = %q, want data", gotBody)
	}
	if gotContentType != "text/plain" {
		t.Errorf("gotContentType = %q", gotContentType)
	}
	if gotAuthHeader == "" {
		t.Error("expected Authorization header to be set")
	}
}

func TestClientUploadServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nipB7.WriteError(w, http.StatusRequestEntityTooLarge, "blob too large")
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Upload(context.Background(), srv.URL, UploadRequest{Body: strings.NewReader("data")})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("err = %v", err)
	}
}

func TestClientUploadMalformedDescriptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Upload(context.Background(), srv.URL, UploadRequest{Body: strings.NewReader("data")})
	if err == nil {
		t.Fatal("expected error decoding malformed descriptor")
	}
}

func TestClientUploadInvalidDescriptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nipB7.BlobDescriptor{URL: "", Sha256: testHash, Size: 4, Uploaded: 1})
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Upload(context.Background(), srv.URL, UploadRequest{Body: strings.NewReader("data")})
	if err == nil {
		t.Fatal("expected error for descriptor missing url")
	}
}

func TestClientUploadEmptyServer(t *testing.T) {
	c := &Client{}
	if _, err := c.Upload(context.Background(), "", UploadRequest{Body: strings.NewReader("x")}); !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestClientHeadUploadSuccess(t *testing.T) {
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{}
	err := c.HeadUpload(context.Background(), srv.URL, nipB7.UploadRequirements{
		SHA256: testHash, ContentLength: 4, ContentType: "text/plain",
	}, nil)
	if err != nil {
		t.Fatalf("HeadUpload() error = %v", err)
	}
	if gotHeaders.Get(nipB7.HeaderSHA256) != testHash {
		t.Errorf("X-SHA-256 = %q", gotHeaders.Get(nipB7.HeaderSHA256))
	}
}

func TestClientHeadUploadPaymentRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(nipB7.HeaderLightning, "lnbc1...")
		w.Header().Set(nipB7.HeaderReason, "payment required")
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()

	c := &Client{}
	err := c.HeadUpload(context.Background(), srv.URL, nipB7.UploadRequirements{}, nil)

	var payErr *PaymentRequiredError
	if !errors.As(err, &payErr) {
		t.Fatalf("err = %v, want *PaymentRequiredError", err)
	}
	if payErr.Payment.Lightning != "lnbc1..." {
		t.Errorf("Payment.Lightning = %q", payErr.Payment.Lightning)
	}
	if payErr.StatusCode != http.StatusPaymentRequired {
		t.Errorf("StatusCode = %d", payErr.StatusCode)
	}
}

func TestClientHeadUploadEmptyServer(t *testing.T) {
	c := &Client{}
	err := c.HeadUpload(context.Background(), "", nipB7.UploadRequirements{}, nil)
	if !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestClientHeadMediaSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media" {
			t.Errorf("path = %q, want /media", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{}
	if err := c.HeadMedia(context.Background(), srv.URL, nipB7.UploadRequirements{}, nil); err != nil {
		t.Errorf("HeadMedia() error = %v", err)
	}
}

func TestClientMediaSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/media" {
			t.Errorf("path = %q, want /media", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(validDescriptorJSON(t))
	}))
	defer srv.Close()

	c := &Client{}
	descriptor, err := c.Media(context.Background(), srv.URL, UploadRequest{Body: strings.NewReader("data")})
	if err != nil {
		t.Fatalf("Media() error = %v", err)
	}
	if descriptor.Sha256 != testHash {
		t.Errorf("descriptor.Sha256 = %q", descriptor.Sha256)
	}
}

// --- Mirror ---

func TestClientMirrorSuccess(t *testing.T) {
	var gotBody mirrorRequestBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mirror" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(validDescriptorJSON(t))
	}))
	defer srv.Close()

	c := &Client{}
	descriptor, err := c.Mirror(context.Background(), srv.URL, "https://source.example/blob", nil)
	if err != nil {
		t.Fatalf("Mirror() error = %v", err)
	}
	if gotBody.URL != "https://source.example/blob" {
		t.Errorf("gotBody.URL = %q", gotBody.URL)
	}
	if descriptor.Sha256 != testHash {
		t.Errorf("descriptor.Sha256 = %q", descriptor.Sha256)
	}
}

func TestClientMirrorMalformedDescriptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := &Client{}
	if _, err := c.Mirror(context.Background(), srv.URL, "https://source.example/x", nil); err == nil {
		t.Fatal("expected error decoding malformed descriptor")
	}
}

func TestClientMirrorInvalidDescriptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(nipB7.BlobDescriptor{URL: "", Sha256: testHash, Size: 4, Uploaded: 1})
	}))
	defer srv.Close()

	c := &Client{}
	if _, err := c.Mirror(context.Background(), srv.URL, "https://source.example/x", nil); err == nil {
		t.Fatal("expected error for descriptor missing url")
	}
}

func TestClientMirrorEmptyServer(t *testing.T) {
	c := &Client{}
	if _, err := c.Mirror(context.Background(), "", "https://source.example/x", nil); !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestClientMirrorError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Mirror(context.Background(), srv.URL, "https://source.example/blob", nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusBadGateway {
		t.Errorf("err = %v", err)
	}
}

// --- List ---

func TestClientListSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/list/somepubkey" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "5" {
			t.Errorf("limit query = %q", r.URL.Query().Get("limit"))
		}
		_ = json.NewEncoder(w).Encode([]nipB7.BlobDescriptor{
			{URL: "https://blossom.example/" + testHash, Sha256: testHash, Size: 4, Uploaded: 1700000000},
		})
	}))
	defer srv.Close()

	c := &Client{}
	descriptors, err := c.List(context.Background(), srv.URL, "somepubkey", nipB7.ListQuery{Limit: 5}, nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(descriptors) != 1 || descriptors[0].Sha256 != testHash {
		t.Errorf("descriptors = %+v", descriptors)
	}
}

func TestClientListMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := &Client{}
	if _, err := c.List(context.Background(), srv.URL, "somepubkey", nipB7.ListQuery{}, nil); err == nil {
		t.Fatal("expected error decoding malformed list response")
	}
}

func TestClientListEmptyServer(t *testing.T) {
	c := &Client{}
	if _, err := c.List(context.Background(), "", "somepubkey", nipB7.ListQuery{}, nil); !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestClientListUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nipB7.WriteError(w, http.StatusUnauthorized, "missing authorization")
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.List(context.Background(), srv.URL, "somepubkey", nipB7.ListQuery{}, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("err = %v", err)
	}
}

// --- Delete ---

func TestClientDeleteSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &Client{}
	if err := c.Delete(context.Background(), srv.URL, testHash, newAuth(t, nipB7.VerbDelete)); err != nil {
		t.Errorf("Delete() error = %v", err)
	}
}

func TestClientDeleteUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{}
	err := c.Delete(context.Background(), srv.URL, testHash, nil)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("err = %v", err)
	}
}

// --- Report ---

func TestClientReportSuccess(t *testing.T) {
	ev, err := nipB7.NewReport("", []nipB7.ReportedBlob{{Hash: testHash, Type: "malware"}}, "contains malware")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	var gotEvent nip01.Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/report" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotEvent)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &Client{}
	if err := c.Report(context.Background(), srv.URL, ev); err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if gotEvent.ID != ev.ID {
		t.Errorf("gotEvent.ID = %q, want %q", gotEvent.ID, ev.ID)
	}
}

func TestClientReportEmptyServer(t *testing.T) {
	ev, _ := nipB7.NewReport("", []nipB7.ReportedBlob{{Hash: testHash}}, "reason")
	c := &Client{}
	if err := c.Report(context.Background(), "", ev); !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestClientReportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nipB7.WriteError(w, http.StatusBadRequest, "malformed report")
	}))
	defer srv.Close()

	ev, _ := nipB7.NewReport("", []nipB7.ReportedBlob{{Hash: testHash}}, "reason")
	c := &Client{}
	err := c.Report(context.Background(), srv.URL, ev)
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Reason != "malformed report" {
		t.Errorf("err = %v", err)
	}
}

// --- shared plumbing ---

func TestClientUsesConfiguredHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var used bool
	c := &Client{HTTPClient: &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			used = true
			return http.DefaultTransport.RoundTrip(req)
		}),
	}}
	resp, err := c.Get(context.Background(), srv.URL, testHash, GetOptions{})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	_ = resp.Body.Close()
	if !used {
		t.Error("expected configured HTTPClient's transport to be used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestJoinPathEmptyServer(t *testing.T) {
	if _, err := joinPath("", "/upload"); !errors.Is(err, ErrEmptyServer) {
		t.Errorf("err = %v, want ErrEmptyServer", err)
	}
}

func TestHTTPErrorMessage(t *testing.T) {
	e := &HTTPError{Server: "https://x.example", StatusCode: http.StatusNotFound, Reason: "gone"}
	if !strings.Contains(e.Error(), "gone") {
		t.Errorf("Error() = %q, want it to contain reason", e.Error())
	}
	e2 := &HTTPError{Server: "https://x.example", StatusCode: http.StatusNotFound}
	if strings.Contains(e2.Error(), ": : ") {
		t.Errorf("Error() = %q, malformed with empty reason", e2.Error())
	}
}

// closedServerURL returns a URL that is guaranteed to refuse connections:
// a real httptest.Server address whose listener has already been closed.
func closedServerURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}

func TestClientTransportErrors(t *testing.T) {
	ctx := context.Background()
	server := closedServerURL(t)
	c := &Client{}
	ev, err := nipB7.NewReport("", []nipB7.ReportedBlob{{Hash: testHash}}, "r")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}

	if _, err := c.Get(ctx, server, testHash, GetOptions{}); err == nil {
		t.Error("Get: expected a transport error against a closed server")
	}
	if _, err := c.Head(ctx, server, testHash, GetOptions{}); err == nil {
		t.Error("Head: expected a transport error against a closed server")
	}
	if err := c.Delete(ctx, server, testHash, nil); err == nil {
		t.Error("Delete: expected a transport error against a closed server")
	}
	if _, err := c.List(ctx, server, "pub", nipB7.ListQuery{}, nil); err == nil {
		t.Error("List: expected a transport error against a closed server")
	}
	if _, err := c.Mirror(ctx, server, "https://source.example/x", nil); err == nil {
		t.Error("Mirror: expected a transport error against a closed server")
	}
	if err := c.Report(ctx, server, ev); err == nil {
		t.Error("Report: expected a transport error against a closed server")
	}
	if _, err := c.Upload(ctx, server, UploadRequest{Body: strings.NewReader("x")}); err == nil {
		t.Error("Upload: expected a transport error against a closed server")
	}
	if err := c.HeadUpload(ctx, server, nipB7.UploadRequirements{}, nil); err == nil {
		t.Error("HeadUpload: expected a transport error against a closed server")
	}
}

func TestClientMalformedServerURL(t *testing.T) {
	ctx := context.Background()
	const bad = "://bad"
	c := &Client{}
	ev, err := nipB7.NewReport("", []nipB7.ReportedBlob{{Hash: testHash}}, "r")
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}

	if _, err := c.Get(ctx, bad, testHash, GetOptions{}); err == nil {
		t.Error("Get: expected error for malformed server url")
	}
	if _, err := c.Head(ctx, bad, testHash, GetOptions{}); err == nil {
		t.Error("Head: expected error for malformed server url")
	}
	if err := c.Delete(ctx, bad, testHash, nil); err == nil {
		t.Error("Delete: expected error for malformed server url")
	}
	if _, err := c.List(ctx, bad, "pub", nipB7.ListQuery{}, nil); err == nil {
		t.Error("List: expected error for malformed server url")
	}
	if _, err := c.Mirror(ctx, bad, "https://source.example/x", nil); err == nil {
		t.Error("Mirror: expected error for malformed server url")
	}
	if err := c.Report(ctx, bad, ev); err == nil {
		t.Error("Report: expected error for malformed server url")
	}
	if _, err := c.Upload(ctx, bad, UploadRequest{Body: strings.NewReader("x")}); err == nil {
		t.Error("Upload: expected error for malformed server url")
	}
	if err := c.HeadUpload(ctx, bad, nipB7.UploadRequirements{}, nil); err == nil {
		t.Error("HeadUpload: expected error for malformed server url")
	}
}

func TestSetAuthHeaderNil(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://x.example", nil)
	if err := setAuthHeader(req, nil); err != nil {
		t.Errorf("setAuthHeader(nil) error = %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("expected no Authorization header when auth is nil")
	}
}
