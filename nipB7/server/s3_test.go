package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
)

// storeContract checks the behaviour the Server relies on from any Store.
func storeContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	blob := []byte("contract blob")
	sha := hashOf(blob)

	if _, _, err := s.Open(ctx, sha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open(missing) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetMeta(ctx, sha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMeta(missing) = %v, want ErrNotFound", err)
	}
	if err := s.Put(ctx, sha, bytes.NewReader(blob), int64(len(blob)), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMeta(ctx, sha, []byte(`{"size":13}`)); err != nil {
		t.Fatal(err)
	}
	r, size, err := s.Open(ctx, sha)
	if err != nil || size != int64(len(blob)) {
		t.Fatalf("Open = %d, %v", size, err)
	}
	if _, err := r.Seek(9, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "blob" {
		t.Fatalf("read after seek = %q", rest)
	}
	_ = r.Close()
	if m, err := s.GetMeta(ctx, sha); err != nil || string(m) != `{"size":13}` {
		t.Fatalf("GetMeta = %s, %v", m, err)
	}
	if err := s.Delete(ctx, sha); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(ctx, sha); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open(deleted) = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, sha); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil", err)
	}
}

func TestDirStoreContract(t *testing.T) {
	s, err := NewDirStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
}

// s3FromEnv connects to the S3-compatible storage NIPB7_S3_ENDPOINT names
// (with NIPB7_S3_BUCKET, NIPB7_S3_ACCESS_KEY, NIPB7_S3_SECRET_KEY), or skips.
func s3FromEnv(t *testing.T) *S3Store {
	t.Helper()
	endpoint := os.Getenv("NIPB7_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("NIPB7_S3_ENDPOINT not set")
	}
	s, err := NewS3Store(context.Background(), S3Options{
		Endpoint:  endpoint,
		Bucket:    os.Getenv("NIPB7_S3_BUCKET"),
		Prefix:    "test/" + t.Name() + "/",
		AccessKey: os.Getenv("NIPB7_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("NIPB7_S3_SECRET_KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestS3StoreContract(t *testing.T) {
	storeContract(t, s3FromEnv(t))
}

func TestServerOverS3(t *testing.T) {
	s3 := s3FromEnv(t)
	f := newFixture(t, func(o *Options) { o.Store = s3 })
	blob := []byte("served from object storage")
	wantStatus(t, f.upload(memberPriv, blob), http.StatusOK)

	part := f.do(http.MethodGet, "/media/"+hashOf(blob), "", nil, map[string]string{"Range": "bytes=12-17"})
	wantStatus(t, part, http.StatusPartialContent)
	if got, _ := io.ReadAll(part.Body); string(got) != "object" {
		t.Fatalf("range read %q", got)
	}
}
