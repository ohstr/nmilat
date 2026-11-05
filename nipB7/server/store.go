// Package server is a Blossom (BUD-01, BUD-02) blob server: PUT uploads
// authorized by a kind 24242 token, GET/HEAD by sha256 with Range, and
// DELETE by an uploader or an admin, over a pluggable Store (a directory or
// S3-compatible object storage).
package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ErrNotFound is returned by a Store for a blob or metadata it doesn't hold.
var ErrNotFound = errors.New("blossom: not found")

// Store keeps blobs and a small JSON metadata document per blob, both keyed
// by the blob's sha256. The server verifies a blob's hash before Put, so a
// Store never sees bytes that don't match their key.
type Store interface {
	// Put stores size bytes from r as blob sha.
	Put(ctx context.Context, sha string, r io.Reader, size int64, contentType string) error
	// Open returns blob sha for reading and seeking, and its size.
	Open(ctx context.Context, sha string) (io.ReadSeekCloser, int64, error)
	// Delete removes blob sha and its metadata. Deleting a missing blob is
	// not an error.
	Delete(ctx context.Context, sha string) error
	// PutMeta replaces blob sha's metadata document.
	PutMeta(ctx context.Context, sha string, meta []byte) error
	// GetMeta returns blob sha's metadata document, or ErrNotFound.
	GetMeta(ctx context.Context, sha string) ([]byte, error)
}

// DirStore keeps blobs as files under a directory, sharded by the hash's
// first two characters: <dir>/<ab>/<sha> and <dir>/<ab>/<sha>.json.
type DirStore struct {
	dir string
}

// NewDirStore returns a DirStore rooted at dir, creating it if needed.
func NewDirStore(dir string) (*DirStore, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &DirStore{dir: dir}, nil
}

func (d *DirStore) path(sha string) string {
	return filepath.Join(d.dir, sha[:2], sha)
}

// writeAtomic writes r to path through a temporary file in the same
// directory, so a reader never sees a partial file.
func writeAtomic(path string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (d *DirStore) Put(_ context.Context, sha string, r io.Reader, _ int64, _ string) error {
	return writeAtomic(d.path(sha), r)
}

func (d *DirStore) Open(_ context.Context, sha string) (io.ReadSeekCloser, int64, error) {
	f, err := os.Open(d.path(sha))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

func (d *DirStore) Delete(_ context.Context, sha string) error {
	for _, p := range []string{d.path(sha), d.path(sha) + ".json"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (d *DirStore) PutMeta(_ context.Context, sha string, meta []byte) error {
	return writeAtomic(d.path(sha)+".json", bytes.NewReader(meta))
}

func (d *DirStore) GetMeta(_ context.Context, sha string) ([]byte, error) {
	b, err := os.ReadFile(d.path(sha) + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}
