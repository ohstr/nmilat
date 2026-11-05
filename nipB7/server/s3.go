package server

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Options configure an S3Store: any S3-compatible object storage, such as
// MinIO.
type S3Options struct {
	// Endpoint is host[:port], without a scheme, e.g. "minio:9000".
	Endpoint string
	// Bucket holds the blobs; it must already exist.
	Bucket string
	// Region, when the storage needs one.
	Region string
	// Prefix is prepended to every object key, e.g. "blobs/".
	Prefix    string
	AccessKey string
	SecretKey string
	// UseSSL dials the endpoint over HTTPS.
	UseSSL bool
}

// S3Store keeps blobs as objects <prefix><sha> and their metadata as
// <prefix><sha>.json in one bucket. Blobs are always served through the
// Server, never by redirect, since clients sign for the server's host.
type S3Store struct {
	client *minio.Client
	bucket string
	prefix string
}

// NewS3Store connects to opt.Endpoint and checks that opt.Bucket exists.
func NewS3Store(ctx context.Context, opt S3Options) (*S3Store, error) {
	client, err := minio.New(opt.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(opt.AccessKey, opt.SecretKey, ""),
		Secure: opt.UseSSL,
		Region: opt.Region,
	})
	if err != nil {
		return nil, err
	}
	ok, err := client.BucketExists(ctx, opt.Bucket)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("blossom: bucket " + opt.Bucket + " does not exist")
	}
	return &S3Store{client: client, bucket: opt.Bucket, prefix: opt.Prefix}, nil
}

func notFound(err error) bool {
	code := minio.ToErrorResponse(err).Code
	return code == "NoSuchKey" || code == "NotFound"
}

func (s *S3Store) Put(ctx context.Context, sha string, r io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, s.prefix+sha, r, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (s *S3Store) Open(ctx context.Context, sha string) (io.ReadSeekCloser, int64, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.prefix+sha, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, err
	}
	info, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		if notFound(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	return obj, info.Size, nil
}

func (s *S3Store) Delete(ctx context.Context, sha string) error {
	for _, key := range []string{s.prefix + sha, s.prefix + sha + ".json"} {
		if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil && !notFound(err) {
			return err
		}
	}
	return nil
}

func (s *S3Store) PutMeta(ctx context.Context, sha string, meta []byte) error {
	_, err := s.client.PutObject(ctx, s.bucket, s.prefix+sha+".json", bytes.NewReader(meta), int64(len(meta)),
		minio.PutObjectOptions{ContentType: "application/json"})
	return err
}

func (s *S3Store) GetMeta(ctx context.Context, sha string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.prefix+sha+".json", minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = obj.Close() }()
	b, err := io.ReadAll(obj)
	if notFound(err) {
		return nil, ErrNotFound
	}
	return b, err
}
