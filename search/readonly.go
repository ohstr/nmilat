package search

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ReadOnlyService wraps a Service and silently drops all write operations.
// Read operations (FindProfiles) are delegated to the inner service.
// Use this for relay instances that should query the search backend but never index.
type ReadOnlyService struct {
	inner Service
}

// NewReadOnlyService returns a Service that no-ops all writes, logging
// through the process-global logger.
func NewReadOnlyService(inner Service) *ReadOnlyService {
	return NewReadOnlyServiceWithLogger(inner, log.Logger)
}

// NewReadOnlyServiceWithLogger is like NewReadOnlyService but logs through
// the given logger instead of the process-global one, so callers (tests in
// particular) can route this message through their own logger rather than
// having it dumped as raw JSON to stdout/stderr.
func NewReadOnlyServiceWithLogger(inner Service, logger zerolog.Logger) *ReadOnlyService {
	logger.Info().Msg("search service running in READ-ONLY mode (writes disabled)")
	return &ReadOnlyService{inner: inner}
}

func (r *ReadOnlyService) Initialize(ctx context.Context) error {
	return r.inner.Initialize(ctx)
}

func (r *ReadOnlyService) Shutdown(ctx context.Context) error {
	return r.inner.Shutdown(ctx)
}

func (r *ReadOnlyService) FindProfiles(ctx context.Context, query string, limit int) ([]string, error) {
	return r.inner.FindProfiles(ctx, query, limit)
}

// Write operations — all no-ops in readonly mode.

func (r *ReadOnlyService) IndexProfile(ctx context.Context, doc *ProfileDocument) error {
	return nil
}

func (r *ReadOnlyService) IndexProfileWithMetrics(ctx context.Context, doc *ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error {
	return nil
}

func (r *ReadOnlyService) UpdateScore(ctx context.Context, pubkey string, score int64) error {
	return nil
}

func (r *ReadOnlyService) DeleteIndex(ctx context.Context) error {
	return nil
}

func (r *ReadOnlyService) DeleteProfile(ctx context.Context, pubkey string) error {
	return nil
}
