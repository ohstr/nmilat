package search

import "context"

// Indexer defines how we send data to the search engine.
// R1 Implementation: Direct HTTP calls to the search backend via a Go Channel buffer.
type Indexer interface {
	IndexProfile(ctx context.Context, profile *ProfileDocument) error
	UpdateScore(ctx context.Context, pubkey string, score int64) error
	// IndexProfileWithMetrics calculates total score using existing BoltDB metrics.
	IndexProfileWithMetrics(ctx context.Context, profile *ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error
	// DeleteProfile removes a single profile's document from the index.
	DeleteProfile(ctx context.Context, pubkey string) error
}

// Searcher defines how we query data.
// R1 Implementation: HTTP GET to the search backend.
type Searcher interface {
	FindProfiles(ctx context.Context, query string, limit int) ([]string, error)
}

// Service combines both for the Relay to use.
type Service interface {
	Indexer
	Searcher
	// Initialize ensures the index exists with correct settings
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	DeleteIndex(ctx context.Context) error
}
