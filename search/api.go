// Package search maps profiles (kind 0) to search documents and defines
// the search engine a relay queries for NIP-50 and keeps in sync
// (relay.SearchIndexer).
package search

import "context"

// Searcher answers profile queries.
type Searcher interface {
	FindProfiles(ctx context.Context, query string, limit int) ([]string, error)
}

// Writer changes the search engine's documents. Each call returns once the
// engine applied the change, so a caller that acknowledges after it never
// loses one.
type Writer interface {
	Upsert(ctx context.Context, docs []*ProfileDocument) error
	Delete(ctx context.Context, pubkeys []string) error
}
