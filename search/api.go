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

// Pending is a change the engine accepted but may not have applied yet.
type Pending interface {
	// Wait returns once the engine applied the change, or why it didn't.
	Wait(ctx context.Context) error
}

// Enqueuer is a Writer that also takes changes without waiting for them,
// so a caller can keep several in flight while the engine merges them. The
// engine applies enqueued changes in the order they were enqueued.
type Enqueuer interface {
	Writer
	EnqueueUpsert(ctx context.Context, docs []*ProfileDocument) (Pending, error)
	EnqueueDelete(ctx context.Context, pubkeys []string) (Pending, error)
}

// Applied is a Pending the engine already applied.
type Applied struct{}

func (Applied) Wait(context.Context) error { return nil }

// Async returns w as an Enqueuer: w itself when it is one, else one whose
// enqueue applies the change before it returns.
func Async(w Writer) Enqueuer {
	if e, ok := w.(Enqueuer); ok {
		return e
	}
	return syncEnqueuer{w}
}

type syncEnqueuer struct{ Writer }

func (s syncEnqueuer) EnqueueUpsert(ctx context.Context, docs []*ProfileDocument) (Pending, error) {
	return Applied{}, s.Upsert(ctx, docs)
}

func (s syncEnqueuer) EnqueueDelete(ctx context.Context, pubkeys []string) (Pending, error) {
	return Applied{}, s.Delete(ctx, pubkeys)
}
