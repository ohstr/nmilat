package relay

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search"
)

// SearchFeed is the feed a SearchIndexer follows: every stored profile,
// its deletions, and changes to its score.
var SearchFeed = Feed{Name: "search", Kinds: []int{0}, Deletes: true, Scores: true}

// searchBatch bounds the profiles one indexing step sends.
var searchBatch = 500

// SearchIndexer keeps a search engine in step with the store's profiles by
// following SearchFeed: it upserts each stored kind 0, re-reads each
// queued profile (deleted, or rescored) and upserts or deletes it, and
// acknowledges only what the engine applied. While the engine is down it
// retries with backoff and loses nothing.
type SearchIndexer struct {
	store  *EventStore
	writer search.Writer
	// mu is held while a step runs; Exclusive takes it to pause indexing.
	mu sync.Mutex

	upserted atomic.Int64
	deleted  atomic.Int64
	lastErr  atomic.Pointer[searchError]
}

type searchError struct {
	err string
	at  time.Time
}

// NewSearchIndexer registers SearchFeed on store and returns an indexer
// writing to w; Run starts it.
func NewSearchIndexer(store *EventStore, w search.Writer) (*SearchIndexer, error) {
	if err := store.EnsureFeed(SearchFeed); err != nil {
		return nil, err
	}
	return &SearchIndexer{store: store, writer: w}, nil
}

// Run indexes until ctx ends: at once, then whenever events are stored, and
// every second for queued profiles.
func (x *SearchIndexer) Run(ctx context.Context) {
	backoff := time.Second
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		wake := x.store.CommitSignal()
		var err error
		for {
			var more bool
			more, err = x.Step(ctx)
			if err != nil || !more || ctx.Err() != nil {
				break
			}
		}
		delay := time.Duration(0)
		if err != nil && ctx.Err() == nil {
			delay, backoff = backoff, min(backoff*2, 30*time.Second)
		} else {
			backoff = time.Second
		}
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-tick.C:
		}
	}
}

// Step sends one batch to the engine and acknowledges it; more is true when
// the feed may hold more.
func (x *SearchIndexer) Step(ctx context.Context) (more bool, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	batch, err := x.store.FeedChanges(SearchFeed.Name, searchBatch, searchBatch)
	if err != nil {
		return false, x.fail(err)
	}
	if batch.Through == 0 && len(batch.Dirty) == 0 {
		return false, nil
	}
	docs := make([]*search.ProfileDocument, 0, len(batch.Events)+len(batch.Dirty))
	for _, ev := range batch.Events {
		if doc := x.document(ev); doc != nil {
			docs = append(docs, doc)
		}
	}
	var gone []string
	if len(batch.Dirty) > 0 {
		events, err := x.store.FetchProfileEvents(ctx, batch.Dirty)
		if err != nil {
			return false, x.fail(err)
		}
		found := map[string]bool{}
		for _, ev := range events {
			found[ev.PubKey] = true
			if doc := x.document(ev); doc != nil {
				docs = append(docs, doc)
			}
		}
		for _, pk := range batch.Dirty {
			if !found[pk] {
				gone = append(gone, pk)
			}
		}
	}
	if len(docs) > 0 {
		if err := x.writer.Upsert(ctx, dedupeDocs(docs)); err != nil {
			return false, x.fail(err)
		}
	}
	if len(gone) > 0 {
		if err := x.writer.Delete(ctx, gone); err != nil {
			return false, x.fail(err)
		}
	}
	if err := x.store.AckFeed(SearchFeed.Name, batch); err != nil {
		return false, x.fail(err)
	}
	x.upserted.Add(int64(len(docs)))
	x.deleted.Add(int64(len(gone)))
	x.lastErr.Store(nil)
	return true, nil
}

func (x *SearchIndexer) fail(err error) error {
	x.lastErr.Store(&searchError{err: err.Error(), at: time.Now()})
	return err
}

// document builds a profile's search document with its stored score.
func (x *SearchIndexer) document(ev *nip01.Event) *search.ProfileDocument {
	doc := search.FromEvent(ev)
	if doc == nil {
		return nil
	}
	if m, err := x.store.GetProfileMetrics(ev.PubKey); err == nil && m != nil {
		doc.Score += m.CheckScore() + m.SocialScore
	}
	return doc
}

// dedupeDocs keeps one document per profile, the last one.
func dedupeDocs(docs []*search.ProfileDocument) []*search.ProfileDocument {
	at := make(map[string]int, len(docs))
	out := docs[:0]
	for _, d := range docs {
		if i, ok := at[d.ID]; ok {
			out[i] = d
			continue
		}
		at[d.ID] = len(out)
		out = append(out, d)
	}
	return out
}

// Exclusive runs fn with indexing paused, for an operation that replaces
// the engine's index (a fresh rebuild).
func (x *SearchIndexer) Exclusive(fn func() error) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return fn()
}

// SearchIndexerStatus is how far the engine is behind the store.
type SearchIndexerStatus struct {
	FeedStatus
	Upserted  int64     `json:"upserted"`
	Deleted   int64     `json:"deleted"`
	LastError string    `json:"last_error,omitempty"`
	ErrorAt   time.Time `json:"error_at,omitempty"`
}

// Status reports the indexer's progress.
func (x *SearchIndexer) Status() SearchIndexerStatus {
	st := SearchIndexerStatus{Upserted: x.upserted.Load(), Deleted: x.deleted.Load()}
	st.FeedStatus, _ = x.store.FeedStatus(SearchFeed.Name)
	if e := x.lastErr.Load(); e != nil {
		st.LastError, st.ErrorAt = e.err, e.at
	}
	return st
}
