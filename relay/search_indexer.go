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

// Defaults for WithSearchBatch and WithSearchInFlight.
const (
	DefaultSearchBatch    = 10_000
	DefaultSearchInFlight = 4
)

// SearchIndexer keeps a search engine in step with the store's profiles by
// following SearchFeed: it upserts each stored kind 0, re-reads each
// queued profile (deleted, or rescored) and upserts or deletes it, and
// acknowledges only what the engine applied. While the engine is down it
// retries with backoff and loses nothing.
//
// It keeps up to its in-flight limit of batches enqueued, so an engine that
// merges queued changes (search.Enqueuer) pays its per-write cost once for
// several of them, and acknowledges them strictly in the order sent. A
// failure drops what is still in flight and reads again from the last
// acknowledged batch, so the last change sent for a profile is always its
// current state.
type SearchIndexer struct {
	store    *EventStore
	writer   search.Enqueuer
	batch    int
	inFlight int
	// mu is held while a step runs; Exclusive takes it to pause indexing.
	mu sync.Mutex
	// queue is the batches sent and not yet acknowledged, oldest first, and
	// cursor where the next read starts; both guarded by mu.
	queue  []sentBatch
	cursor FeedCursor

	upserted atomic.Int64
	deleted  atomic.Int64
	lastErr  atomic.Pointer[searchError]
}

// sentBatch is a feed batch the engine accepted.
type sentBatch struct {
	batch FeedBatch
	tasks []search.Pending
	docs  int
	gone  int
}

type searchError struct {
	err string
	at  time.Time
}

// SearchIndexerOption configures a SearchIndexer.
type SearchIndexerOption func(*SearchIndexer)

// WithSearchBatch bounds the stored profiles, and separately the queued
// ones, one batch sends (default DefaultSearchBatch).
func WithSearchBatch(n int) SearchIndexerOption {
	return func(x *SearchIndexer) {
		if n > 0 {
			x.batch = n
		}
	}
}

// WithSearchInFlight is how many batches may be sent before the indexer
// waits for the oldest (default DefaultSearchInFlight). It has effect only
// with a writer that is a search.Enqueuer.
func WithSearchInFlight(n int) SearchIndexerOption {
	return func(x *SearchIndexer) {
		if n > 0 {
			x.inFlight = n
		}
	}
}

// NewSearchIndexer registers SearchFeed on store and returns an indexer
// writing to w; Run starts it.
func NewSearchIndexer(store *EventStore, w search.Writer, opts ...SearchIndexerOption) (*SearchIndexer, error) {
	if err := store.EnsureFeed(SearchFeed); err != nil {
		return nil, err
	}
	x := &SearchIndexer{store: store, writer: search.Async(w), batch: DefaultSearchBatch, inFlight: DefaultSearchInFlight}
	for _, o := range opts {
		o(x)
	}
	return x, nil
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

// Step does one unit of indexing: it sends the next batch while fewer than
// the in-flight limit are unacknowledged, else (or when nothing new is
// stored) waits for the oldest and acknowledges it. more is true when the
// feed may hold more or batches are still in flight.
func (x *SearchIndexer) Step(ctx context.Context) (more bool, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.queue) >= x.inFlight {
		return true, x.settle(ctx)
	}
	batch, next, err := x.store.FeedChangesFrom(SearchFeed.Name, x.cursor, x.batch, x.batch)
	if err != nil {
		return false, x.fail(err)
	}
	if batch.Through == 0 && len(batch.Dirty) == 0 {
		if len(x.queue) == 0 {
			// All acknowledged: queued authors are read from the start again.
			x.cursor = FeedCursor{}
			return false, nil
		}
		return true, x.settle(ctx)
	}
	sent, err := x.send(ctx, batch)
	if err != nil {
		x.reset()
		return false, x.fail(err)
	}
	x.queue = append(x.queue, sent)
	x.cursor = next
	return true, nil
}

// send builds a batch's documents and enqueues its upserts, then its
// deletes.
func (x *SearchIndexer) send(ctx context.Context, batch FeedBatch) (sentBatch, error) {
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
			return sentBatch{}, err
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
	out := sentBatch{batch: batch}
	if len(docs) > 0 {
		docs = dedupeDocs(docs)
		p, err := x.writer.EnqueueUpsert(ctx, docs)
		if err != nil {
			return sentBatch{}, err
		}
		out.tasks, out.docs = append(out.tasks, p), len(docs)
	}
	if len(gone) > 0 {
		p, err := x.writer.EnqueueDelete(ctx, gone)
		if err != nil {
			return sentBatch{}, err
		}
		out.tasks, out.gone = append(out.tasks, p), len(gone)
	}
	return out, nil
}

// settle waits for the oldest batch in flight and acknowledges it. When
// the engine didn't apply it, nothing from it on is acknowledged: the
// batches still in flight are dropped and read again from the watermark.
func (x *SearchIndexer) settle(ctx context.Context) error {
	oldest := x.queue[0]
	for _, p := range oldest.tasks {
		if err := p.Wait(ctx); err != nil {
			x.reset()
			return x.fail(err)
		}
	}
	if err := x.store.AckFeed(SearchFeed.Name, oldest.batch); err != nil {
		x.reset()
		return x.fail(err)
	}
	x.queue = x.queue[1:]
	x.upserted.Add(int64(oldest.docs))
	x.deleted.Add(int64(oldest.gone))
	x.lastErr.Store(nil)
	return nil
}

// reset forgets the batches in flight; the next step reads from the
// watermark. Changes still queued in the engine apply before anything sent
// later, so what is read again ends up applied last.
func (x *SearchIndexer) reset() {
	x.queue = nil
	x.cursor = FeedCursor{}
}

func (x *SearchIndexer) fail(err error) error {
	x.lastErr.Store(&searchError{err: err.Error(), at: time.Now()})
	return err
}

func (x *SearchIndexer) document(ev *nip01.Event) *search.ProfileDocument {
	return SearchDocument(x.store, ev)
}

// SearchDocument builds a profile's search document, scored with what the
// store knows of it (check results and social score); nil for an event
// that isn't a profile.
func SearchDocument(store *EventStore, ev *nip01.Event) *search.ProfileDocument {
	doc := search.FromEvent(ev)
	if doc == nil {
		return nil
	}
	if m, err := store.GetProfileMetrics(ev.PubKey); err == nil && m != nil {
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
	// What's in flight isn't acknowledged, so it is read again afterwards.
	x.reset()
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
