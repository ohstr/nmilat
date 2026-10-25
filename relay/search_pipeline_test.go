package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queuedSearchWriter is an engine that, like Meilisearch, queues each
// change as a task and applies tasks in enqueue order when one is waited
// for. failTask makes the task with that sequence number (1-based) fail.
type queuedSearchWriter struct {
	fakeSearchWriter
	qmu      sync.Mutex
	tasks    []*queuedTask
	seq      int
	maxOpen  int
	failTask map[int]bool
}

type queuedTask struct {
	w     *queuedSearchWriter
	n     int
	apply func() error
	done  bool
	err   error
}

func (w *queuedSearchWriter) enqueue(apply func() error) *queuedTask {
	w.qmu.Lock()
	defer w.qmu.Unlock()
	w.seq++
	t := &queuedTask{w: w, n: w.seq, apply: apply}
	w.tasks = append(w.tasks, t)
	open := 0
	for _, t := range w.tasks {
		if !t.done {
			open++
		}
	}
	w.maxOpen = max(w.maxOpen, open)
	return t
}

func (w *queuedSearchWriter) EnqueueUpsert(_ context.Context, docs []*search.ProfileDocument) (search.Pending, error) {
	docs = append([]*search.ProfileDocument(nil), docs...)
	return w.enqueue(func() error { return w.Upsert(context.Background(), docs) }), nil
}

func (w *queuedSearchWriter) EnqueueDelete(_ context.Context, pubkeys []string) (search.Pending, error) {
	pubkeys = append([]string(nil), pubkeys...)
	return w.enqueue(func() error { return w.Delete(context.Background(), pubkeys) }), nil
}

// Wait applies every task up to this one, in order, and returns this one's
// result.
func (t *queuedTask) Wait(context.Context) error {
	w := t.w
	w.qmu.Lock()
	defer w.qmu.Unlock()
	for _, q := range w.tasks {
		if !q.done {
			q.done = true
			if w.failTask[q.n] {
				q.err = fmt.Errorf("task %d failed", q.n)
			} else {
				q.err = q.apply()
			}
		}
		if q == t {
			break
		}
	}
	return t.err
}

// runAll applies every queued task, as the engine does on its own.
func (w *queuedSearchWriter) runAll() {
	w.qmu.Lock()
	last := len(w.tasks) - 1
	w.qmu.Unlock()
	if last >= 0 {
		_ = w.tasks[last].Wait(context.Background())
	}
}

func (w *queuedSearchWriter) open() int {
	w.qmu.Lock()
	defer w.qmu.Unlock()
	n := 0
	for _, t := range w.tasks {
		if !t.done {
			n++
		}
	}
	return n
}

func queuedFixture(t *testing.T, opts ...SearchIndexerOption) (*indexFixture, *SearchIndexer, *queuedSearchWriter) {
	f := newManualIndexFixture(t, noIndexes)
	w := &queuedSearchWriter{failTask: map[int]bool{}}
	x, err := NewSearchIndexer(f.store, w, opts...)
	require.NoError(t, err)
	return f, x, w
}

func TestSearchPipeline_NeverMoreThanInFlight(t *testing.T) {
	f, x, w := queuedFixture(t, WithSearchBatch(1), WithSearchInFlight(3))
	for i := range 20 {
		k := newTestKey(t, 100+i)
		f.insert(f.profile(k, fmt.Sprintf(`{"name":"p%d"}`, i)))
	}
	for range 200 {
		more, err := x.Step(context.Background())
		require.NoError(t, err)
		assert.LessOrEqual(t, w.open(), 3)
		if !more {
			break
		}
	}
	assert.Equal(t, 3, w.maxOpen, "the pipeline fills up to its limit")
	assert.Equal(t, 20, w.count())
	st := x.Status()
	assert.Zero(t, st.Behind)
	assert.Equal(t, int64(20), st.Upserted)
}

func TestSearchPipeline_FailedTaskHoldsTheWatermark(t *testing.T) {
	f, x, w := queuedFixture(t, WithSearchBatch(1), WithSearchInFlight(4))
	carol := newTestKey(t, 13)
	f.insert(f.profile(f.alice, `{"name":"alice"}`))
	f.insert(f.profile(f.bob, `{"name":"bob"}`))
	f.insert(f.profile(carol, `{"name":"carol"}`))
	w.failTask[2] = true // bob's; alice's before it and carol's after it succeed

	for range 3 { // send all three
		more, err := x.Step(context.Background())
		require.NoError(t, err)
		require.True(t, more)
	}
	_, err := x.Step(context.Background()) // settles alice
	require.NoError(t, err)
	w.runAll()
	_, err = x.Step(context.Background()) // bob's task failed
	require.ErrorContains(t, err, "task 2 failed")
	assert.NotNil(t, w.doc(carol.pub), "the engine applied the task after the failed one")

	st, err := f.store.FeedStatus(SearchFeed.Name)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), st.Behind, "the watermark stays before bob's profile")

	drain(t, x)
	assert.Equal(t, "bob", w.doc(f.bob.pub).Name, "bob's profile is sent again")
	assert.Equal(t, 3, w.count())
	st, err = f.store.FeedStatus(SearchFeed.Name)
	require.NoError(t, err)
	assert.Zero(t, st.Behind)
}

func TestSearchPipeline_LastUpdateWinsAcrossTasks(t *testing.T) {
	f, x, w := queuedFixture(t, WithSearchBatch(1), WithSearchInFlight(4))
	for i := range 5 {
		f.insert(f.profile(f.alice, fmt.Sprintf(`{"name":"v%d"}`, i)))
		more, err := x.Step(context.Background())
		require.NoError(t, err)
		require.True(t, more)
	}
	drain(t, x)
	assert.Equal(t, "v4", w.doc(f.alice.pub).Name)

	// The same with a failure in the middle of the updates.
	w.failTask[w.seq+2] = true
	for i := 5; i < 10; i++ {
		f.insert(f.profile(f.alice, fmt.Sprintf(`{"name":"v%d"}`, i)))
		if _, err := x.Step(context.Background()); err != nil {
			continue
		}
	}
	for range 100 {
		more, err := x.Step(context.Background())
		if err == nil && !more {
			break
		}
	}
	assert.Equal(t, "v9", w.doc(f.alice.pub).Name)
}

func TestSearchPipeline_DeleteAfterUpsertInFlight(t *testing.T) {
	f, x, w := queuedFixture(t, WithSearchBatch(1), WithSearchInFlight(4))
	p := f.profile(f.alice, `{"name":"alice"}`)
	f.insert(p)
	_, err := x.Step(context.Background())
	require.NoError(t, err)
	f.insert(f.deletion(f.alice, p.ID))
	drain(t, x)
	assert.Nil(t, w.doc(f.alice.pub), "the delete is applied after the upsert sent before it")
}

func TestSearchPipeline_EnqueueErrorLosesNothing(t *testing.T) {
	f, x, w := searchFixture(t) // a plain Writer: enqueue applies at once
	w.fail = errors.New("down")
	f.insert(f.profile(f.alice, `{"name":"alice"}`))
	_, err := x.Step(context.Background())
	require.Error(t, err)
	w.fail = nil
	drain(t, x)
	assert.NotNil(t, w.doc(f.alice.pub))
}

func TestSearchPipeline_ExclusiveDropsInFlight(t *testing.T) {
	f, x, w := queuedFixture(t, WithSearchBatch(1), WithSearchInFlight(4))
	f.insert(f.profile(f.alice, `{"name":"alice"}`))
	_, err := x.Step(context.Background())
	require.NoError(t, err)
	require.NoError(t, x.Exclusive(func() error { return nil }))
	drain(t, x)
	assert.NotNil(t, w.doc(f.alice.pub), "read again after the pause")
}

func TestFeed_ChangesFromReadsPastTheCursor(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	require.NoError(t, f.store.EnsureFeed(SearchFeed))
	carol := newTestKey(t, 13)
	f.insert(f.profile(f.alice, `{}`), f.note(f.alice, 1), f.profile(f.bob, `{}`), f.profile(carol, `{}`))
	for _, k := range []testKey{f.alice, f.bob, carol} {
		require.NoError(t, f.store.UpdateProfileMetrics(k.pub, func(m *ProfileMetrics) { m.SocialScore = 1 }))
	}

	b1, c1, err := f.store.FeedChangesFrom(SearchFeed.Name, FeedCursor{}, 1, 2)
	require.NoError(t, err)
	require.Len(t, b1.Events, 1)
	require.Len(t, b1.Dirty, 2)
	b2, c2, err := f.store.FeedChangesFrom(SearchFeed.Name, c1, 5, 5)
	require.NoError(t, err)
	assert.Len(t, b2.Events, 2, "the profiles after the first, past the note")
	assert.Len(t, b2.Dirty, 1, "only the queued author not read yet")
	assert.NotContains(t, b2.Dirty, b1.Dirty[0])
	b3, _, err := f.store.FeedChangesFrom(SearchFeed.Name, c2, 5, 5)
	require.NoError(t, err)
	assert.True(t, b3.Empty())

	// Acknowledged up to b1: a zero cursor starts from the watermark.
	require.NoError(t, f.store.AckFeed(SearchFeed.Name, b1))
	b4, _, err := f.store.FeedChangesFrom(SearchFeed.Name, FeedCursor{}, 5, 5)
	require.NoError(t, err)
	assert.Equal(t, b2.Evsids, b4.Evsids)
	assert.Equal(t, b2.Dirty, b4.Dirty)
}

func TestFeed_ChangesFromFillsPastOneReadTransaction(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	require.NoError(t, f.store.EnsureFeed(SearchFeed))
	var notes []*nip01.Event
	for range scanBatch*5 + 10 {
		notes = append(notes, f.note(f.alice, 1))
	}
	f.insert(notes...)
	f.insert(f.profile(f.bob, `{}`))
	b, _, err := f.store.FeedChangesFrom(SearchFeed.Name, FeedCursor{}, 10, 10)
	require.NoError(t, err)
	assert.Len(t, b.Events, 1, "the profile behind more notes than one read takes")
}
