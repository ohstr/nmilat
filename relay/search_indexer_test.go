package relay

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSearchWriter is a search engine in memory that can be made to fail.
type fakeSearchWriter struct {
	mu   sync.Mutex
	docs map[string]*search.ProfileDocument
	fail error
}

func (w *fakeSearchWriter) Upsert(_ context.Context, docs []*search.ProfileDocument) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail != nil {
		return w.fail
	}
	if w.docs == nil {
		w.docs = map[string]*search.ProfileDocument{}
	}
	for _, d := range docs {
		w.docs[d.ID] = d
	}
	return nil
}

func (w *fakeSearchWriter) Delete(_ context.Context, pubkeys []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fail != nil {
		return w.fail
	}
	for _, pk := range pubkeys {
		delete(w.docs, pk)
	}
	return nil
}

func (w *fakeSearchWriter) doc(pk string) *search.ProfileDocument {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.docs[pk]
}

func (w *fakeSearchWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.docs)
}

// drain runs the indexer until the feed has nothing left.
func drain(t *testing.T, x *SearchIndexer) {
	t.Helper()
	for range 100 {
		more, err := x.Step(context.Background())
		require.NoError(t, err)
		if !more {
			return
		}
	}
	t.Fatal("the search feed never drained")
}

func searchFixture(t *testing.T) (*indexFixture, *SearchIndexer, *fakeSearchWriter) {
	f := newManualIndexFixture(t, noIndexes)
	w := &fakeSearchWriter{}
	x, err := NewSearchIndexer(f.store, w)
	require.NoError(t, err)
	return f, x, w
}

func (f *indexFixture) profile(k testKey, content string) *nip01.Event {
	f.at++
	ev := &nip01.Event{PubKey: k.pub, CreatedAt: f.at, Kind: 0, Content: content}
	require.NoError(f.t, ev.Sign(k.priv))
	return ev
}

func TestSearchIndexer_IndexesStoredProfilesOnly(t *testing.T) {
	f, x, w := searchFixture(t)
	f.insert(
		f.profile(f.alice, `{"name":"alice"}`),
		f.note(f.bob, 1),
		f.profile(f.bob, "not json at all"),
	)
	drain(t, x)
	assert.Equal(t, 2, w.count(), "profiles, not notes")
	assert.Equal(t, "alice", w.doc(f.alice.pub).Name)
	assert.Equal(t, int64(-500), w.doc(f.bob.pub).Score, "invalid content still indexed, penalised")
	st := x.Status()
	assert.Zero(t, st.Behind)
	assert.Equal(t, int64(2), st.Upserted)
}

func TestSearchIndexer_OlderProfileNeverReplacesNewer(t *testing.T) {
	f, x, w := searchFixture(t)
	newer := f.profile(f.alice, `{"name":"new"}`)
	older := &nip01.Event{PubKey: f.alice.pub, CreatedAt: newer.CreatedAt - 10, Kind: 0, Content: `{"name":"old"}`}
	require.NoError(t, older.Sign(f.alice.priv))
	f.insert(newer)
	f.insert(older) // rejected by the store as older
	drain(t, x)
	assert.Equal(t, "new", w.doc(f.alice.pub).Name)
}

func TestSearchIndexer_DeletedProfileLeaves(t *testing.T) {
	f, x, w := searchFixture(t)
	p := f.profile(f.alice, `{"name":"alice"}`)
	f.insert(p)
	drain(t, x)
	require.NotNil(t, w.doc(f.alice.pub))

	f.insert(f.deletion(f.alice, p.ID))
	drain(t, x)
	assert.Nil(t, w.doc(f.alice.pub), "a kind 5 removes it from search")
}

func TestSearchIndexer_EngineOutageLosesNothing(t *testing.T) {
	f, x, w := searchFixture(t)
	w.fail = errors.New("search backend unavailable")
	p := f.profile(f.alice, `{"name":"alice"}`)
	f.insert(p, f.profile(f.bob, `{"name":"bob"}`))
	_, err := x.Step(context.Background())
	assert.Error(t, err)
	assert.Contains(t, x.Status().LastError, "unavailable")
	assert.NotZero(t, x.Status().Behind, "nothing acknowledged")

	// Writes keep being accepted meanwhile, and a delete waits its turn.
	f.insert(f.deletion(f.alice, p.ID))
	w.fail = nil
	drain(t, x)
	assert.Nil(t, w.doc(f.alice.pub))
	assert.NotNil(t, w.doc(f.bob.pub))
	assert.Empty(t, x.Status().LastError)
}

func TestSearchIndexer_FollowsWhileItWasOff(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	require.NoError(t, f.store.EnsureFeed(SearchFeed))
	p := f.profile(f.alice, `{"name":"alice"}`)
	f.insert(p, f.profile(f.bob, `{"name":"bob"}`))
	f.insert(f.deletion(f.alice, p.ID))
	f.reopen(noIndexes) // the feed is kept in the store

	w := &fakeSearchWriter{}
	x, err := NewSearchIndexer(f.store, w)
	require.NoError(t, err)
	drain(t, x)
	assert.Nil(t, w.doc(f.alice.pub), "deleted before the indexer ran")
	assert.NotNil(t, w.doc(f.bob.pub))
}

func TestSearchIndexer_ScoreChangesReachSearch(t *testing.T) {
	f, x, w := searchFixture(t)
	f.insert(f.profile(f.alice, `{"name":"alice"}`))
	drain(t, x)
	before := w.doc(f.alice.pub).Score
	require.NoError(t, f.store.UpdateProfileMetrics(f.alice.pub, func(m *ProfileMetrics) { m.SocialScore = 7 }))
	st := x.Status()
	assert.Equal(t, int64(1), st.Queued)
	drain(t, x)
	assert.Equal(t, before+7, w.doc(f.alice.pub).Score)
	assert.Zero(t, x.Status().Queued)
}

func TestSearchIndexer_RebuildFromZero(t *testing.T) {
	f, x, w := searchFixture(t)
	f.insert(f.profile(f.alice, `{"name":"alice"}`))
	drain(t, x)
	w.docs = nil
	require.NoError(t, f.store.SetFeedWatermark(SearchFeed.Name, 0))
	drain(t, x)
	assert.NotNil(t, w.doc(f.alice.pub))
}
