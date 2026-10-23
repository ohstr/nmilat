package relay

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFeed_QueuedAgainWhileInFlightStaysQueued(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	require.NoError(t, f.store.EnsureFeed(SearchFeed))
	p := f.profile(f.alice, `{"name":"a"}`)
	f.insert(p, f.deletion(f.alice, p.ID))

	batch, err := f.store.FeedChanges(SearchFeed.Name, 10, 10)
	require.NoError(t, err)
	require.Equal(t, []string{f.alice.pub}, batch.Dirty)
	// Rescored while the consumer works on the batch.
	require.NoError(t, f.store.UpdateProfileMetrics(f.alice.pub, func(m *ProfileMetrics) { m.SocialScore = 3 }))
	require.NoError(t, f.store.AckFeed(SearchFeed.Name, batch))

	st, err := f.store.FeedStatus(SearchFeed.Name)
	require.NoError(t, err)
	assert.Equal(t, int64(1), st.Queued, "the newer change is still to apply")
	assert.Zero(t, st.Behind)
}

func TestFeed_UnknownAndDropped(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	_, err := f.store.FeedChanges("nope", 1, 1)
	assert.ErrorIs(t, err, ErrUnknownFeed)
	require.NoError(t, f.store.EnsureFeed(SearchFeed))
	require.NoError(t, f.store.DropFeed(SearchFeed.Name))
	_, err = f.store.FeedStatus(SearchFeed.Name)
	assert.ErrorIs(t, err, ErrUnknownFeed)

	// A dropped feed queues nothing more.
	p := f.profile(f.alice, `{}`)
	f.insert(p, f.deletion(f.alice, p.ID))
	assert.ErrorIs(t, f.store.DropFeed(SearchFeed.Name), ErrUnknownFeed)
}

func TestFeed_UptoCutsTheBatch(t *testing.T) {
	b := FeedBatch{Evsids: []uint64{4, 7, 9}, Through: 12, Dirty: []string{"x"}}
	b.Events = make([]*nip01.Event, 3)
	assert.Equal(t, uint64(7), b.Upto(2).Through)
	assert.Empty(t, b.Upto(2).Dirty)
	assert.Equal(t, uint64(3), b.Upto(0).Through)
	assert.Equal(t, uint64(12), b.Upto(3).Through)
}
