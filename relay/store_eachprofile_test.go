package relay

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

// fullProfileScan is the newest kind 0 per author found by reading every
// stored event, as search rebuilds did before EachProfile.
func fullProfileScan(t *testing.T, s *EventStore) (map[string]string, int) {
	out := map[string]string{}
	newest := map[string]int64{}
	read := 0
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(indexEvents).ForEach(func(_, v []byte) error {
			read++
			var ev nip01.Event
			if json.Unmarshal(v, &ev) != nil || ev.Kind != 0 {
				return nil
			}
			if ts, ok := newest[ev.PubKey]; !ok || int64(ev.CreatedAt) > ts {
				newest[ev.PubKey], out[ev.PubKey] = int64(ev.CreatedAt), ev.ID
			}
			return nil
		})
	}))
	return out, read
}

func eachProfile(t *testing.T, s *EventStore) map[string]string {
	out := map[string]string{}
	require.NoError(t, s.EachProfile(context.Background(), func(ev *nip01.Event) error {
		require.Equal(t, 0, ev.Kind)
		_, dup := out[ev.PubKey]
		require.False(t, dup, "one profile per author")
		out[ev.PubKey] = ev.ID
		return nil
	}))
	return out
}

func TestEachProfile_MatchesAFullScan(t *testing.T) {
	defer func(n int) { profileScanChunk = n }(profileScanChunk)
	profileScanChunk = 2 // several read transactions

	f := newManualIndexFixture(t, noIndexes)
	var events []*nip01.Event
	var keys []testKey
	for i := range 7 {
		k := newTestKey(t, 200+i)
		keys = append(keys, k)
		events = append(events, f.profile(k, `{"name":"first"}`))
		for range 8 {
			events = append(events, f.note(k, 1))
		}
	}
	f.insert(events...)
	// Replaced, deleted, and a replacement older than what's stored.
	f.insert(f.profile(keys[1], `{"name":"second"}`))
	deleted := f.profile(keys[2], `{"name":"gone"}`)
	f.insert(deleted)
	f.insert(f.deletion(keys[2], deleted.ID))
	stale := &nip01.Event{PubKey: keys[3].pub, CreatedAt: 1, Kind: 0, Content: `{"name":"stale"}`}
	require.NoError(t, stale.Sign(keys[3].priv))
	f.insert(stale)

	want, read := fullProfileScan(t, f.store)
	got := eachProfile(t, f.store)
	assert.Equal(t, want, got)
	assert.Len(t, got, 6, "the deleted profile is gone")
	// One event read per profile, against every event for the full scan.
	assert.LessOrEqual(t, len(got)*5, read, "at least 80% fewer reads")
}

func TestEachProfile_StopsOnErrorAndCancel(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	f.insert(f.profile(f.alice, `{}`), f.profile(f.bob, `{}`))
	boom := errors.New("boom")
	n := 0
	err := f.store.EachProfile(context.Background(), func(*nip01.Event) error { n++; return boom })
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, 1, n)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Error(t, f.store.EachProfile(ctx, func(*nip01.Event) error { return nil }))
}

func TestEachProfile_EmptyStore(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	f.insert(f.note(f.alice, 1))
	assert.Empty(t, eachProfile(t, f.store))
}
