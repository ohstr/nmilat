package relay

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

// bruteCounts recounts from the indexes: what the counters must equal.
func bruteCounts(t *testing.T, store *EventStore) (map[int]uint64, uint64) {
	kinds := map[int]uint64{}
	var authors uint64
	require.NoError(t, store.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(indexKind).ForEach(func(k, _ []byte) error {
			kinds[int(btoi(k[:8]))]++
			return nil
		}); err != nil {
			return err
		}
		var last []byte
		return tx.Bucket(indexPubkey).ForEach(func(k, _ []byte) error {
			if !bytes.Equal(k[:32], last) {
				authors++
				last = bytes.Clone(k[:32])
			}
			return nil
		})
	}))
	return kinds, authors
}

func assertCountsExact(t *testing.T, store *EventStore) Counts {
	t.Helper()
	kinds, authors := bruteCounts(t, store)
	c := store.Counts()
	require.True(t, c.Ready)
	assert.Equal(t, kinds, c.Kinds)
	assert.Equal(t, authors, c.Authors)
	var events uint64
	for _, n := range kinds {
		events += n
	}
	assert.Equal(t, events, c.Events)
	return c
}

func signed(t *testing.T, key testKey, kind int, createdAt uint64, tags ...[]string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{PubKey: key.pub, Kind: kind, CreatedAt: createdAt, Tags: tags, Content: strconv.Itoa(kind)}
	require.NoError(t, ev.Sign(key.priv))
	return ev
}

func TestCounters_FollowEveryWrite(t *testing.T) {
	store := newStore(t)
	alice, bob, carol := newTestKey(t, 1), newTestKey(t, 2), newTestKey(t, 3)
	now := uint64(time.Now().Unix())

	note := signed(t, alice, 1, now-10)
	InsertTestEvents(t, store, []*nip01.Event{note, signed(t, alice, 1, now-9), signed(t, bob, 1, now-8)})
	c := assertCountsExact(t, store)
	assert.Equal(t, uint64(3), c.Kind(1))
	assert.Equal(t, uint64(2), c.Authors)

	// Duplicates change nothing.
	InsertTestEvents(t, store, []*nip01.Event{note})
	assert.Equal(t, uint64(3), assertCountsExact(t, store).Events)

	// Replaceable and addressable replacements keep one each.
	InsertTestEvents(t, store, []*nip01.Event{signed(t, alice, 0, now-7), signed(t, alice, 0, now-6)})
	InsertTestEvents(t, store, []*nip01.Event{signed(t, bob, 30023, now-5, []string{"d", "x"}), signed(t, bob, 30023, now-4, []string{"d", "x"})})
	c = assertCountsExact(t, store)
	assert.Equal(t, uint64(1), c.Kind(0))
	assert.Equal(t, uint64(1), c.Kind(30023))

	// A new author, then their note deleted: the note goes, the kind 5 is kept and counted (NIP-09).
	carols := signed(t, carol, 1, now-3)
	InsertTestEvents(t, store, []*nip01.Event{carols})
	assert.Equal(t, uint64(3), assertCountsExact(t, store).Authors)
	InsertTestEvents(t, store, []*nip01.Event{signed(t, carol, 5, now-2, []string{"e", carols.ID})})
	c = assertCountsExact(t, store)
	assert.Equal(t, uint64(3), c.Authors, "carol's deletion request is still hers")
	assert.Equal(t, uint64(1), c.Kind(5))

	// Expired events are pruned and uncounted: a new author's only event expires, authors back down.
	dave := newTestKey(t, 4)
	InsertTestEvents(t, store, []*nip01.Event{signed(t, dave, 1, now-30, []string{"expiration", strconv.FormatUint(now-20, 10)})})
	assert.Equal(t, uint64(4), assertCountsExact(t, store).Authors)
	require.NoError(t, store.pruneExpiredEvents())
	require.Eventually(t, func() bool { return store.Counts().Authors == 3 }, 5*time.Second, 10*time.Millisecond)
	assertCountsExact(t, store)
}

func TestCounters_BackfillWhileWriting(t *testing.T) {
	old := countersChunk
	countersChunk = 3
	t.Cleanup(func() { countersChunk = old })

	path := filepath.Join(t.TempDir(), "counters.db")
	open := func() *EventStore {
		s, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
		require.NoError(t, err)
		return s
	}
	store := open()
	now := uint64(time.Now().Unix())
	var events []*nip01.Event
	for i := 0; i < 40; i++ {
		events = append(events, signed(t, newTestKey(t, i%9), []int{1, 7, 1984}[i%3], now-uint64(100+i)))
	}
	InsertTestEvents(t, store, events)

	// A store from before counters.
	require.NoError(t, store.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(indexCounters) }))
	store.Close()

	store = open()
	t.Cleanup(store.Close)
	// Writes race the chunked backfill: new authors and kinds, and deletes.
	for i := 0; i < 20; i++ {
		InsertTestEvents(t, store, []*nip01.Event{signed(t, newTestKey(t, 100+i%4), []int{1, 6, 30000 + i}[i%3], now-uint64(i), []string{"d", fmt.Sprint(i)})})
		if i%5 == 0 {
			ev := events[i]
			InsertTestEvents(t, store, []*nip01.Event{signed(t, newTestKey(t, i%9), 5, now, []string{"e", ev.ID})})
		}
	}
	require.Eventually(t, func() bool { return store.Counts().Ready }, 5*time.Second, 10*time.Millisecond)
	assertCountsExact(t, store)
}

func TestCounters_EmptyStoreIsReady(t *testing.T) {
	assert.True(t, newStore(t).Counts().Ready)
}

func TestCountFromCounters_OnlyKindFilters(t *testing.T) {
	store := newStore(t)
	alice := newTestKey(t, 1)
	now := uint64(time.Now().Unix())
	InsertTestEvents(t, store, []*nip01.Event{signed(t, alice, 1, now-3), signed(t, alice, 1, now-2), signed(t, alice, 7, now-1)})

	group := func(fs ...*nip01.SubscriptionFilter) *nip01.SubscriptionFilterGroup {
		return nip01.NewSubscriptionFilterGroup(fs...)
	}
	for name, c := range map[string]struct {
		g    *nip01.SubscriptionFilterGroup
		n    int64
		used bool
	}{
		"empty":             {group(&nip01.SubscriptionFilter{}), 3, true},
		"one kind":          {group(&nip01.SubscriptionFilter{Kinds: []int{1}}), 2, true},
		"kinds across":      {group(&nip01.SubscriptionFilter{Kinds: []int{1}}, &nip01.SubscriptionFilter{Kinds: []int{1, 7}}), 3, true},
		"empty wins":        {group(&nip01.SubscriptionFilter{Kinds: []int{7}}, &nip01.SubscriptionFilter{}), 3, true},
		"unknown kind":      {group(&nip01.SubscriptionFilter{Kinds: []int{42}}), 0, true},
		"authors need scan": {group(&nip01.SubscriptionFilter{Authors: []string{alice.pub}}), 0, false},
		"tags need scan":    {group(&nip01.SubscriptionFilter{Tags: map[string][]string{"p": {alice.pub}}}), 0, false},
		"since needs scan":  {group(&nip01.SubscriptionFilter{Since: 1}), 0, false},
		"limit needs scan":  {group(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 1}), 0, false},
	} {
		n, used := store.CountFromCounters(c.g)
		assert.Equal(t, c.used, used, name)
		if c.used {
			assert.Equal(t, c.n, n, name)
		}
	}
}

func TestProcessCount_ExactBeyondMaxLimitAndApproximateWhenCapped(t *testing.T) {
	store, err := NewEventStore(filepath.Join(t.TempDir(), "count.db"), &nip11.Limitation{MaxLimit: 3}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	t.Cleanup(store.Close)
	alice := newTestKey(t, 1)
	now := uint64(time.Now().Unix())
	for i := 0; i < 10; i++ {
		InsertTestEvents(t, store, []*nip01.Event{signed(t, alice, 1, now-uint64(i))})
	}
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, defaultSessionConfig())
	sc.groups = NewGroupsService(store)
	sess := &Session{SessionContext: sc}

	count := func(f *nip01.SubscriptionFilter) *wire.CountSubscriptionResponse {
		require.NoError(t, sess.processCount(context.Background(), &wire.CountPacket{SubscriptionID: "c", Filters: nip01.NewSubscriptionFilterGroup(f)}))
		resp, ok := (<-sess.incoming).(*wire.CountSubscriptionResponse)
		require.True(t, ok)
		return resp
	}

	exact := count(&nip01.SubscriptionFilter{Kinds: []int{1}})
	assert.Equal(t, int64(10), exact.Count, "kind-only COUNT is exact past max_limit")
	assert.False(t, exact.Approximate)

	capped := count(&nip01.SubscriptionFilter{Authors: []string{alice.pub}})
	assert.Equal(t, int64(3), capped.Count)
	assert.True(t, capped.Approximate, "a scan that hit max_limit is a lower bound")

	small := count(&nip01.SubscriptionFilter{Authors: []string{alice.pub}, Since: now - 1})
	assert.Equal(t, int64(2), small.Count)
	assert.False(t, small.Approximate)
}

func BenchmarkCounts(b *testing.B) {
	for _, n := range []int{100, 10_000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			store := newStore(b)
			now := uint64(time.Now().Unix())
			var batch []*nip01.Event
			for i := 0; i < n; i++ {
				k := newTestKey(b, i%500)
				ev := &nip01.Event{PubKey: k.pub, Kind: i % 20, CreatedAt: now - uint64(i), Content: strconv.Itoa(i)}
				require.NoError(b, ev.Sign(k.priv))
				batch = append(batch, ev)
			}
			InsertTestEvents(b, store, batch)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = store.Counts()
			}
		})
	}
}
