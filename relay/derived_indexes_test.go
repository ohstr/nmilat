package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

var (
	noIndexes   = DerivedIndexes{}
	bothIndexes = DerivedIndexes{Zaps: true, Social: true}
)

// indexFixture opens, closes and reopens one store file with chosen
// derived indexes, and builds the events they index.
type indexFixture struct {
	*socialFixture
	path   string
	manual bool
	obs    *indexObserver
}

func newIndexFixture(t *testing.T, ix DerivedIndexes) *indexFixture {
	return newIndexFixtureWith(t, ix, false)
}

// newManualIndexFixture leaves the index operations to the test.
func newManualIndexFixture(t *testing.T, ix DerivedIndexes) *indexFixture {
	return newIndexFixtureWith(t, ix, true)
}

func newIndexFixtureWith(t *testing.T, ix DerivedIndexes, manual bool) *indexFixture {
	f := &indexFixture{
		socialFixture: &socialFixture{t: t, alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12), at: 1_700_000_000},
		path:          filepath.Join(t.TempDir(), "derived.db"),
		manual:        manual,
		obs:           &indexObserver{},
	}
	f.reopen(ix)
	return f
}

// indexObserver counts index operation transactions.
type indexObserver struct {
	NopObserver
	mu  sync.Mutex
	txs int
	max time.Duration
}

func (o *indexObserver) IndexBatchCommitted(_ string, d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.txs++
	o.max = max(o.max, d)
}

func (o *indexObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.txs
}

// reopen closes the store and opens the same file with ix.
func (f *indexFixture) reopen(ix DerivedIndexes) {
	if f.store != nil {
		f.store.Close()
	}
	opts := []EventStoreOption{WithEventStoreLogger(testlogger.New(f.t)), WithEventStoreIndexes(ix), WithEventStoreObserver(f.obs)}
	if f.manual {
		opts = append(opts, WithEventStoreIndexMaintenance(MaintenanceManual))
	}
	store, err := NewEventStore(f.path, &nip11.Limitation{MaxLimit: 1000}, opts...)
	require.NoError(f.t, err)
	f.t.Cleanup(store.Close)
	f.store = store
}

func (f *indexFixture) note(author testKey, kind int) *nip01.Event {
	f.at++
	ev := &nip01.Event{PubKey: author.pub, CreatedAt: f.at, Kind: kind, Content: "{}"}
	require.NoError(f.t, ev.Sign(author.priv))
	return ev
}

// mixed is one of everything: a note, a profile, a contact list replaced
// by a newer one, a NIP-57 zap and an AltZap.
func (f *indexFixture) mixed() []*nip01.Event {
	f.at += 10
	return []*nip01.Event{
		f.note(f.alice, 1),
		f.note(f.alice, 0),
		f.note(f.bob, 0),
		f.contacts(f.bob, f.at-5, f.alice.pub),
		f.contacts(f.bob, f.at-4, f.alice.pub, f.provider.pub),
		f.zap(f.bob.pub, f.alice.pub, 21_000),
		f.zap(f.bob.pub, f.alice.pub, 2_000, func(z *zapSpec) { z.Kind = nipAZ.KindAltZapReceipt }),
	}
}

// derivedBuckets closes the store and lists, straight from the file, the
// top-level buckets of the zap and social indexes.
func (f *indexFixture) derivedBuckets() []string {
	f.store.Close()
	db, err := bolt.Open(f.path, 0o600, &bolt.Options{Timeout: time.Second, ReadOnly: true})
	require.NoError(f.t, err)
	defer func() { _ = db.Close() }()
	var names []string
	require.NoError(f.t, db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if name[0] == indexZaps[0] || name[0] == socialDefault[0] {
				names = append(names, string(name))
			}
			return nil
		})
	}))
	return names
}

func (f *indexFixture) status(name string) IndexStatus {
	st, err := f.store.IndexStatus(name)
	require.NoError(f.t, err)
	return st
}

// waitCurrent waits until every enabled index needs nothing.
func (f *indexFixture) waitCurrent() {
	require.Eventually(f.t, func() bool {
		for _, name := range []string{IndexZaps, IndexSocial} {
			st := f.status(name)
			if st.Running != "" || (st.Enabled && st.Action != "" && st.Action != ActionReap) {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
}

// run runs what an index asks for until it needs nothing.
func (f *indexFixture) run(name string) {
	for range 10 {
		st := f.status(name)
		if st.Action == "" {
			return
		}
		_, err := f.store.RunIndexAction(context.Background(), name, st.Action, nil)
		require.NoError(f.t, err, "%s %s", name, st.Action)
	}
	f.t.Fatalf("%s never settled", name)
}

func (f *indexFixture) zapTotal() uint64 {
	ranked, err := f.store.TopZapped(context.Background(), 0, 1<<62, CoinSats, 10)
	require.NoError(f.t, err)
	var total uint64
	for _, r := range ranked {
		total += r.Total
	}
	return total
}

func (f *indexFixture) rawState(d *derivedIndex) (byte, uint64) {
	var st byte
	var w uint64
	require.NoError(f.t, f.store.db.View(func(tx *bolt.Tx) error {
		st, w = d.state(tx)
		return nil
	}))
	return st, w
}

// snapshot dumps a bucket's keys and values, nested buckets included.
func snapshot(b *bolt.Bucket, prefix string, out map[string]string) {
	_ = b.ForEach(func(k, v []byte) error {
		if v == nil {
			snapshot(b.Bucket(k), prefix+string(k)+"/", out)
			return nil
		}
		out[prefix+string(k)] = string(v)
		return nil
	})
}

func activeSnapshot(t *testing.T, s *EventStore, d *derivedIndex) map[string]string {
	out := map[string]string{}
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(d.active(tx)); b != nil {
			snapshot(b, "", out)
		}
		return nil
	}))
	return out
}

func TestDerivedIndexes_DefaultOff(t *testing.T) {
	off := newIndexFixture(t, noIndexes)
	events := off.mixed()
	off.insert(events...)
	assert.Empty(t, off.store.TakeSocialDirty(100))

	on := newIndexFixture(t, bothIndexes)
	on.insert(events...)

	filter := &nip01.SubscriptionFilter{Kinds: []int{0, 1, 3, 9735, 9521}}
	ids := func(s *EventStore) []string {
		evs, err := s.QueryEvents(context.Background(), filter)
		require.NoError(t, err)
		var out []string
		for _, ev := range evs {
			out = append(out, ev.ID)
		}
		sort.Strings(out)
		return out
	}
	assert.Equal(t, ids(on.store), ids(off.store), "queries don't depend on derived indexes")
	assert.Len(t, ids(off.store), 6, "the older contact list was replaced")
	assert.Equal(t, on.store.Counts(), off.store.Counts())

	assert.Empty(t, off.derivedBuckets())
	assert.NotEmpty(t, on.derivedBuckets())
}

func TestDerivedIndexes_EachIndependently(t *testing.T) {
	for _, ix := range []DerivedIndexes{{Zaps: true}, {Social: true}, bothIndexes} {
		f := newIndexFixture(t, ix)
		f.insert(f.mixed()...)

		_, zerr := f.store.ZapTotals(context.Background(), ZapRankingConfig{})
		_, serr := f.store.GetProfileStats(f.alice.pub)
		assert.Equal(t, !ix.Zaps, zerr != nil, "%+v", ix)
		assert.Equal(t, !ix.Social, serr != nil, "%+v", ix)
		assert.Equal(t, ix.Zaps, f.status(IndexZaps).HasData, "%+v", ix)
		assert.Equal(t, ix.Social, f.status(IndexSocial).HasData, "%+v", ix)
	}
}

func TestDerivedIndexes_ExactEntries(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	assert.Equal(t, int64(2), f.status(IndexZaps).Entries, "two receipts")
	assert.Equal(t, int64(2), f.status(IndexSocial).Entries, "alice and provider have followers")

	f.insert(f.contacts(f.bob, f.at+1))
	assert.Equal(t, int64(0), f.status(IndexSocial).Entries, "bob unfollowed both")
}

func TestDerivedIndexes_DeletesSkipDisabled(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	zap := f.zap(f.bob.pub, f.alice.pub, 1_000)
	f.insert(zap, f.contacts(f.bob, 10, f.alice.pub))
	f.insert(f.deletion(f.provider, zap.ID), f.contacts(f.bob, 20))

	pes, err := f.store.FindEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{3}})
	require.NoError(t, err)
	require.NoError(t, f.store.DeleteAll(pes))

	assert.Empty(t, f.derivedBuckets())
}

func TestDerivedIndexes_WriteDoesNothingWhenOff(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	zap := f.zap(f.bob.pub, f.alice.pub, 1_000)
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error { return f.store.write(tx, f.store.zaps, zap, 1, true) }))
	assert.Empty(t, f.derivedBuckets())
}

func TestDerivedIndexes_ReadersAndOperationsRefusedWhenOff(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	f.insert(f.mixed()...)
	ctx := context.Background()

	_, err := f.store.ZapRanking(ctx, ZapRankingConfig{}, ZapWindow{D: time.Hour}, CoinSats)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.ZapTotals(ctx, ZapRankingConfig{})
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.TopZapped(ctx, 0, 1<<62, CoinSats, 10)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.GetProfileStats(f.alice.pub)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.ComputeSocialScore(f.alice.pub)
	assert.ErrorIs(t, err, ErrIndexDisabled)

	for _, name := range []string{IndexZaps, IndexSocial} {
		st := f.status(name)
		assert.Equal(t, StateDisabled, st.State)
		assert.Empty(t, st.Action)
		assert.Zero(t, st.Entries)
		_, err = f.store.RebuildIndex(ctx, name, nil)
		assert.ErrorIs(t, err, ErrIndexDisabled)
		_, err = f.store.CatchUpIndex(ctx, name, nil)
		assert.ErrorIs(t, err, ErrIndexDisabled)
	}
	_, err = f.store.RescoreIndex(ctx, IndexSocial, nil)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.IndexStatus("nope")
	assert.ErrorIs(t, err, ErrUnknownIndex)

	assert.Empty(t, f.derivedBuckets())
}

func TestDerivedIndexes_IngestMatchesRebuild(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	zaps, social := activeSnapshot(t, f.store, f.store.zaps), activeSnapshot(t, f.store, f.store.social)
	require.NotEmpty(t, zaps)
	require.NotEmpty(t, social)
	entries := []int64{f.status(IndexZaps).Entries, f.status(IndexSocial).Entries}

	for _, name := range []string{IndexZaps, IndexSocial} {
		res, err := f.store.RebuildIndex(context.Background(), name, nil)
		require.NoError(t, err)
		assert.Equal(t, res.EntriesBefore, res.EntriesAfter, name)
	}
	assert.Equal(t, zaps, activeSnapshot(t, f.store, f.store.zaps))
	assert.Equal(t, social, activeSnapshot(t, f.store, f.store.social))
	assert.Equal(t, entries, []int64{f.status(IndexZaps).Entries, f.status(IndexSocial).Entries})
}

func TestDerivedIndexes_ReadOnlyOpenChangesNothing(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()

	f.reopen(noIndexes)
	_, err := f.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{9735}})
	require.NoError(t, err)
	f.insert(f.note(f.alice, 1)) // a write neither index cares about
	for _, d := range []*derivedIndex{f.store.zaps, f.store.social} {
		st, _ := f.rawState(d)
		assert.Equal(t, stLive, st, d.name)
	}

	f.reopen(bothIndexes)
	for _, name := range []string{IndexZaps, IndexSocial} {
		st := f.status(name)
		assert.Equal(t, StateReady, st.State, name)
		assert.Empty(t, st.Action, "nothing to do for %s", name)
	}
}

func TestDerivedIndexes_FirstSkippedWriteFreezes(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()
	f.reopen(noIndexes)

	follows := f.contacts(f.alice, f.at+1, f.bob.pub)
	f.insert(follows)
	head := f.store.Head()
	st, w := f.rawState(f.store.social)
	assert.Equal(t, stFrozen, st, "a skipped kind 3 freezes the social index")
	assert.Equal(t, head-1, w, "at the last event it reflects")
	st, _ = f.rawState(f.store.zaps)
	assert.Equal(t, stLive, st, "the zap index missed nothing")

	before := f.status(IndexZaps)
	f.insert(f.zap(f.alice.pub, f.bob.pub, 5_000))
	after := f.status(IndexZaps)
	st, _ = f.rawState(f.store.zaps)
	assert.Equal(t, stFrozen, st)
	assert.Equal(t, before.Entries, after.Entries, "data kept, unchanged")
	assert.True(t, after.HasData)
	require.NoError(t, f.store.db.View(func(tx *bolt.Tx) error {
		assert.Nil(t, metaValue(tx, zapMeta, coinsKey), "an older version would rebuild it")
		return nil
	}))
}

func TestDerivedIndexes_EnablingBuilds(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	f.insert(f.mixed()...)

	f.reopen(bothIndexes)
	f.waitCurrent()
	assert.Equal(t, uint64(21_000), f.zapTotal())
	st, err := f.store.GetProfileStats(f.alice.pub)
	require.NoError(t, err)
	assert.Equal(t, int64(1), st.Followers)
	assert.Equal(t, 2, st.ZapCntRecd)
}

func TestDerivedIndexes_ReenablingCatchesUp(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	old := f.zap(f.bob.pub, f.alice.pub, 1_000)
	f.insert(old)
	gen := activeGen(t, f.store, f.store.zaps)

	f.reopen(noIndexes)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 4_000), f.deletion(f.provider, old.ID))

	f.reopen(bothIndexes)
	st := f.status(IndexZaps)
	assert.Equal(t, StateBehind, st.State)
	assert.Equal(t, ActionCatchUp, st.Action)
	assert.Equal(t, int64(1), st.Tombstones)
	assert.Contains(t, st.Reason, "1 deleted")
	assert.NotZero(t, st.Behind)

	res, err := f.store.CatchUpIndex(context.Background(), IndexZaps, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), res.EntriesBefore)
	assert.Equal(t, int64(1), res.EntriesAfter)
	assert.Equal(t, uint64(4_000), f.zapTotal(), "the zap deleted while disabled is gone")
	assert.Equal(t, gen, activeGen(t, f.store, f.store.zaps), "caught up in place, not rebuilt")
	st = f.status(IndexZaps)
	assert.Equal(t, StateReady, st.State)
	assert.Zero(t, st.Tombstones)
	_, err = f.store.CatchUpIndex(context.Background(), IndexZaps, nil)
	assert.ErrorIs(t, err, ErrNothingToDo)
}

func activeGen(t *testing.T, s *EventStore, d *derivedIndex) string {
	var gen []byte
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		gen = d.active(tx)
		return nil
	}))
	return string(gen)
}

// TestDerivedIndexes_CatchUpMatchesRebuild drives random writes with the
// indexes off — zaps, contact lists replacing each other, deletions by
// kind 5 and by an admin — and checks a catch-up lands exactly where a
// rebuild from the stored events does.
func TestDerivedIndexes_CatchUpMatchesRebuild(t *testing.T) {
	for seed := int64(1); seed <= 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		f := newManualIndexFixture(t, bothIndexes)
		keys := []testKey{f.alice, f.bob, f.provider}
		var zaps []*nip01.Event
		randomWrites := func(n int) {
			for range n {
				switch rng.Intn(5) {
				case 0, 1:
					z := f.zap(keys[rng.Intn(2)].pub, keys[rng.Intn(3)].pub, int64(1_000*(1+rng.Intn(9))))
					zaps = append(zaps, z)
					f.insert(z)
				case 2:
					author := keys[rng.Intn(3)]
					var follows []string
					for _, k := range keys {
						if k.pub != author.pub && rng.Intn(2) == 0 {
							follows = append(follows, k.pub)
						}
					}
					f.at++
					f.insert(f.contacts(author, f.at, follows...))
				case 3:
					if len(zaps) > 0 {
						z := zaps[rng.Intn(len(zaps))]
						f.insert(f.deletion(f.key(z.PubKey), z.ID))
					}
				case 4:
					pes, err := f.store.FindEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{3}, Authors: []string{keys[rng.Intn(3)].pub}})
					require.NoError(t, err)
					require.NoError(t, f.store.DeleteAll(pes))
				}
			}
		}
		randomWrites(20)
		f.reopen(noIndexes)
		randomWrites(30)
		f.reopen(bothIndexes)

		for _, name := range []string{IndexZaps, IndexSocial} {
			if f.status(name).Action == ActionCatchUp {
				_, err := f.store.CatchUpIndex(context.Background(), name, nil)
				require.NoError(t, err)
			}
		}
		caught := []map[string]string{activeSnapshot(t, f.store, f.store.zaps), activeSnapshot(t, f.store, f.store.social)}
		entries := []int64{f.status(IndexZaps).Entries, f.status(IndexSocial).Entries}
		for _, name := range []string{IndexZaps, IndexSocial} {
			_, err := f.store.RebuildIndex(context.Background(), name, nil)
			require.NoError(t, err)
		}
		assert.Equal(t, activeSnapshot(t, f.store, f.store.zaps), caught[0], "seed %d: zaps", seed)
		assert.Equal(t, activeSnapshot(t, f.store, f.store.social), caught[1], "seed %d: social", seed)
		assert.Equal(t, []int64{f.status(IndexZaps).Entries, f.status(IndexSocial).Entries}, entries, "seed %d: entries", seed)
	}
}

func TestDerivedIndexes_SharedFollowsSurviveAnyOrder(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.contacts(f.alice, 10, f.bob.pub, f.provider.pub))
	f.reopen(noIndexes)
	f.insert(f.contacts(f.alice, 20, f.provider.pub))
	f.reopen(bothIndexes)
	require.Equal(t, ActionCatchUp, f.status(IndexSocial).Action)

	// A newer list arrives live before the catch-up removes the first one.
	f.insert(f.contacts(f.alice, 30, f.provider.pub))
	_, err := f.store.CatchUpIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), f.stats(f.provider.pub).Followers, "kept: the live list follows provider too")
	assert.Zero(t, f.stats(f.bob.pub).Followers)
	assert.Equal(t, int64(1), f.stats(f.alice.pub).Following)
}

func TestDerivedIndexes_TooManyDeletesMeanRebuild(t *testing.T) {
	old := maxTombstones
	maxTombstones = 1
	t.Cleanup(func() { maxTombstones = old })

	f := newManualIndexFixture(t, bothIndexes)
	a, b := f.zap(f.bob.pub, f.alice.pub, 1_000), f.zap(f.bob.pub, f.alice.pub, 2_000)
	f.insert(a, b, f.zap(f.bob.pub, f.alice.pub, 4_000))
	f.reopen(noIndexes)
	f.insert(f.deletion(f.provider, a.ID), f.deletion(f.provider, b.ID))

	f.reopen(bothIndexes)
	st := f.status(IndexZaps)
	assert.Equal(t, StateNeedsRebuild, st.State)
	assert.Equal(t, ActionRebuild, st.Action)
	assert.Equal(t, "too many deletes while the index was off", st.Reason)
	f.run(IndexZaps)
	assert.Equal(t, uint64(4_000), f.zapTotal())
	assert.Zero(t, f.status(IndexZaps).Retired, "the old generation and tombstones were freed")
}

// interruptedBuild starts a zap rebuild over many events and stops it
// after its first step.
func interruptedBuild(t *testing.T) (*indexFixture, map[string]string) {
	oldBatch, oldMax := scanBatch, applyMax
	scanBatch, applyMax = 20, 5
	t.Cleanup(func() { scanBatch, applyMax = oldBatch, oldMax })

	f := newManualIndexFixture(t, bothIndexes)
	var evs []*nip01.Event
	for i := range 60 {
		evs = append(evs, f.zap(f.bob.pub, f.alice.pub, int64(1_000+i)), f.note(f.alice, 1))
	}
	f.insert(evs...)
	want := activeSnapshot(t, f.store, f.store.zaps)

	ctx, cancel := context.WithCancel(context.Background())
	_, err := f.store.RebuildIndex(ctx, IndexZaps, func(IndexProgress) { cancel() })
	require.ErrorIs(t, err, context.Canceled)
	st := f.status(IndexZaps)
	require.NotNil(t, st.Build)
	require.NotZero(t, st.Build.Mark)
	assert.Equal(t, ActionResume, st.Action)
	assert.Equal(t, StateReady, st.State, "readers keep the old generation")
	return f, want
}

func TestDerivedIndexes_RebuildResumesAfterRestart(t *testing.T) {
	f, want := interruptedBuild(t)
	mark := f.status(IndexZaps).Build.Mark

	f.reopen(bothIndexes)
	st := f.status(IndexZaps)
	require.Equal(t, ActionResume, st.Action)
	first := uint64(0)
	_, err := f.store.RebuildIndex(context.Background(), IndexZaps, func(p IndexProgress) {
		if first == 0 {
			first = uint64(p.Done)
		}
	})
	require.NoError(t, err)
	assert.Greater(t, first, mark, "picked up after the mark, not from the start")
	assert.Equal(t, want, activeSnapshot(t, f.store, f.store.zaps))
	assert.Equal(t, int64(60), f.status(IndexZaps).Entries)
}

func TestDerivedIndexes_AbortedBuildIsRetired(t *testing.T) {
	f, _ := interruptedBuild(t)
	require.NoError(t, f.store.AbortIndexBuild(IndexZaps))
	st := f.status(IndexZaps)
	assert.Nil(t, st.Build)
	assert.Equal(t, 1, st.Retired)
	assert.Equal(t, ActionReap, st.Action)
	assert.ErrorIs(t, f.store.AbortIndexBuild(IndexZaps), ErrNothingToDo)
}

func TestDerivedIndexes_DisabledOpenRetiresBuild(t *testing.T) {
	f, _ := interruptedBuild(t)
	f.reopen(DerivedIndexes{Social: true})
	st := f.status(IndexZaps)
	assert.Nil(t, st.Build)
	assert.Equal(t, 1, st.Retired)
	require.NoError(t, f.store.db.View(func(tx *bolt.Tx) error {
		assert.Nil(t, f.store.zaps.building(tx))
		return nil
	}))
}

func TestDerivedIndexes_DeleteDuringRebuildStaysDeleted(t *testing.T) {
	oldMax := applyMax
	applyMax = 1
	t.Cleanup(func() { applyMax = oldMax })

	f := newManualIndexFixture(t, bothIndexes)
	keep, gone := f.zap(f.bob.pub, f.alice.pub, 1_000), f.zap(f.bob.pub, f.alice.pub, 2_000)
	f.insert(keep, gone)
	once := sync.Once{}
	_, err := f.store.RebuildIndex(context.Background(), IndexZaps, func(IndexProgress) {
		// After the first receipt is applied and before the second is.
		once.Do(func() { f.insert(f.deletion(f.provider, gone.ID)) })
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(1_000), f.zapTotal(), "a receipt deleted mid-rebuild isn't put back")
	assert.Equal(t, int64(1), f.status(IndexZaps).Entries)
}

func TestDerivedIndexes_OperationsHoldTheWriterBriefly(t *testing.T) {
	oldMax := applyMax
	applyMax = 4
	t.Cleanup(func() { applyMax = oldMax })

	f := newManualIndexFixture(t, bothIndexes)
	var evs []*nip01.Event
	for i := range 40 {
		evs = append(evs, f.zap(f.bob.pub, f.alice.pub, int64(1_000+i)))
	}
	f.insert(evs...)
	before := f.obs.count()
	_, err := f.store.RebuildIndex(context.Background(), IndexZaps, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, f.obs.count()-before, 10, "40 receipts at most 4 per transaction")

	// The swap only moved a pointer; the old generation is freed apart.
	st := f.status(IndexZaps)
	assert.Equal(t, 1, st.Retired)
	oldChunk := reapChunk
	reapChunk = 7
	t.Cleanup(func() { reapChunk = oldChunk })
	before = f.obs.count()
	res, err := f.store.ReapIndex(context.Background(), IndexZaps, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(40), res.Applied)
	assert.GreaterOrEqual(t, f.obs.count()-before, 6, "40 keys at most 7 per transaction")
	assert.Zero(t, f.status(IndexZaps).Retired)
	_, err = f.store.ReapIndex(context.Background(), IndexZaps, nil)
	assert.ErrorIs(t, err, ErrNothingToDo)
}

// within fails the test if fn doesn't return in time, so a livelock fails
// instead of hanging the suite.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("no progress within %s", d)
	}
}

// hogWriter holds the store's single writer for hold at a time until the
// test ends, as heavy ingest does.
func hogWriter(t *testing.T, s *EventStore, hold time.Duration) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = s.db.Update(func(*bolt.Tx) error { time.Sleep(hold); return nil })
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
}

// Waiting for the writer longer than applyBudget used to panic the scan
// (index out of range [-1]) and spin the reap without deleting anything.
func TestDerivedIndexes_ProgressWhenTheWriterWaitExceedsTheBudget(t *testing.T) {
	oldMax, oldBudget, oldChunk := applyMax, applyBudget, reapChunk
	applyMax, applyBudget, reapChunk = 4, 0, 7
	t.Cleanup(func() { applyMax, applyBudget, reapChunk = oldMax, oldBudget, oldChunk })

	f := newManualIndexFixture(t, bothIndexes)
	old := f.zap(f.bob.pub, f.alice.pub, 1)
	evs := []*nip01.Event{old}
	for i := range 40 {
		evs = append(evs, f.zap(f.bob.pub, f.alice.pub, int64(1_000+i)))
	}
	f.insert(evs...)
	var err error
	within(t, 10*time.Second, func() { _, err = f.store.RebuildIndex(context.Background(), IndexZaps, nil) })
	require.NoError(t, err)
	assert.Equal(t, int64(41), f.status(IndexZaps).Entries)

	var res IndexResult
	within(t, 10*time.Second, func() { res, err = f.store.ReapIndex(context.Background(), IndexZaps, nil) })
	require.NoError(t, err)
	assert.Equal(t, int64(41), res.Applied)
	assert.Zero(t, f.status(IndexZaps).Retired)

	f.reopen(noIndexes)
	f.insert(f.deletion(f.provider, old.ID))
	f.reopen(bothIndexes)
	within(t, 10*time.Second, func() { _, err = f.store.CatchUpIndex(context.Background(), IndexZaps, nil) })
	require.NoError(t, err)
	assert.Equal(t, int64(40), f.status(IndexZaps).Entries)
	assert.Zero(t, f.status(IndexZaps).Tombstones)
}

func TestDerivedIndexes_ProgressUnderWriterContention(t *testing.T) {
	oldMax, oldChunk := applyMax, reapChunk
	applyMax, reapChunk = 4, 7
	t.Cleanup(func() { applyMax, reapChunk = oldMax, oldChunk })

	f := newManualIndexFixture(t, bothIndexes)
	var evs []*nip01.Event
	for i := range 40 {
		evs = append(evs, f.zap(f.bob.pub, f.alice.pub, int64(1_000+i)))
	}
	f.insert(evs...)
	hogWriter(t, f.store, 2*applyBudget)
	var rebuildErr, reapErr error
	var res IndexResult
	within(t, 30*time.Second, func() {
		_, rebuildErr = f.store.RebuildIndex(context.Background(), IndexZaps, nil)
		res, reapErr = f.store.ReapIndex(context.Background(), IndexZaps, nil)
	})
	require.NoError(t, rebuildErr)
	require.NoError(t, reapErr)
	assert.Equal(t, int64(40), res.Applied)
	assert.Equal(t, int64(40), f.status(IndexZaps).Entries)
	assert.Zero(t, f.status(IndexZaps).Retired)
}

func TestDerivedIndexes_EmptyStoreMarksOnlyEnabled(t *testing.T) {
	f := newIndexFixture(t, DerivedIndexes{Zaps: true})
	assert.Equal(t, StateReady, f.status(IndexZaps).State)
	assert.Equal(t, StateDisabled, f.status(IndexSocial).State)
	assert.Equal(t, []string{string(zapMeta)}, f.derivedBuckets())
}

func TestDerivedIndexes_NeverBuiltOnAStoreWithEvents(t *testing.T) {
	f := newManualIndexFixture(t, noIndexes)
	f.insert(f.mixed()...)
	f.reopen(bothIndexes)
	st := f.status(IndexZaps)
	assert.Equal(t, StateNeedsRebuild, st.State)
	assert.Equal(t, ActionRebuild, st.Action)
	assert.Equal(t, "never built", st.Reason)
	f.run(IndexZaps)
	assert.Equal(t, uint64(21_000), f.zapTotal())
}

func TestClearIndex_RefusedWhileEnabled(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	_, err := f.store.ClearIndex(IndexZaps)
	assert.ErrorIs(t, err, ErrIndexEnabled)
}

func TestClearIndex_EmptiesADisabledIndex(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.reopen(noIndexes)

	for _, name := range []string{IndexZaps, IndexSocial} {
		res, err := f.store.ClearIndex(name)
		require.NoError(t, err)
		assert.NotZero(t, res.EntriesBefore, name)
		st := f.status(name)
		assert.False(t, st.HasData, name)
		assert.Zero(t, st.Entries, name)
		assert.Equal(t, ActionReap, st.Action, name)
		_, err = f.store.ClearIndex(name)
		assert.ErrorIs(t, err, ErrNothingToDo, "%s: already empty", name)
		_, err = f.store.ReapIndex(context.Background(), name, nil)
		require.NoError(t, err)
	}
	assert.Equal(t, []string{string(zapMeta), string(socialMeta)}, f.derivedBuckets(), "only the meta buckets remain")
}

func TestClearIndex_ThenEnablingRebuilds(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()
	f.reopen(noIndexes)
	_, err := f.store.ClearIndex(IndexZaps)
	require.NoError(t, err)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 3_000))

	f.reopen(bothIndexes)
	f.waitCurrent()
	assert.Equal(t, uint64(24_000), f.zapTotal(), "rebuilt from every stored zap")
}

func TestDerivedIndexes_BusyRefusesASecondOperation(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.reopen(noIndexes)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 1))
	f.reopen(bothIndexes)

	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := f.store.RebuildIndex(context.Background(), IndexZaps, func(IndexProgress) {
			select {
			case <-started:
			default:
				close(started)
				<-release
			}
		})
		done <- err
	}()
	<-started
	assert.Equal(t, ActionRebuild, f.status(IndexZaps).Running)
	_, err := f.store.CatchUpIndex(context.Background(), IndexZaps, nil)
	assert.ErrorIs(t, err, ErrIndexBusy)
	close(release)
	require.NoError(t, <-done)
	assert.Equal(t, StateReady, f.status(IndexZaps).State, "the rebuild covers what the catch-up would")
}

func TestDerivedIndexes_LegacyIndexIsRebuilt(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	// As an older version left it: markers, no state.
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error {
		for _, m := range [][]byte{zapMeta, socialMeta} {
			for _, k := range [][]byte{keyState, keyManifest, keyKinds} {
				if err := tx.Bucket(m).Delete(k); err != nil {
					return err
				}
			}
		}
		return tx.Bucket(storeMeta).Delete(seqKey)
	}))
	f.reopen(bothIndexes)
	for _, name := range []string{IndexZaps, IndexSocial} {
		st := f.status(name)
		assert.Equal(t, ActionRebuild, st.Action, name)
		assert.Equal(t, "built by an older version", st.Reason, name)
		f.run(name)
	}
	assert.Equal(t, uint64(21_000), f.zapTotal())
}

func TestDerivedIndexes_ForeignWritesMeanRebuild(t *testing.T) {
	t.Run("insert", func(t *testing.T) {
		f := newManualIndexFixture(t, bothIndexes)
		f.insert(f.mixed()...)
		// Another program stored an event: the sequence moved past ours.
		require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error {
			return f.store.stampSeq(tx, tx.Bucket(indexEvents).Sequence()-1)
		}))
		f.reopen(bothIndexes)
		assert.Equal(t, "events changed by another program since this index was updated", f.status(IndexZaps).Reason)
	})
	t.Run("delete", func(t *testing.T) {
		f := newManualIndexFixture(t, bothIndexes)
		f.insert(f.mixed()...)
		// Another program deleted a receipt: the counters moved, our stamp didn't.
		require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error {
			return addCounter(tx.Bucket(indexCounters), kindCounterKey(itob(9735)), -1)
		}))
		f.reopen(bothIndexes)
		assert.Equal(t, ActionRebuild, f.status(IndexZaps).Action)
		assert.Equal(t, ActionRebuild, f.status(IndexSocial).Action)
	})
}

func TestDerivedIndexes_LegacyMarkersFollowState(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()
	marked := func() bool {
		var ok bool
		require.NoError(t, f.store.db.View(func(tx *bolt.Tx) error {
			ok = metaValue(tx, zapMeta, coinsKey) != nil && metaValue(tx, socialMeta, socialBuiltAt) != nil
			return nil
		}))
		return ok
	}
	assert.True(t, marked(), "live: an older version may trust it")
}

// newRescoreFixture is a verification worker over an indexed store at a
// known path, so tests can reopen it.
func newRescoreFixture(t *testing.T) (*indexFixture, *verifyFixture) {
	f := newManualIndexFixture(t, bothIndexes)
	v := newVerifyFixture(t, VerificationConfig{})
	v.store = f.store
	v.w.store = f.store
	return f, v
}

func TestSocialRescore_AfterRebuild(t *testing.T) {
	f, _ := newRescoreFixture(t)
	f.insert(f.mixed()...)
	_ = f.store.TakeSocialDirty(1000) // as if the scores were never stored

	old := rescoreBatch
	rescoreBatch = 1
	t.Cleanup(func() { rescoreBatch = old })

	_, err := f.store.RebuildIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	st := f.status(IndexSocial)
	assert.Equal(t, ActionRescore, st.Action)
	assert.Equal(t, "after a rebuild", st.Reason)
	res, err := f.store.RescoreIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), res.Scanned, "both profiles")
	for _, k := range []testKey{f.alice, f.bob} {
		want, err := f.store.ComputeSocialScore(k.pub)
		require.NoError(t, err)
		assert.Equal(t, want, mustMetrics(t, f.store, k.pub).SocialScore)
	}
	assert.NotZero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)
	assert.NotEqual(t, ActionRescore, f.status(IndexSocial).Action, "rescore finished")
}

func TestSocialRescore_ResumesAfterRestart(t *testing.T) {
	f, _ := newRescoreFixture(t)
	f.insert(f.mixed()...)
	old := rescoreBatch
	rescoreBatch = 1
	t.Cleanup(func() { rescoreBatch = old })
	_, err := f.store.RebuildIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	_, err = f.store.RescoreIndex(ctx, IndexSocial, func(IndexProgress) { cancel() })
	require.ErrorIs(t, err, context.Canceled)
	f.reopen(bothIndexes)
	res, err := f.store.RescoreIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), res.Scanned, "only the profile left")
}

func TestSocialRescore_WhenScoringChanges(t *testing.T) {
	f, _ := newRescoreFixture(t)
	f.insert(f.mixed()...)
	assert.Empty(t, f.status(IndexSocial).Action)

	prev := *config.Get()
	t.Cleanup(func() { config.Configure(func(c *config.AppConfig) { *c = prev }) })
	config.Configure(func(c *config.AppConfig) { c.Search.Social.FollowersWeight *= 2 })
	f.reopen(bothIndexes)
	st := f.status(IndexSocial)
	assert.Equal(t, ActionRescore, st.Action)
	assert.Equal(t, "the scoring settings changed", st.Reason)
	f.run(IndexSocial)

	f.reopen(bothIndexes)
	assert.Empty(t, f.status(IndexSocial).Action, "same settings: nothing to do")
}

func TestSocialRescore_DropsStaleScoreToZero(t *testing.T) {
	f, v := newRescoreFixture(t)
	f.insert(f.note(f.alice, 0), f.contacts(f.bob, 10, f.alice.pub))
	v.w.refreshSocial()
	require.NotZero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)

	f.reopen(noIndexes)
	f.insert(f.contacts(f.bob, 20)) // bob unfollows alice while disabled
	f.reopen(bothIndexes)
	v.store, v.w.store = f.store, f.store
	f.run(IndexSocial)
	v.w.refreshSocial()
	assert.Zero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)
}

func TestSocialRescore_ClearDropsIt(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	_, err := f.store.RebuildIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	f.reopen(noIndexes)
	_, err = f.store.ClearIndex(IndexSocial)
	require.NoError(t, err)
	f.reopen(bothIndexes)
	assert.Equal(t, ActionRebuild, f.status(IndexSocial).Action, "rebuilt, then rescored")
}

func TestSocialRescore_NothingWhenSocialOff(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	v := newVerifyFixture(t, VerificationConfig{})
	v.store, v.w.store = f.store, f.store
	f.insert(f.mixed()...)
	v.w.refreshSocial()
	assert.Zero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)
	assert.Empty(t, f.derivedBuckets())
}

func TestSocialDirty_SurvivesARestart(t *testing.T) {
	f := newManualIndexFixture(t, bothIndexes)
	f.insert(f.contacts(f.bob, 10, f.alice.pub))
	f.reopen(bothIndexes)
	got := f.store.TakeSocialDirty(10)
	sort.Strings(got)
	want := []string{f.alice.pub, f.bob.pub}
	sort.Strings(want)
	assert.Equal(t, want, got)
	assert.Empty(t, f.store.TakeSocialDirty(10))
}

func TestDerivedIndexes_AutoMaintenance(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.reopen(noIndexes)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 1_000))
	f.reopen(bothIndexes)
	f.waitCurrent()
	assert.Equal(t, uint64(22_000), f.zapTotal())
}

func TestPeekKind(t *testing.T) {
	ev := &nip01.Event{Kind: 9735, Content: `a "kind":1 in the content`, Tags: [][]string{{"p", `"kind":3`}}}
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	k, ok := peekKind(raw)
	assert.True(t, ok)
	assert.Equal(t, 9735, k)
	_, ok = peekKind([]byte(`{}`))
	assert.False(t, ok)
	assert.True(t, bytes.Contains(raw, []byte(`\"kind\":1`)))
}

func mustMetrics(t *testing.T, s *EventStore, pk string) *ProfileMetrics {
	m, err := s.GetProfileMetrics(pk)
	require.NoError(t, err)
	return m
}

func TestSessionFeaturesWithoutIndex(t *testing.T) {
	var buf bytes.Buffer
	store := newStore(t)
	NewSessionHandler(store, &nip11.Metadata{}, &MockSearchService{}, WithLogger(zerolog.New(&buf)), WithSessionZaps(ZapRankingConfig{Enabled: true}))
	assert.Contains(t, buf.String(), "zap index is not")
	assert.Contains(t, buf.String(), "social index is not")

	f := &rankingFixture{t: t, store: store, sender: newTestKey(t, 1), provider: newTestKey(t, 2), now: uint64(time.Now().Unix())}
	f.zap(pubkeyN(1), CoinSats, 21, time.Hour)
	r := f.ask(f.session(ZapRankingConfig{Enabled: true}), `["zap-ranking"]`)
	assert.Nil(t, r.event)
	assert.Equal(t, "restricted: zap ranking is not enabled on this relay", r.closed)

	sess := newGroupsEnabledTestSession(t)
	sess.config.EnableProfileStats = true
	evs, closed := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: map[string][]string{"d": {f.sender.pub}}})
	assert.Empty(t, evs, "answered like a relay without stats")
	assert.Empty(t, closed)
}
