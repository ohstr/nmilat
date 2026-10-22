package relay

import (
	"bytes"
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

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
	path string
}

func newIndexFixture(t *testing.T, ix DerivedIndexes) *indexFixture {
	f := &indexFixture{
		socialFixture: &socialFixture{t: t, alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12), at: 1_700_000_000},
		path:          filepath.Join(t.TempDir(), "derived.db"),
	}
	f.reopen(ix)
	return f
}

// reopen closes the store and opens the same file with ix.
func (f *indexFixture) reopen(ix DerivedIndexes) {
	if f.store != nil {
		f.store.Close()
	}
	store, err := NewEventStore(f.path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(f.t)), WithEventStoreIndexes(ix))
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

func (f *indexFixture) waitCurrent() {
	require.Eventually(f.t, func() bool {
		z, s := f.store.ZapIndexState(), f.store.SocialIndexState()
		return z.Current == z.Enabled && s.Current == s.Enabled && !z.Rebuilding && !s.Rebuilding
	}, 5*time.Second, 10*time.Millisecond)
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
		assert.Equal(t, ix.Zaps, f.store.ZapIndexState().HasData, "%+v", ix)
		assert.Equal(t, ix.Social, f.store.SocialIndexState().HasData, "%+v", ix)
	}
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

func TestDerivedIndexes_IndexZapDoesNothingWhenOff(t *testing.T) {
	f := newIndexFixture(t, noIndexes)
	zap := f.zap(f.bob.pub, f.alice.pub, 1_000)
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error { return f.store.IndexZap(tx, zap, 1) }))
	assert.Empty(t, f.derivedBuckets())
}

func TestDerivedIndexes_ReadersAndRebuildsRefusedWhenOff(t *testing.T) {
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
	assert.Zero(t, f.store.CountSocialProfiles())

	_, err = f.store.RebuildZapIndex(ctx, nil)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.ReindexZaps(ctx, nil)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	_, err = f.store.RebuildSocialIndex(ctx, nil)
	assert.ErrorIs(t, err, ErrIndexDisabled)
	assert.Empty(t, f.store.TakeSocialRescore(10))

	assert.Empty(t, f.derivedBuckets())
}

func TestDerivedIndexes_IngestMatchesRebuild(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	zaps, social := activeSnapshot(t, f.store, f.store.zaps), activeSnapshot(t, f.store, f.store.social)
	require.NotEmpty(t, zaps)
	require.NotEmpty(t, social)

	_, err := f.store.RebuildZapIndex(context.Background(), nil)
	require.NoError(t, err)
	_, err = f.store.RebuildSocialIndex(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, zaps, activeSnapshot(t, f.store, f.store.zaps))
	assert.Equal(t, social, activeSnapshot(t, f.store, f.store.social))
}

func TestDerivedIndexes_ReadOnlyOpenKeepsMarkers(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()

	f.reopen(noIndexes)
	_, err := f.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{9735}})
	require.NoError(t, err)
	f.insert(f.note(f.alice, 1)) // a write neither index cares about
	assert.True(t, f.store.ZapIndexState().Current)
	assert.True(t, f.store.SocialIndexState().Current)

	f.reopen(bothIndexes)
	assert.True(t, f.store.ZapIndexState().Current, "nothing to rebuild")
	assert.True(t, f.store.SocialIndexState().Current)
	assert.False(t, f.store.ZapIndexRebuilding())
	assert.False(t, f.store.SocialIndexRebuilding())
}

func TestDerivedIndexes_FirstSkippedWriteUnmarks(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()
	f.reopen(noIndexes)

	f.insert(f.contacts(f.alice, f.at+1, f.bob.pub))
	assert.False(t, f.store.SocialIndexState().Current, "a skipped kind 3 makes the social index stale")
	assert.True(t, f.store.ZapIndexState().Current, "the zap index missed nothing")

	before := f.store.ZapIndexState()
	f.insert(f.zap(f.alice.pub, f.bob.pub, 5_000))
	after := f.store.ZapIndexState()
	assert.Equal(t, IndexState{Enabled: false, Current: false, HasData: true, Entries: before.Entries}, after, "data kept, unchanged, no longer current")
}

func TestDerivedIndexes_EnablingRebuilds(t *testing.T) {
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

func TestDerivedIndexes_ReenablingRebuildsFromEvents(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	old := f.zap(f.bob.pub, f.alice.pub, 1_000)
	f.insert(old)
	f.waitCurrent()

	f.reopen(noIndexes)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 4_000), f.deletion(f.provider, old.ID))

	f.reopen(bothIndexes)
	f.waitCurrent()
	assert.Equal(t, uint64(4_000), f.zapTotal(), "the zap deleted while disabled is gone")
}

func TestDerivedIndexes_StaleBuildingDroppedOnOpen(t *testing.T) {
	for _, ix := range []DerivedIndexes{bothIndexes, noIndexes} {
		f := newIndexFixture(t, bothIndexes)
		f.insert(f.zap(f.bob.pub, f.alice.pub, 1_000))
		f.waitCurrent()
		orphan := append([]byte{9, 'g'}, itob(99)...)
		require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error {
			if _, err := tx.CreateBucket(orphan); err != nil {
				return err
			}
			return tx.Bucket(zapMeta).Put(zapBuildingKey, orphan)
		}))

		f.reopen(ix)
		f.insert(f.zap(f.bob.pub, f.alice.pub, 2_000))
		require.NoError(t, f.store.db.View(func(tx *bolt.Tx) error {
			assert.Nil(t, tx.Bucket(orphan), "%+v", ix)
			assert.Nil(t, f.store.zaps.building(tx), "%+v", ix)
			return nil
		}))
	}
}

func TestDerivedIndexes_EmptyStoreMarksOnlyEnabled(t *testing.T) {
	f := newIndexFixture(t, DerivedIndexes{Zaps: true})
	assert.True(t, f.store.ZapIndexState().Current)
	assert.False(t, f.store.SocialIndexState().Current)
	assert.Equal(t, []string{string(zapMeta)}, f.derivedBuckets())
}

func TestClearIndex_RemovesDataAndMarker(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()

	require.NoError(t, f.store.ClearZapIndex(context.Background()))
	require.NoError(t, f.store.ClearSocialIndex(context.Background()))
	assert.Equal(t, IndexState{Enabled: true}, f.store.ZapIndexState())
	assert.Equal(t, IndexState{Enabled: true}, f.store.SocialIndexState())

	f.insert(f.zap(f.bob.pub, f.alice.pub, 3_000))
	st := f.store.ZapIndexState()
	assert.True(t, st.HasData)
	assert.False(t, st.Current, "a cleared index is stale until rebuilt")

	f.reopen(bothIndexes)
	f.waitCurrent()
	assert.Equal(t, uint64(24_000), f.zapTotal(), "rebuilt from every stored zap")
}

func TestClearIndex_WorksWhileDisabled(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()
	f.reopen(noIndexes)

	require.NoError(t, f.store.ClearZapIndex(context.Background()))
	require.NoError(t, f.store.ClearSocialIndex(context.Background()))
	assert.Equal(t, IndexState{}, f.store.ZapIndexState())
	assert.Equal(t, IndexState{}, f.store.SocialIndexState())
	assert.Equal(t, []string{string(zapMeta), string(socialMeta)}, f.derivedBuckets(), "only the meta buckets remain")
}

func TestClearIndex_RefusedDuringRebuild(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	f.waitCurrent()

	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := f.store.RebuildZapIndex(context.Background(), func(int, int) {
			close(started)
			<-release
		})
		done <- err
	}()
	<-started
	assert.ErrorIs(t, f.store.ClearZapIndex(context.Background()), ErrZapRebuildInProgress)
	_, err := f.store.ReindexZaps(context.Background(), nil)
	assert.ErrorIs(t, err, ErrZapRebuildInProgress)
	close(release)
	require.NoError(t, <-done)
	assert.True(t, f.store.ZapIndexState().Current)
	assert.Equal(t, uint64(21_000), f.zapTotal())
}

// newRescoreFixture is a verification worker over an indexed store at a
// known path, so tests can reopen it.
func newRescoreFixture(t *testing.T) (*indexFixture, *verifyFixture) {
	f := newIndexFixture(t, bothIndexes)
	v := newVerifyFixture(t, VerificationConfig{})
	v.store = f.store
	v.w.store = f.store
	return f, v
}

func TestSocialRescore_AfterRebuild(t *testing.T) {
	f, v := newRescoreFixture(t)
	f.insert(f.mixed()...)
	_ = f.store.TakeSocialDirty(1000) // as if the scores were never stored

	old := maxSocialRefresh
	maxSocialRefresh = 1
	t.Cleanup(func() { maxSocialRefresh = old })

	_, err := f.store.RebuildSocialIndex(context.Background(), nil)
	require.NoError(t, err)
	for range 5 {
		v.w.refreshSocial()
	}
	for _, k := range []testKey{f.alice, f.bob} {
		want, err := f.store.ComputeSocialScore(k.pub)
		require.NoError(t, err)
		m, err := f.store.GetProfileMetrics(k.pub)
		require.NoError(t, err)
		assert.Equal(t, want, m.SocialScore)
	}
	assert.NotZero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)
	require.NoError(t, f.store.db.View(func(tx *bolt.Tx) error {
		assert.Nil(t, metaValue(tx, socialMeta, socialRescoreKey), "rescore finished")
		return nil
	}))
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
	f.waitCurrent()
	v.w.refreshSocial()
	assert.Zero(t, mustMetrics(t, f.store, f.alice.pub).SocialScore)
}

func TestSocialRescore_ClearDropsIt(t *testing.T) {
	f := newIndexFixture(t, bothIndexes)
	f.insert(f.mixed()...)
	_, err := f.store.RebuildSocialIndex(context.Background(), nil)
	require.NoError(t, err)
	require.NoError(t, f.store.ClearSocialIndex(context.Background()))
	assert.Empty(t, f.store.TakeSocialRescore(10))
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
