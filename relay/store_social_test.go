package relay

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

type socialFixture struct {
	t        *testing.T
	store    *EventStore
	alice    testKey // receives zaps
	bob      testKey // sends zaps
	provider testKey // alice's LNURL server
	at       uint64
}

func newSocialFixture(t *testing.T) *socialFixture {
	return &socialFixture{
		t: t, store: newIndexedStore(t),
		alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12),
		at: 1_700_000_000,
	}
}

func (f *socialFixture) zap(sender, recipient string, amount int64, opts ...func(*zapSpec)) *nip01.Event {
	f.at++
	z := zapSpec{Sender: f.key(sender), Provider: f.provider, Recipient: recipient, Amount: amount, CreatedAt: f.at}
	for _, o := range opts {
		o(&z)
	}
	return zapReceipt(f.t, z)
}

func (f *socialFixture) key(pub string) testKey {
	for _, k := range []testKey{f.alice, f.bob, f.provider} {
		if k.pub == pub {
			return k
		}
	}
	f.t.Fatalf("unknown key %s", pub)
	return testKey{}
}

func (f *socialFixture) insert(events ...*nip01.Event) {
	InsertTestEvents(f.t, f.store, events)
}

func (f *socialFixture) stats(pk string) *ProfileStats {
	st, err := f.store.GetProfileStats(pk)
	require.NoError(f.t, err)
	return st
}

// verifyLNURL records pk's verified LNURL server key.
func (f *socialFixture) verifyLNURL(pk, serverKey string) {
	require.NoError(f.t, f.store.UpdateProfileMetrics(pk, func(m *ProfileMetrics) {
		m.Lud16 = CheckState{Value: "x@example.com", Status: CheckOK}
		m.Lud16NostrPubkey = serverKey
	}))
}

func (f *socialFixture) contacts(author testKey, createdAt uint64, follows ...string) *nip01.Event {
	ev := &nip01.Event{PubKey: author.pub, CreatedAt: createdAt, Kind: 3}
	for _, p := range follows {
		ev.Tags = append(ev.Tags, []string{"p", p})
	}
	require.NoError(f.t, ev.Sign(author.priv))
	return ev
}

func (f *socialFixture) deletion(author testKey, ids ...string) *nip01.Event {
	f.at++
	ev := &nip01.Event{PubKey: author.pub, CreatedAt: f.at, Kind: 5}
	for _, id := range ids {
		ev.Tags = append(ev.Tags, []string{"e", id})
	}
	require.NoError(f.t, ev.Sign(author.priv))
	return ev
}

func TestProfileStats_CountsZapsBothWays(t *testing.T) {
	f := newSocialFixture(t)
	first := f.zap(f.bob.pub, f.alice.pub, 21_000)
	second := f.zap(f.bob.pub, f.alice.pub, 1_000)
	f.insert(first, second, f.zap(f.alice.pub, f.bob.pub, 5_000))

	a := f.stats(f.alice.pub)
	assert.Equal(t, 2, a.ZapCntRecd)
	assert.Equal(t, uint64(22_000), a.ZapAmtRecd)
	assert.Equal(t, 1, a.ZappersRecd)
	assert.Equal(t, int64(first.CreatedAt), a.ZapFirstRecd)
	assert.Equal(t, int64(second.CreatedAt), a.ZapLastRecd)
	assert.Equal(t, 1, a.ZapCntSent)
	assert.Equal(t, uint64(5_000), a.ZapAmtSent)

	b := f.stats(f.bob.pub)
	assert.Equal(t, 2, b.ZapCntSent)
	assert.Equal(t, uint64(22_000), b.ZapAmtSent)
	assert.Equal(t, int64(first.CreatedAt), b.ZapFirstSent)
}

func TestProfileStats_ExcludesSelfZapsDuplicatesAndInvalid(t *testing.T) {
	f := newSocialFixture(t)
	samePayment := func(z *zapSpec) { z.Preimage = strings.Repeat("ab", 32) }
	paid := f.zap(f.bob.pub, f.alice.pub, 1_000, samePayment)
	again := f.zap(f.bob.pub, f.alice.pub, 1_000, samePayment)

	f.insert(paid, again, f.zap(f.alice.pub, f.alice.pub, 50_000))
	// An unsigned look-alike never validates.
	putRawEvents(t, f.store, 1000, &nip01.Event{Kind: 9735, CreatedAt: 5, Tags: [][]string{{"p", f.alice.pub}, {"amount", "99000"}}})
	_, err := f.store.RebuildIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)

	a := f.stats(f.alice.pub)
	assert.Equal(t, 1, a.ZapCntRecd, "self-zap, duplicate payment and invalid receipt don't count")
	assert.Equal(t, uint64(1_000), a.ZapAmtRecd)
	assert.Equal(t, 0, a.ZapCntSent)
}

func TestProfileStats_RequiresTheRecipientsLNURLServer(t *testing.T) {
	f := newSocialFixture(t)
	other := newTestKey(t, 99)
	f.insert(
		f.zap(f.bob.pub, f.alice.pub, 1_000),
		f.zap(f.bob.pub, f.alice.pub, 2_000, func(z *zapSpec) { z.Provider = other }),
	)
	assert.Equal(t, 2, f.stats(f.alice.pub).ZapCntRecd, "with no known LNURL key, valid receipts count")

	f.verifyLNURL(f.alice.pub, f.provider.pub)
	a := f.stats(f.alice.pub)
	assert.Equal(t, 1, a.ZapCntRecd, "only alice's own LNURL server is believed")
	assert.Equal(t, uint64(1_000), a.ZapAmtRecd)
	assert.Equal(t, 1, f.stats(f.bob.pub).ZapCntSent)

	top, err := f.store.TopZapped(context.Background(), 0, f.at+1, CoinSats, 10)
	require.NoError(t, err)
	require.Len(t, top, 1)
	assert.Equal(t, uint64(1_000), top[0].Total, "the zap ranking applies the same rules")
}

func TestProfileStats_DeletedZapIsRemoved(t *testing.T) {
	f := newSocialFixture(t)
	z := f.zap(f.bob.pub, f.alice.pub, 1_000)
	f.insert(z)
	require.Equal(t, 1, f.stats(f.alice.pub).ZapCntRecd)

	f.insert(f.deletion(f.provider, z.ID))
	assert.Equal(t, 0, f.stats(f.alice.pub).ZapCntRecd)
	assert.Equal(t, 0, f.stats(f.bob.pub).ZapCntSent)
	top, err := f.store.TopZapped(context.Background(), 0, f.at+1, CoinSats, 10)
	require.NoError(t, err)
	assert.Empty(t, top)
}

func TestProfileStats_Follows(t *testing.T) {
	f := newSocialFixture(t)
	carol, dave := newTestKey(t, 20).pub, newTestKey(t, 21).pub

	f.insert(f.contacts(f.alice, 100, f.bob.pub, carol, carol, f.alice.pub, "not-a-key"))
	assert.Equal(t, int64(2), f.stats(f.alice.pub).Following, "duplicates, self and junk are ignored")
	assert.Equal(t, int64(1), f.stats(f.bob.pub).Followers)
	assert.Equal(t, int64(1), f.stats(carol).Followers)

	f.insert(f.contacts(f.bob, 100, carol))
	assert.Equal(t, int64(2), f.stats(carol).Followers)

	// A newer list replaces the old one.
	f.insert(f.contacts(f.alice, 200, carol, dave))
	assert.Equal(t, int64(0), f.stats(f.bob.pub).Followers)
	assert.Equal(t, int64(2), f.stats(carol).Followers)
	assert.Equal(t, int64(1), f.stats(dave).Followers)

	// An older list changes nothing.
	f.insert(f.contacts(f.alice, 150, f.bob.pub))
	assert.Equal(t, int64(0), f.stats(f.bob.pub).Followers)

	latest := f.contacts(f.alice, 300, dave)
	f.insert(latest)
	f.insert(f.deletion(f.alice, latest.ID))
	assert.Equal(t, int64(0), f.stats(dave).Followers)
	assert.Equal(t, int64(0), f.stats(f.alice.pub).Following)
	assert.Equal(t, int64(1), f.stats(carol).Followers, "bob still follows carol")
}

func TestRebuildSocialIndex_MatchesIncremental(t *testing.T) {
	f := newSocialFixture(t)
	carol := newTestKey(t, 20).pub
	f.insert(
		f.zap(f.bob.pub, f.alice.pub, 1_000),
		f.zap(f.alice.pub, f.bob.pub, 2_000),
		f.contacts(f.alice, 100, f.bob.pub, carol),
		f.contacts(f.bob, 100, carol),
	)
	before := map[string]*ProfileStats{}
	for _, pk := range []string{f.alice.pub, f.bob.pub, carol} {
		before[pk] = f.stats(pk)
	}

	res, err := f.store.RebuildIndex(context.Background(), IndexSocial, nil)
	require.NoError(t, err)
	for pk, want := range before {
		assert.Equal(t, want, f.stats(pk), pk)
	}
	assert.Equal(t, res.EntriesBefore, res.EntriesAfter)
	st, err := f.store.IndexStatus(IndexSocial)
	require.NoError(t, err)
	assert.NotZero(t, st.BuiltAt)
}

func TestSocialIndex_BackfillsOnOpen(t *testing.T) {
	store, path := newStoreAtPath(t, allIndexes)
	f := &socialFixture{t: t, store: store, alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12), at: 1_700_000_000}
	putRawEvents(t, store, 1, f.zap(f.bob.pub, f.alice.pub, 1_000), f.contacts(f.bob, 100, f.alice.pub))
	require.NoError(t, store.db.Update(func(tx *bolt.Tx) error {
		return store.markDirty(tx, store.social, "test")
	}))
	store.Close()

	reopened, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)), allIndexes)
	require.NoError(t, err)
	t.Cleanup(reopened.Close)
	require.Eventually(t, func() bool {
		st, err := reopened.IndexStatus(IndexSocial)
		return err == nil && st.State == StateReady && st.Running == "" && st.Action != ActionRebuild
	}, 5*time.Second, 10*time.Millisecond)

	st, err := reopened.GetProfileStats(f.alice.pub)
	require.NoError(t, err)
	assert.Equal(t, 1, st.ZapCntRecd)
	assert.Equal(t, int64(1), st.Followers)
}

func TestSocialIndex_ReplacedContactsInOneBatch(t *testing.T) {
	f := newSocialFixture(t)
	f.insert(f.contacts(f.bob, 100, f.alice.pub), f.contacts(f.bob, 200, f.alice.pub, f.provider.pub))
	assert.Equal(t, int64(1), f.stats(f.alice.pub).Followers)
	assert.Equal(t, int64(1), f.stats(f.provider.pub).Followers)
}
