package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bob gets 21 sats and 980 loki from alice and sends 3 sats back.
func coinStatsFixture(t *testing.T) (*socialFixture, testKey, testKey) {
	f := newSocialFixture(t)
	alice, bob := f.bob, f.alice // f.bob sends in the fixture's naming
	f.insert(
		f.zap(alice.pub, bob.pub, 21_000),
		f.zap(alice.pub, bob.pub, 980_000, func(z *zapSpec) { z.Kind = nipAZ.KindAltZapReceipt }),
		f.zap(bob.pub, alice.pub, 3_000),
	)
	return f, alice, bob
}

func TestProfileStats_AmountsPerCoin(t *testing.T) {
	f, alice, bob := coinStatsFixture(t)
	st := f.stats(bob.pub)
	assert.Equal(t, 2, st.ZapCntRecd, "counts cover every coin")
	assert.Equal(t, 1, st.ZappersRecd)
	assert.Equal(t, uint64(21_000), st.ZapAmtRecd, "zap_amt_recd is sats")
	assert.Equal(t, uint64(980_000), st.AmtRecd[CoinLoki])
	assert.Equal(t, map[string]uint64{alice.pub: 21_000}, st.RecdBySender, "the score sees sats only")
	assert.Equal(t, uint64(3_000), st.ZapAmtSent)
	assert.Zero(t, st.AmtSent[CoinLoki])

	var j map[string]any
	b, err := json.Marshal(st)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &j))
	assert.EqualValues(t, 21_000, j["zap_amt_recd"])
	assert.EqualValues(t, 980_000, j["zap_amt_recd_loki"])
	assert.NotContains(t, j, "zap_amt_sent_loki")

	var a map[string]any
	b, err = json.Marshal(f.stats(alice.pub))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &a))
	assert.EqualValues(t, 980_000, a["zap_amt_sent_loki"])
	assert.NotContains(t, a, "zap_amt_recd_loki", "no key for a coin without an amount")
}

func TestProfileStats_UnknownCoinCountedNotSummed(t *testing.T) {
	f := newSocialFixture(t)
	f.insert(f.zap(f.bob.pub, f.alice.pub, 5_000, func(z *zapSpec) { z.Currency = "xx" }))
	st := f.stats(f.alice.pub)
	assert.Equal(t, 1, st.ZapCntRecd, "a valid zap in an unknown coin still counts")
	assert.Zero(t, st.ZapAmtRecd)
	assert.Equal(t, uint64(5_000), st.AmtRecd[CoinUnknown])
	assert.Empty(t, st.RecdBySender)
}

func TestAssertions_PerCoinTags(t *testing.T) {
	sess := newAssertionsSession(t)
	f := &socialFixture{t: t, store: sess.store, alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12), at: 1_700_000_000}
	alice, bob := f.bob, f.alice
	f.insert(
		f.zap(alice.pub, bob.pub, 21_000),
		f.zap(alice.pub, bob.pub, 980_000, func(z *zapSpec) { z.Kind = nipAZ.KindAltZapReceipt }),
		f.zap(bob.pub, alice.pub, 3_000),
	)

	events, closed := assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(bob.pub)})
	require.Empty(t, closed)
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, "2", tagValue(ev, "zap_cnt_recd"))
	assert.Equal(t, "21", tagValue(ev, "zap_amt_recd"))
	assert.Equal(t, "980", tagValue(ev, "zap_amt_recd_loki"))
	assert.Equal(t, "3", tagValue(ev, "zap_amt_sent"))
	assert.Equal(t, "", tagValue(ev, "zap_amt_sent_loki"), "only coins with an amount")

	// A relay that doesn't list loki publishes only the sats tags.
	sess.config.Zaps.Coins = []Coin{CoinSats}
	events, _ = assertionsReq(t, sess, &nip01.SubscriptionFilter{Tags: dTags(bob.pub)})
	require.Len(t, events, 1)
	assert.Equal(t, "", tagValue(events[0], "zap_amt_recd_loki"))
	assert.Equal(t, "21", tagValue(events[0], "zap_amt_recd"))
}

func TestSocialScore_IgnoresOtherCoins(t *testing.T) {
	f, _, bob := coinStatsFixture(t)
	withLoki := f.store.SocialScore(f.stats(bob.pub))

	g := newSocialFixture(t)
	g.insert(g.zap(g.bob.pub, g.alice.pub, 21_000))
	satsOnly := g.store.SocialScore(g.stats(g.alice.pub))
	assert.Equal(t, satsOnly, withLoki, "980 loki adds nothing to a sats score")
}

func TestProfileStats_NoAllocationPerCoin(t *testing.T) {
	f, _, bob := coinStatsFixture(t)
	base := testing.AllocsPerRun(20, func() { _, _ = f.store.GetProfileStats(f.alice.pub) })
	withCoins := testing.AllocsPerRun(20, func() { _, _ = f.store.GetProfileStats(bob.pub) })
	// bob has one more zap than alice; per-coin amounts are an array, so
	// the difference is the zap itself, not a map per coin.
	assert.Less(t, withCoins-base, 40.0)
}
