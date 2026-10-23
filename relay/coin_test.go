package relay

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestCoinNames(t *testing.T) {
	for _, c := range []struct {
		currency string
		want     Coin
	}{{"bc", CoinSats}, {"tb", CoinSats}, {"tbs", CoinSats}, {"bcrt", CoinSats}, {"fc", CoinLoki}, {"xx", CoinUnknown}, {"", CoinUnknown}} {
		assert.Equal(t, c.want, coinForCurrency(c.currency), c.currency)
	}
	for _, name := range []string{"sats", "loki", "SATS"} {
		c, err := ParseCoin(name)
		require.NoError(t, err)
		assert.NotEqual(t, CoinUnknown, c)
	}
	for _, name := range []string{"", "btc", "msat"} {
		_, err := ParseCoin(name)
		assert.Error(t, err, name)
	}
	assert.Equal(t, "sats", CoinSats.String())
	assert.Equal(t, "loki", CoinLoki.String())
	assert.Equal(t, "", Coin(200).String())
	assert.Equal(t, uint64(21), WholeUnits(21_999))
}

func TestParseZapFact_Coin(t *testing.T) {
	sender, provider, recipient := newTestKey(t, 1), newTestKey(t, 2), newTestKey(t, 3)
	spec := func(kind int, currency string, chain nipAZ.Chain) zapSpec {
		return zapSpec{Kind: kind, Sender: sender, Provider: provider, Recipient: recipient.pub, Amount: 21000, CreatedAt: 1_700_000_000, Currency: currency, Chain: chain}
	}
	for name, c := range map[string]struct {
		z    zapSpec
		want Coin
	}{
		"9735 bc":        {spec(0, "", ""), CoinSats},
		"9735 fc":        {spec(0, "fc", ""), CoinLoki},
		"9521 flokicoin": {spec(nipAZ.KindAltZapReceipt, "", ""), CoinLoki},
		"9521 bitcoin":   {spec(nipAZ.KindAltZapReceipt, "", "bitcoin"), CoinSats},
	} {
		f, err := parseZapFact(zapReceipt(t, c.z))
		require.NoError(t, err, name)
		assert.True(t, f.Valid, name)
		assert.Equal(t, c.want, f.Coin, name)
	}

	// Without an invoice a 9521 falls back to its chain tag, a 9735 to unknown.
	for kind, want := range map[int]Coin{0: CoinUnknown, nipAZ.KindAltZapReceipt: CoinLoki} {
		ev := zapReceipt(t, spec(kind, "", ""))
		ev.Tags = withoutTag(ev.Tags, "bolt11")
		ev.Tags = append(ev.Tags, []string{"amount", "21000"})
		f, err := parseZapFact(ev)
		require.NoError(t, err)
		assert.Equal(t, want, f.Coin, "kind %d", kind)
	}
}

func withoutTag(tags [][]string, name string) [][]string {
	var out [][]string
	for _, tag := range tags {
		if len(tag) == 0 || tag[0] != name {
			out = append(out, tag)
		}
	}
	return out
}

func TestZapEntry_CoinRoundTrip(t *testing.T) {
	e := zapEntry{Amount: 5, Other: newTestKey(t, 1).pub, Valid: true, Coin: CoinLoki}
	v := e.encode()
	require.Len(t, v, zapEntryLen+1)
	got, ok := decodeZapEntry(v)
	require.True(t, ok)
	assert.Equal(t, e, got)

	// An entry written before coins existed decodes as unknown.
	got, ok = decodeZapEntry(v[:zapEntryLen])
	require.True(t, ok)
	assert.Equal(t, CoinUnknown, got.Coin)
	assert.Equal(t, uint64(5), got.Amount)
}

func TestIndexes_RebuildOnOpenToRecordCoins(t *testing.T) {
	store, path := newStoreAtPath(t, allIndexes)
	f := &socialFixture{t: t, store: store, alice: newTestKey(t, 10), bob: newTestKey(t, 11), provider: newTestKey(t, 12), at: 1_700_000_000}
	f.insert(f.zap(f.bob.pub, f.alice.pub, 1_000), f.zap(f.bob.pub, f.alice.pub, 2_000, func(z *zapSpec) { z.Kind = nipAZ.KindAltZapReceipt }))

	// Make it look like a store from before coins: entries without the coin
	// byte and no coins flag.
	require.NoError(t, store.db.Update(func(tx *bolt.Tx) error {
		for _, gen := range [][]byte{activeZapBucket(tx)} {
			if err := truncateValues(tx.Bucket(gen), 40+zapEntryLen); err != nil {
				return err
			}
		}
		social := tx.Bucket(activeSocialBucket(tx))
		for _, sub := range [][]byte{subZapsRecd, subZapsSent} {
			if err := truncateValues(social.Bucket(sub), zapEntryLen); err != nil {
				return err
			}
		}
		// An index from before coins is one from before index states too.
		for _, m := range [][]byte{zapMeta, socialMeta} {
			for _, k := range [][]byte{coinsKey, keyState, keyManifest} {
				if err := tx.Bucket(m).Delete(k); err != nil {
					return err
				}
			}
		}
		return tx.Bucket(storeMeta).Delete(seqKey)
	}))
	assert.Equal(t, []Coin{CoinUnknown, CoinUnknown}, storedCoins(t, store))
	store.Close()

	reopened, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)), allIndexes)
	require.NoError(t, err)
	t.Cleanup(reopened.Close)
	require.Eventually(t, func() bool { return hasCoinsFlags(reopened) }, 5*time.Second, 10*time.Millisecond)
	assert.ElementsMatch(t, []Coin{CoinSats, CoinLoki}, storedCoins(t, reopened))
	require.Eventually(t, func() bool {
		z, _ := reopened.IndexStatus(IndexZaps)
		s, _ := reopened.IndexStatus(IndexSocial)
		return z.Running == "" && s.Running == ""
	}, 5*time.Second, 10*time.Millisecond)
}

func TestIndexes_EmptyStoreNeedsNoRebuild(t *testing.T) {
	store := newIndexedStore(t)
	assert.True(t, hasCoinsFlags(store))
	for _, name := range []string{IndexZaps, IndexSocial} {
		st, err := store.IndexStatus(name)
		require.NoError(t, err)
		assert.Equal(t, StateReady, st.State, name)
		assert.Empty(t, st.Action, name)
	}
}

func truncateValues(b *bolt.Bucket, n int) error {
	type kv struct{ k, v []byte }
	var all []kv
	_ = b.ForEach(func(k, v []byte) error {
		if len(v) > n {
			all = append(all, kv{append([]byte(nil), k...), append([]byte(nil), v[:n]...)})
		}
		return nil
	})
	for _, e := range all {
		if err := b.Put(e.k, e.v); err != nil {
			return err
		}
	}
	return nil
}

// storedCoins returns each zap-index entry's coin, in key order.
func storedCoins(t *testing.T, store *EventStore) []Coin {
	var coins []Coin
	require.NoError(t, store.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(activeZapBucket(tx)).ForEach(func(_, v []byte) error {
			e, ok := decodeZapEntry(v[40:])
			require.True(t, ok)
			coins = append(coins, e.Coin)
			return nil
		})
	}))
	return coins
}

func hasCoinsFlags(store *EventStore) bool {
	ok := false
	_ = store.db.View(func(tx *bolt.Tx) error {
		zm, sm := tx.Bucket(zapMeta), tx.Bucket(socialMeta)
		ok = zm != nil && sm != nil && zm.Get(coinsKey) != nil && sm.Get(coinsKey) != nil
		return nil
	})
	return ok
}
