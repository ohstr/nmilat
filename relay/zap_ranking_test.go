package relay

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseZapWindows(t *testing.T) {
	ws, err := ParseZapWindows([]string{"24h", "7d", "1mo", "all", "90m"})
	require.NoError(t, err)
	assert.Equal(t, []ZapWindow{{"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}, {"1mo", 30 * 24 * time.Hour}, {"all", 0}, {"90m", 90 * time.Minute}}, ws)
	for _, bad := range [][]string{nil, {}, {"24h", "1d"}, {"all", "ALL"}, {"3x"}, {""}, {"-1h"}} {
		_, err := ParseZapWindows(bad)
		assert.Error(t, err, "%q", bad)
	}
	cs, err := ParseCoins([]string{"loki", "sats"})
	require.NoError(t, err)
	assert.Equal(t, []Coin{CoinLoki, CoinSats}, cs)
	for _, bad := range [][]string{nil, {"sats", "SATS"}, {"btc"}} {
		_, err := ParseCoins(bad)
		assert.Error(t, err, "%q", bad)
	}
}

func cachePasses(s *EventStore) int {
	s.zapRank.mu.Lock()
	defer s.zapRank.mu.Unlock()
	return s.zapRank.passes
}

func TestZapRankingCache_SingleFlight(t *testing.T) {
	f := newRankingFixture(t)
	f.zap(pubkeyN(1), CoinSats, 1, time.Hour)
	cfg := ZapRankingConfig{Enabled: true, Windows: fourWindows}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := cfg.Windows[i%len(cfg.Windows)]
			r, err := f.store.ZapRanking(context.Background(), cfg, w, CoinSats)
			assert.NoError(t, err)
			assert.Len(t, r.Zaps, 1)
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 1, cachePasses(f.store), "50 concurrent first requests share one pass")
}

func TestZapRankingCache_StaleWhileRevalidate(t *testing.T) {
	f := newRankingFixture(t)
	a, b := pubkeyN(1), pubkeyN(2)
	f.zap(a, CoinSats, 1, time.Hour)
	cfg := ZapRankingConfig{Enabled: true, Refresh: 50 * time.Millisecond}
	get := func() ZapRanking {
		r, err := f.store.ZapRanking(context.Background(), cfg, DefaultZapWindows[0], CoinSats)
		require.NoError(t, err)
		return r
	}
	first := get()
	require.Len(t, first.Zaps, 1)

	// Expired with no writes: no new pass, just a fresh timestamp.
	time.Sleep(60 * time.Millisecond)
	again := get()
	assert.Equal(t, 1, cachePasses(f.store))
	assert.True(t, again.ComputedAt.After(first.ComputedAt))

	// Expired after a write: the stale list is served and one refresh runs.
	f.zap(b, CoinSats, 2, time.Hour)
	time.Sleep(60 * time.Millisecond)
	stale := get()
	assert.Len(t, stale.Zaps, 1, "served stale while refreshing")
	require.Eventually(t, func() bool { return len(get().Zaps) == 2 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, 2, cachePasses(f.store))
}

func TestZapRankingCache_DroppedWhenIdle(t *testing.T) {
	f := newRankingFixture(t)
	f.zap(pubkeyN(1), CoinSats, 1, time.Hour)
	cfg := ZapRankingConfig{Enabled: true, Refresh: 10 * time.Millisecond}
	_, err := f.store.ZapRanking(context.Background(), cfg, DefaultZapWindows[0], CoinSats)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		f.store.zapRank.mu.Lock()
		defer f.store.zapRank.mu.Unlock()
		return f.store.zapRank.lists == nil
	}, 5*time.Second, 10*time.Millisecond, "idle for 10× refresh drops the lists")
	_, err = f.store.ZapRanking(context.Background(), cfg, DefaultZapWindows[0], CoinSats)
	require.NoError(t, err)
	assert.Equal(t, 2, cachePasses(f.store), "the next request recomputes")
}

func TestZapRankingCache_OnePassMatchesPerWindowQueries(t *testing.T) {
	f := newRankingFixture(t)
	rng := rand.New(rand.NewSource(7))
	receivers := []string{pubkeyN(1), pubkeyN(2), pubkeyN(3), pubkeyN(4), pubkeyN(5), f.sender.pub}
	var events []*nip01.Event
	for i := 0; i < 300; i++ {
		ago := time.Duration(rng.Int63n(int64(60 * 24 * time.Hour)))
		coin := Coins()[rng.Intn(2)]
		z := zapSpec{Sender: f.sender, Provider: f.provider, Recipient: receivers[rng.Intn(len(receivers))],
			Amount: (rng.Int63n(5000) + 1) * 1000, CreatedAt: f.now - uint64(ago.Seconds())}
		if coin == CoinLoki {
			z.Kind = 9521
		}
		if rng.Intn(10) == 0 {
			// Duplicate payments, sometimes straddling a window edge.
			z.Preimage = fmt.Sprintf("%064x", rng.Intn(5))
		}
		events = append(events, zapReceipt(t, z))
	}
	InsertTestEvents(t, f.store, events)

	cfg := ZapRankingConfig{Windows: mustWindows("1h", "24h", "7d", "30d", "all"), MaxLimit: 4}.withDefaults()
	now := time.Unix(int64(f.now), 0)
	lists, totals, err := f.store.rankZaps(cfg, true, now)
	require.NoError(t, err)
	for _, w := range cfg.Windows {
		since := uint64(0)
		if w.D > 0 {
			since = uint64(now.Add(-w.D).Unix())
		}
		for _, coin := range cfg.Coins {
			want, err := f.store.TopZapped(context.Background(), since, f.now, coin, cfg.MaxLimit)
			require.NoError(t, err)
			assert.Equal(t, want, nilIfEmpty(lists[rankKey{w.D, coin}]), "%s %s", w.Label, coin)
		}
	}
	for _, coin := range cfg.Coins {
		all, err := f.store.TopZapped(context.Background(), 0, f.now, coin, 1000)
		require.NoError(t, err)
		var sum uint64
		for _, z := range all {
			sum += z.Total
		}
		assert.Equal(t, sum, totals[coin], "all-time %s total", coin)
	}
}

func nilIfEmpty(z []RankedZap) []RankedZap {
	if len(z) == 0 {
		return []RankedZap{}
	}
	return z
}

func TestZapTotals(t *testing.T) {
	f := newRankingFixture(t)
	f.zap(pubkeyN(1), CoinSats, 5, time.Hour)
	f.zap(pubkeyN(2), CoinSats, 6, 400*24*time.Hour)
	f.zap(pubkeyN(1), CoinLoki, 7, time.Hour)
	// Windows that don't reach back still give all-time totals.
	totals, err := f.store.ZapTotals(context.Background(), ZapRankingConfig{Enabled: true})
	require.NoError(t, err)
	assert.Equal(t, map[Coin]uint64{CoinSats: 11_000, CoinLoki: 7_000}, totals)
}

func BenchmarkZapRanking(b *testing.B) {
	store := newStore(b)
	sender, provider := newTestKey(b, 1), newTestKey(b, 2)
	now := uint64(time.Now().Unix())
	var events []*nip01.Event
	for i := 0; i < 5000; i++ {
		z := zapSpec{Sender: sender, Provider: provider, Recipient: newTestKey(b, 100+i%300).pub,
			Amount: int64(1000 + i), CreatedAt: now - uint64(i*600)}
		if i%2 == 0 {
			z.Kind = 9521
		}
		events = append(events, zapReceipt(b, z))
	}
	InsertTestEvents(b, store, events)
	cfg := ZapRankingConfig{Enabled: true, Windows: fourWindows}.withDefaults()

	b.Run("cold", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := store.rankZaps(cfg, false, time.Now()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm", func(b *testing.B) {
		b.ReportAllocs()
		ctx := context.Background()
		if _, err := store.ZapRanking(ctx, cfg, cfg.Windows[1], CoinSats); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := store.ZapRanking(ctx, cfg, cfg.Windows[1], CoinSats); err != nil {
				b.Fatal(err)
			}
		}
	})
}
