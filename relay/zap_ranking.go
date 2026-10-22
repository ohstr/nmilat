package relay

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/utils"
	bolt "go.etcd.io/bbolt"
)

// ZapWindow is a zap-ranking time range ending now; D == 0 is all time.
type ZapWindow struct {
	Label string
	D     time.Duration
}

// ParseZapWindow reads "all" or a duration like "24h", "7d", "1mo".
func ParseZapWindow(s string) (ZapWindow, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "all") {
		return ZapWindow{Label: "all"}, nil
	}
	d, err := utils.ParseDuration(s)
	if err != nil {
		return ZapWindow{}, err
	}
	return ZapWindow{Label: s, D: d}, nil
}

// ParseZapWindows reads a window list, refusing an empty list and duplicates.
func ParseZapWindows(labels []string) ([]ZapWindow, error) {
	if len(labels) == 0 {
		return nil, fmt.Errorf("no windows")
	}
	var out []ZapWindow
	for _, l := range labels {
		w, err := ParseZapWindow(l)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(out, func(o ZapWindow) bool { return o.D == w.D }) {
			return nil, fmt.Errorf("duplicate window %q", l)
		}
		out = append(out, w)
	}
	return out, nil
}

// ParseCoins reads a coin list, refusing an empty list and duplicates.
func ParseCoins(names []string) ([]Coin, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no coins")
	}
	var out []Coin
	for _, n := range names {
		c, err := ParseCoin(n)
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, c) {
			return nil, fmt.Errorf("duplicate coin %q", n)
		}
		out = append(out, c)
	}
	return out, nil
}

// ZapRankingConfig configures the zap-ranking cache action. The first
// window and coin are the defaults a request gets.
type ZapRankingConfig struct {
	Enabled  bool
	Windows  []ZapWindow
	Coins    []Coin
	Limit    int           // default list length
	MaxLimit int           // cap on a request's limit
	Refresh  time.Duration // how long a computed list is reused
}

// Defaults for unset ZapRankingConfig fields.
var (
	DefaultZapWindows        = []ZapWindow{{Label: "24h", D: 24 * time.Hour}}
	DefaultZapCoins          = []Coin{CoinSats, CoinLoki}
	DefaultZapLimit          = 50
	DefaultZapMaxLimit       = 200
	DefaultZapRankingRefresh = time.Minute
)

func (c ZapRankingConfig) withDefaults() ZapRankingConfig {
	if len(c.Windows) == 0 {
		c.Windows = DefaultZapWindows
	}
	if len(c.Coins) == 0 {
		c.Coins = DefaultZapCoins
	}
	if c.MaxLimit <= 0 {
		c.MaxLimit = DefaultZapMaxLimit
	}
	if c.Limit <= 0 {
		c.Limit = DefaultZapLimit
	}
	c.Limit = min(c.Limit, c.MaxLimit)
	if c.Refresh <= 0 {
		c.Refresh = DefaultZapRankingRefresh
	}
	return c
}

// RankedZap is a receiver's counted zap total, in milli-units of one coin.
type RankedZap struct {
	Pubkey string
	Total  uint64
}

// ZapRanking is one computed list.
type ZapRanking struct {
	Window     ZapWindow
	Coin       Coin
	Zaps       []RankedZap // at most the config's MaxLimit, highest first
	ComputedAt time.Time
}

// zapRankingCache holds every (window, coin) list of one config, computed
// together in one pass, on first use. A list older than Refresh is served
// stale while one refresh runs; nothing is recomputed when the store
// hasn't changed; unused for 10× Refresh, the lists are dropped.
type zapRankingCache struct {
	mu         sync.Mutex
	key        string
	lists      map[rankKey][]RankedZap
	totals     [numCoins]uint64
	hasTotals  bool
	computedAt time.Time
	commits    uint64
	lastUsed   time.Time
	flight     chan struct{} // closed when the running refresh ends
	flightErr  error
	evict      *time.Timer

	// passes counts refresh passes, for tests.
	passes int
}

type rankKey struct {
	window time.Duration
	coin   Coin
}

func configKey(c ZapRankingConfig, totals bool) string {
	var b strings.Builder
	for _, w := range c.Windows {
		fmt.Fprintf(&b, "%d,", w.D)
	}
	for _, coin := range c.Coins {
		fmt.Fprintf(&b, "%d,", coin)
	}
	fmt.Fprintf(&b, "%d,%t", c.MaxLimit, totals)
	return b.String()
}

// ZapRanking returns the ranking for window and coin from the cache,
// computing it on first use.
func (s *EventStore) ZapRanking(ctx context.Context, cfg ZapRankingConfig, window ZapWindow, coin Coin) (ZapRanking, error) {
	cfg = cfg.withDefaults()
	lists, at, err := s.zapRank.get(ctx, s, cfg, false)
	if err != nil {
		return ZapRanking{}, err
	}
	return ZapRanking{Window: window, Coin: coin, Zaps: lists[rankKey{window.D, coin}], ComputedAt: at}, nil
}

// ZapTotals returns all-time counted zap totals per coin, in milli-units,
// from the same cache (whose pass then covers all time).
func (s *EventStore) ZapTotals(ctx context.Context, cfg ZapRankingConfig) (map[Coin]uint64, error) {
	cfg = cfg.withDefaults()
	if _, _, err := s.zapRank.get(ctx, s, cfg, true); err != nil {
		return nil, err
	}
	c := &s.zapRank
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[Coin]uint64{}
	for _, coin := range cfg.Coins {
		out[coin] = c.totals[coin]
	}
	return out, nil
}

func (c *zapRankingCache) get(ctx context.Context, s *EventStore, cfg ZapRankingConfig, totals bool) (map[rankKey][]RankedZap, time.Time, error) {
	c.mu.Lock()
	// Totals need an all-time pass; once a pass includes them, keep doing so.
	totals = totals || (c.key == configKey(cfg, true))
	key := configKey(cfg, totals)
	if c.key != key {
		c.key, c.lists, c.hasTotals = key, nil, false
	}
	now := time.Now()
	c.lastUsed = now
	if c.lists != nil {
		lists, at := c.lists, c.computedAt
		if now.Sub(c.computedAt) >= cfg.Refresh && c.flight == nil {
			if s.commits.Load() == c.commits {
				c.computedAt = now
				at = now
			} else {
				c.startRefresh(s, cfg, totals)
			}
		}
		c.mu.Unlock()
		return lists, at, nil
	}
	if c.flight == nil {
		c.startRefresh(s, cfg, totals)
	}
	flight := c.flight
	c.mu.Unlock()

	select {
	case <-flight:
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lists == nil {
		if c.flightErr != nil {
			return nil, time.Time{}, c.flightErr
		}
		return nil, time.Time{}, fmt.Errorf("zap ranking unavailable")
	}
	return c.lists, c.computedAt, nil
}

// startRefresh runs one pass in the background; c.mu is held.
func (c *zapRankingCache) startRefresh(s *EventStore, cfg ZapRankingConfig, totals bool) {
	done := make(chan struct{})
	c.flight = done
	key := c.key
	go func() {
		commits := s.commits.Load()
		lists, sums, err := s.rankZaps(cfg, totals, time.Now())
		c.mu.Lock()
		defer c.mu.Unlock()
		c.passes++
		c.flight, c.flightErr = nil, err
		if err == nil && c.key == key {
			c.lists, c.totals, c.hasTotals = lists, sums, totals
			c.computedAt, c.commits = time.Now(), commits
			c.scheduleEvict(cfg.Refresh * 10)
		}
		close(done)
	}()
}

// scheduleEvict drops the lists once unused for idle; c.mu is held.
func (c *zapRankingCache) scheduleEvict(idle time.Duration) {
	if c.evict != nil {
		c.evict.Stop()
	}
	var check func()
	check = func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if left := idle - time.Since(c.lastUsed); left > 0 {
			c.evict = time.AfterFunc(left, check)
			return
		}
		c.lists, c.key, c.evict = nil, "", nil
	}
	c.evict = time.AfterFunc(idle, check)
}

// rankZaps walks the zap index once, newest first, back to the longest
// window's start (or all time), adding each counted zap to every window
// containing it. Newest first with one payment-hash set means each payment
// counts once, as its newest copy, in every window holding any copy.
func (s *EventStore) rankZaps(cfg ZapRankingConfig, totals bool, now time.Time) (map[rankKey][]RankedZap, [numCoins]uint64, error) {
	var sums [numCoins]uint64
	starts := make([]uint64, len(cfg.Windows))
	var since uint64
	allTime := totals
	for i, w := range cfg.Windows {
		if w.D == 0 {
			allTime = true
			continue
		}
		starts[i] = uint64(now.Add(-w.D).Unix())
	}
	if !allTime {
		since = slices.Min(starts)
	}
	wanted := [numCoins]bool{}
	for _, c := range cfg.Coins {
		wanted[c] = true
	}
	type recvCoin struct {
		pk   [32]byte
		coin Coin
	}
	agg := map[recvCoin][]uint64{}

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(activeZapBucket(tx))
		if b == nil {
			return nil
		}
		keys := lnurlKeys{tx: tx, cache: map[string]string{}}
		// Payments are told apart per coin, so each coin's list stands alone.
		var seen [numCoins]map[string]bool
		for i := range seen {
			seen[i] = map[string]bool{}
		}
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if len(k) < 8 || len(v) < 40 {
				continue
			}
			at := binary.BigEndian.Uint64(k[:8])
			if at < since {
				break
			}
			if at > uint64(now.Unix()) {
				continue
			}
			e, ok := decodeZapEntry(v[40:])
			if !ok || !wanted[e.Coin] {
				continue
			}
			receiver := hex.EncodeToString(v[8:40])
			if !zapCounts(e, e.Other, receiver, keys.get(receiver), seen[e.Coin]) {
				continue
			}
			sums[e.Coin] += e.Amount
			rc := recvCoin{coin: e.Coin}
			copy(rc.pk[:], v[8:40])
			per := agg[rc]
			if per == nil {
				per = make([]uint64, len(cfg.Windows))
				agg[rc] = per
			}
			for i, w := range cfg.Windows {
				if w.D == 0 || at >= starts[i] {
					per[i] += e.Amount
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, sums, err
	}

	lists := map[rankKey][]RankedZap{}
	for i, w := range cfg.Windows {
		for _, coin := range cfg.Coins {
			var all []RankedZap
			for rc, per := range agg {
				if rc.coin == coin && per[i] > 0 {
					all = append(all, RankedZap{Pubkey: hex.EncodeToString(rc.pk[:]), Total: per[i]})
				}
			}
			sortRanked(all)
			if len(all) > cfg.MaxLimit {
				all = all[:cfg.MaxLimit]
			}
			lists[rankKey{w.D, coin}] = all
		}
	}
	return lists, sums, nil
}

// sortRanked orders highest total first, ties by pubkey.
func sortRanked(z []RankedZap) {
	slices.SortFunc(z, func(a, b RankedZap) int {
		if c := cmp.Compare(b.Total, a.Total); c != 0 {
			return c
		}
		return strings.Compare(a.Pubkey, b.Pubkey)
	})
}

// TopZapped ranks receivers by counted zaps in coin created in [since,
// until], uncached; the reference the cache must match.
func (s *EventStore) TopZapped(ctx context.Context, since, until uint64, coin Coin, limit int) ([]RankedZap, error) {
	if limit <= 0 {
		return nil, nil
	}
	agg := map[string]uint64{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(activeZapBucket(tx))
		if b == nil {
			return nil
		}
		keys := lnurlKeys{tx: tx, cache: map[string]string{}}
		seen := map[string]bool{}
		c := b.Cursor()
		// Newest first, like rankZaps: a payment counts as its newest copy.
		var k, v []byte
		if k, _ = c.Seek(itob(until + 1)); k == nil {
			k, v = c.Last()
		} else {
			k, v = c.Prev()
		}
		for ; k != nil; k, v = c.Prev() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(k) < 8 || bytes.Compare(k[:8], itob(since)) < 0 {
				break
			}
			if len(v) < 40 {
				continue
			}
			e, ok := decodeZapEntry(v[40:])
			if !ok || e.Coin != coin {
				continue
			}
			receiver := hex.EncodeToString(v[8:40])
			if zapCounts(e, e.Other, receiver, keys.get(receiver), seen) {
				agg[receiver] += e.Amount
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]RankedZap, 0, len(agg))
	for pk, total := range agg {
		out = append(out, RankedZap{Pubkey: pk, Total: total})
	}
	sortRanked(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
