package relay

import (
	"container/list"
	"context"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// KindUserAssertion is NIP-85's assertion about a user (kind 30382).
const KindUserAssertion = 30382

// AssertionsHandler answers NIP-85 user-assertion filters (kinds [30382]
// with #d target pubkeys) from the relay's profile stats, signed with
// SessionConfig.PrivKey. A filter for another provider's assertions
// (authors without the relay key) is served from stored events, and so is
// the rest of a REQ that mixes assertion filters with others.
//
// Tags beyond NIP-85's: following, zappers_recd, zap_first_recd,
// zap_last_recd, zap_first_sent, zap_last_sent (unix times), and
// nip05_verified / lud16_verified (the identifier, when verified).
type AssertionsHandler struct{}

func isAssertionFilter(f *nip01.SubscriptionFilter) bool {
	return len(f.Kinds) == 1 && f.Kinds[0] == KindUserAssertion
}

func (h *AssertionsHandler) CanHandle(rp *wire.RequestPacket) bool {
	return slices.ContainsFunc(rp.Filters.GetAll(), isAssertionFilter)
}

func (h *AssertionsHandler) Handle(ctx context.Context, s *Session, rp *wire.RequestPacket) (bool, error) {
	if !s.config.EnableProfileStats || s.config.PrivKey == "" {
		return false, nil
	}
	self, err := utils.GetPublicKey(s.config.PrivKey)
	if err != nil {
		return false, nil
	}

	var ours, rest []*nip01.SubscriptionFilter
	for _, f := range rp.Filters.GetAll() {
		if isAssertionFilter(f) && (len(f.Authors) == 0 || slices.Contains(f.Authors, self)) {
			ours = append(ours, f)
		} else {
			rest = append(rest, f)
		}
	}
	if len(ours) == 0 {
		return false, nil
	}

	var targets []string
	for _, f := range ours {
		for _, d := range f.Tags["d"] {
			d = strings.ToLower(d)
			if utils.Validate32Key(d) == nil && !slices.Contains(targets, d) {
				targets = append(targets, d)
			}
		}
	}
	if len(targets) == 0 {
		if len(rest) > 0 {
			return false, nil
		}
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "restricted: profile assertions need #d target pubkeys",
		})
		return true, nil
	}
	maxTargets := s.config.MaxStatsTargets
	if maxTargets <= 0 {
		maxTargets = DefaultMaxStatsTargets
	}
	if len(targets) > maxTargets {
		s.reply(&wire.ClosedSubscriptionResponse{
			SubscriptionID: rp.SubscriptionID,
			Message:        "invalid: at most " + strconv.Itoa(maxTargets) + " #d pubkeys per request",
		})
		return true, nil
	}

	var events []*nip01.Event
	for _, pk := range targets {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		ev, err := userAssertion(s.store, s.config, self, pk)
		if err != nil {
			return true, err
		}
		if ev != nil {
			events = append(events, ev)
		}
	}
	s.SendEvents(rp.SubscriptionID, events)
	if len(rest) > 0 {
		// The other filters go on to the stored events, which end with EOSE.
		rp.Filters = nip01.NewSubscriptionFilterGroup(rest...)
		return false, nil
	}
	s.SendEOSE(rp.SubscriptionID)
	return true, nil
}

// userAssertion builds (or reuses) the signed assertion about pubkey; nil
// when the relay knows nothing about it.
func userAssertion(store *EventStore, cfg *SessionConfig, self, pubkey string) (*nip01.Event, error) {
	st, err := store.GetProfileStats(pubkey)
	if err != nil {
		return nil, err
	}
	m, err := store.GetProfileMetrics(pubkey)
	if err != nil {
		return nil, err
	}
	// Once served, a profile stays served, so a drop to zero reaches
	// clients too.
	tags := assertionTags(st, m, assertions.has(self, pubkey), cfg.Zaps.withDefaults().Coins)
	if tags == nil {
		return nil, nil
	}
	return assertions.get(self, pubkey, tags, func(createdAt uint64) (*nip01.Event, error) {
		ev := &nip01.Event{Kind: KindUserAssertion, CreatedAt: createdAt, Tags: tags}
		if cfg.Delegation != nil {
			ev.Tags = append(ev.Tags, []string{"delegation", cfg.Delegation.Issuer, cfg.Delegation.Conditions, cfg.Delegation.Token})
		}
		return ev, ev.Sign(cfg.PrivKey)
	})
}

// assertionTags is the NIP-85 tag set for a profile, nil if it has no
// stats, was never checked and wasn't served before. Amounts are sats, plus
// a _<coin> tag for each other coin in coins with an amount.
func assertionTags(st *ProfileStats, m *ProfileMetrics, served bool, coins []Coin) [][]string {
	known := served || st.Followers > 0 || st.Following > 0 || st.ZapCntRecd > 0 || st.ZapCntSent > 0 ||
		m.BaseScore != 0 || m.Nip05.Value != "" || m.Lud16.Value != ""
	if !known {
		return nil
	}
	num := func(n int64) string { return strconv.FormatInt(n, 10) }
	tags := [][]string{
		{"d", st.Pubkey},
		{"rank", num(rank(m.TotalScore()))},
		{"followers", num(st.Followers)},
		{"following", num(st.Following)},
		{"zap_cnt_recd", num(int64(st.ZapCntRecd))},
		{"zap_amt_recd", num(int64(st.ZapAmtRecd / 1000))},
		{"zappers_recd", num(int64(st.ZappersRecd))},
		{"zap_cnt_sent", num(int64(st.ZapCntSent))},
		{"zap_amt_sent", num(int64(st.ZapAmtSent / 1000))},
	}
	for _, c := range coins {
		if c == CoinSats {
			continue
		}
		if n := WholeUnits(st.AmtRecd[c]); n > 0 {
			tags = append(tags, []string{"zap_amt_recd_" + c.String(), num(int64(n))})
		}
		if n := WholeUnits(st.AmtSent[c]); n > 0 {
			tags = append(tags, []string{"zap_amt_sent_" + c.String(), num(int64(n))})
		}
	}
	for _, t := range []struct {
		name string
		at   int64
	}{
		{"zap_first_recd", st.ZapFirstRecd}, {"zap_last_recd", st.ZapLastRecd},
		{"zap_first_sent", st.ZapFirstSent}, {"zap_last_sent", st.ZapLastSent},
	} {
		if t.at > 0 {
			tags = append(tags, []string{t.name, num(t.at)})
		}
	}
	if m.Nip05.Status == CheckOK {
		tags = append(tags, []string{"nip05_verified", m.Nip05.Value})
	}
	if m.Lud16.Status == CheckOK {
		tags = append(tags, []string{"lud16_verified", m.Lud16.Value})
	}
	return tags
}

// rank maps a profile score onto NIP-85's 0-100.
func rank(score int64) int64 {
	scale := config.Get().Search.Social.RankScore
	if scale <= 0 || score <= 0 {
		return 0
	}
	return int64(math.Min(100, math.Round(100*float64(score)/scale)))
}

// assertions caches signed assertions so an unchanged profile keeps its
// event id, and a changed one gets a later created_at.
var assertions = newAssertionCache(50_000)

type assertionCache struct {
	mu    sync.Mutex
	max   int
	order *list.List
	items map[string]*list.Element
}

type assertionEntry struct {
	key   string
	tags  string
	event *nip01.Event
}

func newAssertionCache(max int) *assertionCache {
	return &assertionCache{max: max, order: list.New(), items: map[string]*list.Element{}}
}

func (c *assertionCache) has(signer, pubkey string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.items[signer+pubkey]
	return ok
}

func (c *assertionCache) get(signer, pubkey string, tags [][]string, build func(createdAt uint64) (*nip01.Event, error)) (*nip01.Event, error) {
	key := signer + pubkey
	flat := flattenTags(tags)
	createdAt := uint64(time.Now().Unix())

	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*assertionEntry)
		if e.tags == flat {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return e.event, nil
		}
		createdAt = max(createdAt, e.event.CreatedAt+1)
	}
	c.mu.Unlock()

	ev, err := build(createdAt)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value = &assertionEntry{key, flat, ev}
		c.order.MoveToFront(el)
		return ev, nil
	}
	c.items[key] = c.order.PushFront(&assertionEntry{key, flat, ev})
	if c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*assertionEntry).key)
	}
	return ev, nil
}

func flattenTags(tags [][]string) string {
	var b strings.Builder
	for _, t := range tags {
		b.WriteString(strings.Join(t, "\x00"))
		b.WriteByte('\x01')
	}
	return b.String()
}
