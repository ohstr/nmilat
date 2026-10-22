package relay

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
)

// KindRelayDiscovery is NIP-66's relay discovery event, here published by
// the relay about itself.
const KindRelayDiscovery = 30166

// RelayDiscovery is what a self-published NIP-66 event says. Tags for a
// feature appear only when it's on.
type RelayDiscovery struct {
	// URL is the relay's address; its normalized form is the "d" tag.
	URL string
	// Info is the NIP-11 document (JSON), the event's content.
	Info string
	// Metadata gives supported NIPs ("N") and requirements ("R").
	Metadata *nip11.Metadata
	// AllowedKinds/DisallowedKinds, when the relay restricts kinds ("k").
	AllowedKinds, DisallowedKinds []int

	Counts Counts
	// Profiles adds the "profiles" count (kind 0 authors).
	Profiles bool
	// Zaps, when set, adds the zap-receipts count, the per-coin totals
	// (milli-units, as ZapTotals returns them) and the zap-ranking windows
	// and coins.
	Zaps      *ZapRankingConfig
	ZapTotals map[Coin]uint64
}

// NormalizeRelayURL lowercases scheme and host, drops a default port and
// gives an empty path a trailing slash.
func NormalizeRelayURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid relay URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", fmt.Errorf("invalid relay URL %q: want ws:// or wss://", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "wss" && port == "443") || (u.Scheme == "ws" && port == "80") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = host + ":" + port
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String(), nil
}

// Event builds the unsigned kind 30166.
func (d RelayDiscovery) Event() (*nip01.Event, error) {
	dTag, err := NormalizeRelayURL(d.URL)
	if err != nil {
		return nil, err
	}
	num := func(n uint64) string { return strconv.FormatUint(n, 10) }
	tags := [][]string{{"d", dTag}, {"n", relayNetwork(dTag)}}

	if md := d.Metadata; md != nil {
		for _, n := range md.SupportedNips {
			tags = append(tags, []string{"N", n.String()})
		}
		l := md.Limitation
		for _, r := range []struct {
			name string
			on   bool
		}{
			{"auth", l.AuthRequired},
			{"payment", false},
			{"pow", l.StrictPow && l.MinPowDifficulty > 0},
			{"writes", l.MembershipRequired},
		} {
			v := r.name
			if !r.on {
				v = "!" + v
			}
			tags = append(tags, []string{"R", v})
		}
	}
	for _, k := range d.AllowedKinds {
		tags = append(tags, []string{"k", strconv.Itoa(k)})
	}
	for _, k := range d.DisallowedKinds {
		tags = append(tags, []string{"k", "!" + strconv.Itoa(k)})
	}

	tags = append(tags,
		[]string{"count", "events", num(d.Counts.Events)},
		[]string{"count", "authors", num(d.Counts.Authors)},
	)
	if d.Profiles {
		tags = append(tags, []string{"count", "profiles", num(d.Counts.Kind(0))})
	}
	if z := d.Zaps; z != nil {
		cfg := z.withDefaults()
		tags = append(tags, []string{"count", "zap-receipts", num(d.Counts.Kind(9735) + d.Counts.Kind(9521))})
		for _, c := range cfg.Coins {
			tags = append(tags, []string{"total", "zaps", num(WholeUnits(d.ZapTotals[c])), c.String()})
		}
		windows := []string{"zap-ranking", "windows"}
		for _, w := range cfg.Windows {
			windows = append(windows, w.Label)
		}
		coins := []string{"zap-ranking", "coins"}
		for _, c := range cfg.Coins {
			coins = append(coins, c.String())
		}
		tags = append(tags, windows, coins)
	}
	return &nip01.Event{Kind: KindRelayDiscovery, CreatedAt: uint64(time.Now().Unix()), Tags: tags, Content: d.Info}, nil
}

func relayNetwork(u string) string {
	host := u
	if p, err := url.Parse(u); err == nil {
		host = p.Hostname()
	}
	switch {
	case strings.HasSuffix(host, ".onion"):
		return "tor"
	case strings.HasSuffix(host, ".i2p"):
		return "i2p"
	case strings.HasSuffix(host, ".loki"):
		return "loki"
	}
	return "clearnet"
}

// PublishSelfSigned stores ev (an addressable event the relay authors)
// signed with privkey, unless the stored one under the same kind and "d"
// tag has the same tags and content. Its created_at is strictly newer than
// the stored one's, so a same-second republish still replaces it. It
// reports whether it stored a new event.
func (s *EventStore) PublishSelfSigned(ctx context.Context, privkey string, ev *nip01.Event) (bool, error) {
	pubkey, err := nip11.DerivePubKey(privkey)
	if err != nil {
		return false, err
	}
	var d string
	for _, t := range ev.Tags {
		if len(t) > 1 && t[0] == "d" {
			d = t[1]
			break
		}
	}
	prev, err := s.QueryEvents(ctx, &nip01.SubscriptionFilter{
		Kinds: []int{ev.Kind}, Authors: []string{pubkey}, Tags: map[string][]string{"d": {d}}, Limit: 1,
	})
	if err != nil {
		return false, err
	}
	if len(prev) > 0 {
		if prev[0].Content == ev.Content && slices.EqualFunc(prev[0].Tags, ev.Tags, slices.Equal) {
			return false, nil
		}
		if ev.CreatedAt <= prev[0].CreatedAt {
			ev.CreatedAt = prev[0].CreatedAt + 1
		}
	}
	if err := ev.Sign(privkey); err != nil {
		return false, err
	}
	if err := s.InsertEvents(ctx, []*nip01.Event{ev}); err != nil {
		return false, err
	}
	return true, nil
}
