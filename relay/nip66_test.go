package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeRelayURL(t *testing.T) {
	for in, want := range map[string]string{
		"wss://Relay.Example.com":        "wss://relay.example.com/",
		"WSS://relay.example.com:443/":   "wss://relay.example.com/",
		"ws://relay.example.com:80":      "ws://relay.example.com/",
		"ws://127.0.0.1:5500":            "ws://127.0.0.1:5500/",
		"wss://relay.example.com/inbox":  "wss://relay.example.com/inbox",
		"wss://relay.example.com/?x=1#f": "wss://relay.example.com/",
	} {
		got, err := NormalizeRelayURL(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "relay.example.com", "https://relay.example.com", "wss://"} {
		_, err := NormalizeRelayURL(bad)
		assert.Error(t, err, bad)
	}
}

// tagsNamed returns every tag named name.
func tagsNamed(ev *nip01.Event, name string) [][]string {
	var out [][]string
	for _, t := range ev.Tags {
		if len(t) > 0 && t[0] == name {
			out = append(out, t)
		}
	}
	return out
}

func TestRelayDiscovery_EverythingOn(t *testing.T) {
	md := &nip11.Metadata{SupportedNips: []nip11.NIPID{nip11.NIP(1), nip11.NIP(11), nip11.NIP(85)}}
	md.Limitation.AuthRequired = true
	md.Limitation.MinPowDifficulty, md.Limitation.StrictPow = 20, true
	zaps := ZapRankingConfig{Enabled: true, Windows: fourWindows}
	ev, err := RelayDiscovery{
		URL: "wss://Relay.Example.com", Info: `{"name":"x"}`, Metadata: md,
		Counts:   Counts{Events: 1183402, Authors: 84000, Kinds: map[int]uint64{0: 21000, 9735: 40000, 9521: 8000}},
		Profiles: true, Zaps: &zaps, ZapTotals: map[Coin]uint64{CoinSats: 1_250_999, CoinLoki: 98_000_000},
	}.Event()
	require.NoError(t, err)
	assert.Equal(t, KindRelayDiscovery, ev.Kind)
	assert.Equal(t, `{"name":"x"}`, ev.Content)
	assert.Equal(t, [][]string{
		{"d", "wss://relay.example.com/"}, {"n", "clearnet"},
		{"N", "1"}, {"N", "11"}, {"N", "85"},
		{"R", "auth"}, {"R", "!payment"}, {"R", "pow"}, {"R", "!writes"},
		{"count", "events", "1183402"}, {"count", "authors", "84000"},
		{"count", "profiles", "21000"}, {"count", "zap-receipts", "48000"},
		{"total", "zaps", "1250", "sats"}, {"total", "zaps", "98000", "loki"},
		{"zap-ranking", "windows", "24h", "7d", "30d", "all"}, {"zap-ranking", "coins", "sats", "loki"},
	}, ev.Tags)
	assert.Empty(t, tagsNamed(ev, "rtt-open"), "a relay doesn't time itself")
	assert.Empty(t, tagsNamed(ev, "k"), "no k tags when every kind is accepted")
}

func TestRelayDiscovery_FeaturesOff(t *testing.T) {
	ev, err := RelayDiscovery{URL: "ws://localhost:5500", Counts: Counts{Events: 3, Authors: 2, Kinds: map[int]uint64{0: 1}}}.Event()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"count", "events", "3"}, {"count", "authors", "2"}}, tagsNamed(ev, "count"))
	assert.Empty(t, tagsNamed(ev, "total"))
	assert.Empty(t, tagsNamed(ev, "zap-ranking"))
	assert.Empty(t, tagsNamed(ev, "R"), "no metadata, no requirements")
}

func TestRelayDiscovery_KindsAndNetworks(t *testing.T) {
	ev, err := RelayDiscovery{URL: "ws://abc.onion", AllowedKinds: []int{1, 7}, DisallowedKinds: []int{4}}.Event()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"k", "1"}, {"k", "7"}, {"k", "!4"}}, tagsNamed(ev, "k"))
	assert.Equal(t, [][]string{{"n", "tor"}}, tagsNamed(ev, "n"))
	_, err = RelayDiscovery{URL: "not a url"}.Event()
	assert.Error(t, err)
}

func TestPublishSelfSigned_SkipsUnchangedAndStaysNewer(t *testing.T) {
	store := newIndexedStore(t)
	ctx := context.Background()
	key := newTestKey(t, 7)
	build := func(events uint64) *nip01.Event {
		ev, err := RelayDiscovery{URL: "wss://relay.example.com", Counts: Counts{Events: events}}.Event()
		require.NoError(t, err)
		return ev
	}
	latest := func() *nip01.Event {
		evs, err := store.QueryEvents(ctx, &nip01.SubscriptionFilter{Kinds: []int{KindRelayDiscovery}, Authors: []string{key.pub}})
		require.NoError(t, err)
		require.Len(t, evs, 1, "addressable: one stored")
		return evs[0]
	}

	ok, err := store.PublishSelfSigned(ctx, key.priv, build(1))
	require.NoError(t, err)
	assert.True(t, ok)
	first := latest()
	require.NoError(t, first.Verify())
	assert.Equal(t, key.pub, first.PubKey)

	ok, err = store.PublishSelfSigned(ctx, key.priv, build(1))
	require.NoError(t, err)
	assert.False(t, ok, "unchanged tags and content: nothing published")

	// Same second, new numbers: still replaces, strictly newer.
	ok, err = store.PublishSelfSigned(ctx, key.priv, build(2))
	require.NoError(t, err)
	assert.True(t, ok)
	second := latest()
	assert.Greater(t, second.CreatedAt, first.CreatedAt)
	assert.Equal(t, "2", tagsNamed(second, "count")[0][2])

	_, err = store.PublishSelfSigned(ctx, "not a key", build(3))
	assert.Error(t, err)
}
