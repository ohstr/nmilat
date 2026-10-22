package relay

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rankingPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// rankingFixture stores zaps and asks for rankings through a real session.
type rankingFixture struct {
	t        *testing.T
	store    *EventStore
	sender   testKey
	provider testKey
	now      uint64
	n        int
}

func newRankingFixture(t *testing.T) *rankingFixture {
	return &rankingFixture{t: t, store: newStore(t), sender: newTestKey(t, 1), provider: newTestKey(t, 2), now: uint64(time.Now().Unix())}
}

// zap stores a receipt paying receiver amount whole units of coin, ago before now.
func (f *rankingFixture) zap(receiver string, coin Coin, amount int64, ago time.Duration, opts ...func(*zapSpec)) *nip01.Event {
	f.t.Helper()
	f.n++
	z := zapSpec{Sender: f.sender, Provider: f.provider, Recipient: receiver, Amount: amount * 1000, CreatedAt: f.now - uint64(ago.Seconds()) - uint64(f.n%7)}
	if coin == CoinLoki {
		z.Kind = nipAZ.KindAltZapReceipt
	}
	for _, o := range opts {
		o(&z)
	}
	ev := zapReceipt(f.t, z)
	InsertTestEvents(f.t, f.store, []*nip01.Event{ev})
	return ev
}

func (f *rankingFixture) session(zaps ZapRankingConfig) *Session {
	cfg := defaultSessionConfig()
	cfg.PrivKey = rankingPrivKey
	cfg.OutgoingBufferSize = 64
	cfg.Zaps = zaps
	sc := NewSessionContext(f.store, &ClientInfo{RemoteAddr: "test"}, &nip11.Metadata{}, nil, nil, cfg)
	sc.groups = NewGroupsService(f.store)
	return &Session{SessionContext: sc}
}

type rankingReply struct {
	event  *nip01.Event
	totals []rankedZapJSON
	closed string
	others int
}

// ask sends REQ {"cache": cache} and collects the replies.
func (f *rankingFixture) ask(sess *Session, cache string) rankingReply {
	f.t.Helper()
	rp := &wire.RequestPacket{SubscriptionID: "r", Filters: nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Cache: json.RawMessage(cache)})}
	require.NoError(f.t, sess.processRequest(context.Background(), rp))
	var out rankingReply
	for {
		select {
		case resp := <-sess.incoming:
			switch r := resp.(type) {
			case *wire.EventSubscriptionResponse:
				var ev nip01.Event
				require.NoError(f.t, json.Unmarshal(r.EventBytes, &ev))
				if ev.Kind == KindZapRanking {
					out.event = &ev
					require.NoError(f.t, json.Unmarshal([]byte(ev.Content), &out.totals))
				} else {
					out.others++
				}
			case *wire.ClosedSubscriptionResponse:
				out.closed = r.Message
				return out
			}
		case <-time.After(5 * time.Second):
			f.t.Fatal("no CLOSED")
		}
	}
}

var fourWindows = mustWindows("24h", "7d", "30d", "all")

func mustWindows(labels ...string) []ZapWindow {
	ws, err := ParseZapWindows(labels)
	if err != nil {
		panic(err)
	}
	return ws
}

func pubkeyN(n int) string { return nip57test.NewKey(500 + n).Pub }

func TestZapRanking_Defaults(t *testing.T) {
	f := newRankingFixture(t)
	alice, bob := pubkeyN(1), pubkeyN(2)
	f.zap(alice, CoinSats, 21, time.Hour)
	f.zap(bob, CoinLoki, 99, time.Hour)
	f.zap(alice, CoinSats, 5, 3*24*time.Hour) // outside 24h

	r := f.ask(f.session(ZapRankingConfig{Enabled: true}), `["zap-ranking"]`)
	require.NotNil(t, r.event, r.closed)
	assert.Equal(t, "one-shot cache request completed", r.closed)
	assert.Equal(t, "24h", tagValue(r.event, "window"))
	assert.Equal(t, "sats", tagValue(r.event, "coin"))
	assert.Equal(t, "50", tagValue(r.event, "limit"))
	assert.Equal(t, []rankedZapJSON{{alice, 21}}, r.totals, "sats only, last 24h, whole units")
	assert.InDelta(t, float64(time.Now().Unix()), float64(r.event.CreatedAt), 5, "created_at is when the list was computed")
	require.NoError(t, r.event.Verify())
}

func TestZapRanking_FirstWindowAndCoinAreTheDefaults(t *testing.T) {
	f := newRankingFixture(t)
	bob := pubkeyN(2)
	f.zap(bob, CoinLoki, 7, 3*24*time.Hour)
	r := f.ask(f.session(ZapRankingConfig{Enabled: true, Windows: mustWindows("7d", "24h"), Coins: []Coin{CoinLoki, CoinSats}}), `["zap-ranking",{}]`)
	require.NotNil(t, r.event, r.closed)
	assert.Equal(t, "7d", tagValue(r.event, "window"))
	assert.Equal(t, "loki", tagValue(r.event, "coin"))
	assert.Equal(t, []rankedZapJSON{{bob, 7}}, r.totals)
}

func TestZapRanking_EveryWindow(t *testing.T) {
	f := newRankingFixture(t)
	a := pubkeyN(1)
	f.zap(a, CoinSats, 1, time.Hour)
	f.zap(a, CoinSats, 10, 3*24*time.Hour)
	f.zap(a, CoinSats, 100, 20*24*time.Hour)
	f.zap(a, CoinSats, 1000, 400*24*time.Hour)
	sess := f.session(ZapRankingConfig{Enabled: true, Windows: fourWindows})
	for window, want := range map[string]uint64{"24h": 1, "7d": 11, "30d": 111, "all": 1111, "1w": 11, "168h": 11} {
		r := f.ask(sess, `["zap-ranking",{"window":"`+window+`"}]`)
		require.NotNil(t, r.event, "%s: %s", window, r.closed)
		assert.Equal(t, []rankedZapJSON{{a, want}}, r.totals, window)
	}
	// A window given another way is answered under the configured label.
	r := f.ask(sess, `["zap-ranking",{"window":"1w"}]`)
	assert.Equal(t, "7d", tagValue(r.event, "window"))
}

func TestZapRanking_CoinsNeverMix(t *testing.T) {
	f := newRankingFixture(t)
	a, b := pubkeyN(1), pubkeyN(2)
	f.zap(a, CoinSats, 5, time.Hour)
	f.zap(a, CoinLoki, 7, time.Hour)
	f.zap(b, CoinLoki, 3, time.Hour)
	// A 9735 paid with a Flokicoin invoice counts as loki, a 9521 on bitcoin as sats.
	f.zap(b, CoinSats, 4, time.Hour, func(z *zapSpec) { z.Kind, z.Chain = nipAZ.KindAltZapReceipt, "bitcoin" })
	f.zap(a, CoinLoki, 2, time.Hour, func(z *zapSpec) { z.Kind, z.Currency = 0, "fc" })
	sess := f.session(ZapRankingConfig{Enabled: true})

	sats := f.ask(sess, `["zap-ranking",{"coin":"sats"}]`)
	assert.Equal(t, []rankedZapJSON{{a, 5}, {b, 4}}, sats.totals)
	loki := f.ask(sess, `["zap-ranking",{"coin":"LOKI"}]`)
	assert.Equal(t, []rankedZapJSON{{a, 9}, {b, 3}}, loki.totals)
	assert.Equal(t, "loki", tagValue(loki.event, "coin"))
}

func TestZapRanking_LimitClamp(t *testing.T) {
	f := newRankingFixture(t)
	for i := 1; i <= 4; i++ {
		f.zap(pubkeyN(i), CoinSats, int64(i), time.Hour)
	}
	sess := f.session(ZapRankingConfig{Enabled: true, Limit: 2, MaxLimit: 3})
	for req, want := range map[string]int{`{}`: 2, `{"limit":1}`: 1, `{"limit":3}`: 3, `{"limit":1000}`: 3, `{"limit":-5}`: 2} {
		r := f.ask(sess, `["zap-ranking",`+req+`]`)
		require.NotNil(t, r.event, r.closed)
		assert.Len(t, r.totals, want, req)
		assert.Equal(t, strconv.Itoa(want), tagValue(r.event, "limit"), req)
	}
	r := f.ask(sess, `["zap-ranking",{"limit":3}]`)
	assert.Equal(t, []rankedZapJSON{{pubkeyN(4), 4}, {pubkeyN(3), 3}, {pubkeyN(2), 2}}, r.totals, "highest first")
}

func TestZapRanking_Refusals(t *testing.T) {
	f := newRankingFixture(t)
	f.zap(pubkeyN(1), CoinSats, 1, time.Hour)
	// Other stored events must never leak into a refused cache request.
	InsertTestEvents(t, f.store, []*nip01.Event{signed(t, newTestKey(t, 9), 1, f.now-1)})
	sess := f.session(ZapRankingConfig{Enabled: true, Windows: fourWindows})

	for cache, want := range map[string]string{
		`["zap-ranking",{"window":"3d"}]`:   "invalid: window must be one of 24h, 7d, 30d, all",
		`["zap-ranking",{"window":"soon"}]`: "invalid: window must be one of 24h, 7d, 30d, all",
		`["zap-ranking",{"coin":"btc"}]`:    "invalid: coin must be one of sats, loki",
		`["zap-ranking","7d"]`:              "invalid: zap-ranking options must be {window, coin, limit}",
		`["top-zapped",{"window":"24h"}]`:   `invalid: unknown cache action "top-zapped"`,
		`["get_top_zapped"]`:                `invalid: unknown cache action "get_top_zapped"`,
		`["typo"]`:                          `invalid: unknown cache action "typo"`,
		`[]`:                                `invalid: cache must be ["<action>", {options}]`,
		`"zap-ranking"`:                     `invalid: cache must be ["<action>", {options}]`,
		`[42]`:                              "invalid: cache action must be a string",
	} {
		r := f.ask(sess, cache)
		assert.Nil(t, r.event, cache)
		assert.Zero(t, r.others, "%s streamed stored events", cache)
		assert.Equal(t, want, r.closed, cache)
	}

	off := f.ask(f.session(ZapRankingConfig{}), `["zap-ranking"]`)
	assert.Nil(t, off.event)
	assert.Equal(t, "restricted: zap ranking is not enabled on this relay", off.closed)

	keyless := f.session(ZapRankingConfig{Enabled: true})
	keyless.config.PrivKey = ""
	r := f.ask(keyless, `["zap-ranking"]`)
	assert.Nil(t, r.event)
	assert.Contains(t, r.closed, "error: relay private key missing")
}

func TestZapRanking_CountingRules(t *testing.T) {
	f := newRankingFixture(t)
	a := pubkeyN(1)
	// The same payment twice counts once.
	pre := strings.Repeat("1", 64)
	f.zap(a, CoinSats, 10, time.Hour, func(z *zapSpec) { z.Preimage = pre })
	f.zap(a, CoinSats, 10, 2*time.Hour, func(z *zapSpec) { z.Preimage = pre })
	// A self-zap doesn't count.
	f.zap(f.sender.pub, CoinSats, 50, time.Hour)
	r := f.ask(f.session(ZapRankingConfig{Enabled: true}), `["zap-ranking"]`)
	assert.Equal(t, []rankedZapJSON{{a, 10}}, r.totals)
}
