package vectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/niplsp"
	"github.com/ohstr/nmilat/utils"
)

// ---- lsp-announcement.json (NIP-LSP)

type lspFile struct {
	header
	Client  lspClient        `json:"client"`
	Events  []lspEventCase   `json:"events"`
	Parse   []lspParseCase   `json:"parse"`
	Live    []lspLiveCase    `json:"checkLive"`
	Answers []lspAnswersCase `json:"fromLSPSInfo"`
}

type lspClient struct {
	Chains   []string `json:"chains"`
	Networks []string `json:"networks"`
	Now      int64    `json:"now"`
}

type lspEventCase struct {
	ID    string      `json:"id"`
	Event nip01.Event `json:"event"`
	Step  int         `json:"step"`
}

// lspParseCase: ParseAnnouncement(Event, the client, at Now): the failing
// step (0 = read) and what a client reads.
type lspParseCase struct {
	Name   string         `json:"name"`
	Event  nip01.Event    `json:"event"`
	Client *lspClient     `json:"client,omitempty"`
	Step   int            `json:"step"`
	Error  string         `json:"error,omitempty"`
	Want   map[string]any `json:"want,omitempty"`
}

// lspLiveCase: CheckLive of the K-LSP-1 announcement against live answers.
type lspLiveCase struct {
	Name            string             `json:"name"`
	Protocols       []int              `json:"protocols"`
	LSPS1           json.RawMessage    `json:"lsps1"`
	LSPS2           json.RawMessage    `json:"lsps2"`
	MissingProtocol []int              `json:"missingProtocol"`
	Changed         []niplsp.FieldDiff `json:"changed"`
	Same            bool               `json:"same"`
	Worse           bool               `json:"worse"`
	Usable          bool               `json:"usable"`
}

type lspAnswersCase struct {
	Name   string          `json:"name"`
	LSPS1  json.RawMessage `json:"lsps1"`
	LSPS2  json.RawMessage `json:"lsps2"`
	LSPS5  json.RawMessage `json:"lsps5"`
	Error  string          `json:"error,omitempty"`
	Fields map[string]any  `json:"fields,omitempty"`
}

const (
	lspCreated = 1792713600
	lspExpires = 1795305600
	lsps1Sat   = `{"min_required_channel_confirmations":0,"min_funding_confirms_within_blocks":6,"supports_zero_channel_reserve":false,"max_channel_expiry_blocks":12960,"min_initial_client_balance_sat":"0","max_initial_client_balance_sat":"1000000","min_initial_lsp_balance_sat":"0","max_initial_lsp_balance_sat":"10000000","min_channel_balance_sat":"100000","max_channel_balance_sat":"10000000"}`
	lsps1Loki  = `{"options":[],"max_channel_balance_loki":"10000000","min_channel_balance_loki":"100000","max_initial_lsp_balance_loki":"10000000","min_initial_lsp_balance_loki":"0","max_initial_client_balance_loki":"1000000","min_initial_client_balance_loki":"0","max_channel_expiry_blocks":12960,"supports_zero_channel_reserve":false,"min_funding_confirms_within_blocks":6,"min_required_channel_confirmations":0}`
	lsps2Sat   = `{"opening_fee_params_menu":[{"min_fee_msat":"2000000","proportional":4000,"valid_until":"2026-10-22T00:00:00.000Z","min_lifetime":4320,"max_client_to_self_delay":2016,"min_payment_size_msat":"10000000","max_payment_size_msat":"4000000000","promise":"abcdef"}]}`
	lsps2Loki  = `[{"min_fee_mloki":"2000000","proportional":4000,"valid_until":"2026-10-22T00:00:00.000Z","min_lifetime":4320,"max_client_to_self_delay":2016,"min_payment_size_mloki":"10000000","max_payment_size_mloki":"4000000000","promise":"012345"}]`
	lsps5Ans   = `{"num_webhooks":2,"max_webhooks":10,"no_change":false}`
)

func lspExampleFields() niplsp.Fields {
	return niplsp.Fields{
		Meta: niplsp.Meta{
			NodeKey:    connIdentity,
			Addrs:      []string{"vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735", "203.0.113.7:9735"},
			Chain:      "bitcoin",
			Network:    "mainnet",
			Status:     niplsp.StatusOpen,
			Expiration: lspExpires,
			Display: niplsp.Display{Title: "Alice's Liquidity", Content: "Inbound channels and just-in-time channels.", Website: "https://lsp.example.com",
				Operator: &niplsp.Operator{Pubkey: lPub2, Relay: connRelay}, Languages: []string{"en"}},
			Relays: []string{connRelay},
		},
		Protocols: []int{1, 2, 5},
		LSPS1: []niplsp.Option{
			{Name: "min_required_channel_confirmations", Value: "0"}, {Name: "min_funding_confirms_within_blocks", Value: "6"},
			{Name: "supports_zero_channel_reserve", Value: "false"}, {Name: "max_channel_expiry_blocks", Value: "12960"},
			{Name: "min_initial_client_balance", Value: "0"}, {Name: "max_initial_client_balance", Value: "1000000"},
			{Name: "min_initial_lsp_balance", Value: "0"}, {Name: "max_initial_lsp_balance", Value: "10000000"},
			{Name: "min_channel_balance", Value: "100000"}, {Name: "max_channel_balance", Value: "10000000"},
		},
		LSPS2: []niplsp.FeeRow{{MinFeeMillis: 2000000, Proportional: 4000, MinLifetime: 4320, MaxClientToSelfDelay: 2016, MinPaymentSizeMillis: 10000000, MaxPaymentSizeMillis: 4000000000}},
		LSPS5: []niplsp.Option{{Name: "max_webhooks", Value: "10"}},
	}
}

// lspSigner is a NodeSigner over key 1 that hashes the payload itself, as a
// node's Schnorr RPC does.
func lspSigner() niplsp.NodeSigner {
	priv, err := utils.ParsePrivateKeyHex(connKey1)
	if err != nil {
		panic(err)
	}
	return func(_ context.Context, payload []byte) ([]byte, error) {
		h := sha256.Sum256(payload)
		sig, err := schnorr.Sign(priv, h[:])
		if err != nil {
			return nil, err
		}
		return sig.Serialize(), nil
	}
}

func lspStep(err error) int {
	var ae *niplsp.AnnouncementError
	if errors.As(err, &ae) {
		return ae.Step
	}
	if err != nil {
		return -1
	}
	return 0
}

func buildLSP() (any, error) {
	client := lspClient{Chains: []string{"bitcoin"}, Networks: []string{"mainnet"}, Now: lspCreated + 86400}
	opts := func(c lspClient) niplsp.CheckOptions {
		return niplsp.CheckOptions{Chains: c.Chains, Networks: c.Networks, Now: c.Now}
	}
	f := lspFile{header: newHeader(
		"NIP-LSP Lightning service provider announcements (kind 10735): K-LSP-1 (the NIP example) and K-LSP-2..6 (closed, and one failure per client step 2-5), ParseAnnouncement cases in step order, ignored tags, the live check (same, worse, better, a missing protocol) and FromLSPSInfo in both unit dialects.",
		"niplsp/*.go; niplsp/parse_test.go, build_test.go, live_test.go, lsps_test.go (K-LSP-1..6)",
	), Client: client}

	build := func(fl niplsp.Fields) nip01.Event {
		ev, err := niplsp.NewAnnouncement(fl, lspCreated)
		if err != nil {
			panic(err)
		}
		if err := niplsp.Sign(context.Background(), ev, lspSigner()); err != nil {
			panic(err)
		}
		return *ev
	}
	k1 := build(lspExampleFields())
	raw := func(edit func([][]string) [][]string) nip01.Event {
		ev := nip01.Event{Kind: niplsp.Kind, CreatedAt: lspCreated, Content: "Inbound channels and just-in-time channels.", Tags: edit(cloneTagList(k1.Tags))}
		if err := ev.Sign(connKey1); err != nil {
			panic(err)
		}
		return ev
	}
	without := func(name string) func([][]string) [][]string {
		return func(t [][]string) [][]string {
			var out [][]string
			for _, tg := range t {
				if tg[0] != name {
					out = append(out, tg)
				}
			}
			return out
		}
	}
	set := func(name string, v ...string) func([][]string) [][]string {
		return func(t [][]string) [][]string {
			for i, tg := range t {
				if tg[0] == name {
					t[i] = append([]string{name}, v...)
					return t
				}
			}
			return t
		}
	}
	plus := func(extra ...[]string) func([][]string) [][]string {
		return func(t [][]string) [][]string { return append(t, extra...) }
	}
	closed := lspExampleFields()
	closed.Status = niplsp.StatusClosed
	dupOption := func(t [][]string) [][]string {
		for i, tg := range t {
			if tg[0] == "lsps1" && tg[1] == "max_channel_balance" {
				return append(t[:i+1], append([][]string{{"lsps1", "max_channel_balance", "20000000"}}, t[i+1:]...)...)
			}
		}
		return t
	}
	kats := []struct {
		id string
		ev nip01.Event
	}{
		{"K-LSP-1", k1},
		{"K-LSP-2", build(closed)},
		{"K-LSP-3", raw(without("network"))},
		{"K-LSP-4", raw(dupOption)},
		{"K-LSP-5", raw(set("expiration", "1795305601"))},
		{"K-LSP-6", raw(set("network", "regtest"))},
	}
	for _, k := range kats {
		_, err := niplsp.ParseAnnouncement(&k.ev, opts(client))
		f.Events = append(f.Events, lspEventCase{k.id, k.ev, lspStep(err)})
	}

	parse := func(name string, ev nip01.Event, c *lspClient) {
		cl := client
		if c != nil {
			cl = *c
		}
		pc := lspParseCase{Name: name, Event: ev, Client: c}
		a, err := niplsp.ParseAnnouncement(&ev, opts(cl))
		pc.Step, pc.Error = lspStep(err), errString(err)
		if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(a.Fields)), &pc.Want)
			pc.Want["shown"], pc.Want["selling"] = a.Shown(), a.Selling()
			pc.Want["nodeIds"] = a.NodeIDs()
			pc.Want["displayTitle"] = a.DisplayTitle()
		}
		f.Parse = append(f.Parse, pc)
	}
	parse("K-LSP-1", k1, nil)
	parse("K-LSP-2: closed is read, not shown", kats[1].ev, nil)
	bad := k1
	bad.Sig = flipHex(bad.Sig)
	parse("step 1: a bad signature", bad, nil)
	tampered := k1
	tampered.Content = "Cheaper than anyone."
	parse("step 1: content changed", tampered, nil)
	for _, c := range []struct {
		name string
		edit func([][]string) [][]string
	}{
		{"step 2: no n", without("n")},
		{"step 2: two n", plus([]string{"n", "bitcoin"})},
		{"step 2: no status", without("status")},
		{"step 2: two expiration", plus([]string{"expiration", "1795305600"})},
		{"step 2: no addr", without("addr")},
		{"step 2: no protocol", without("protocol")},
		{"step 2: protocol 2 without lsps2_fee", without("lsps2_fee")},
		{"step 2: two titles", plus([]string{"title", "Bob"})},
		{"step 2: two p", plus([]string{"p", lPub2})},
		{"step 2 before step 3", func(t [][]string) [][]string { return set("addr", "nowhere")(without("network")(t)) }},
		{"step 3: addr hostname", set("addr", "lsp.example.com:9735")},
		{"step 3: addr port 0", set("addr", "203.0.113.7:0")},
		{"step 3: chain uppercase", set("n", "Bitcoin")},
		{"step 3: unknown network", set("network", "main")},
		{"step 3: unknown status", set("status", "gone")},
		{"step 3: expiration with a leading zero", set("expiration", "01795305600")},
		{"step 3: protocol word", plus([]string{"protocol", "two"})},
		{"step 3: lsps1 number as bool", set("lsps1", "min_required_channel_confirmations", "false")},
		{"step 3: lsps2_fee five positions", set("lsps2_fee", "2000000", "4000", "4320", "2016", "10000000")},
		{"step 3: lsps5 twice", plus([]string{"lsps5", "max_webhooks", "3"})},
		{"step 3: http website", set("website", "http://lsp.example.com")},
		{"step 3: p relay not ws", set("p", lPub2, "https://relay.example.com")},
		{"step 3: l three letters", set("l", "eng", "ISO-639-1")},
		{"ignored: unknown tag, nonce, unknown option and field, other label namespace", plus([]string{"x", "an unknown tag"}, []string{"nonce", "1", "0"},
			[]string{"lsps1", "future_option", "not a number"}, []string{"lsps5", "future_field", "1"}, []string{"L", "other.namespace"}, []string{"l", "anything at all", "other.namespace"})},
		{"ignored: step data of a protocol not listed", func(t [][]string) [][]string {
			return plus([]string{"protocol", "1"}, []string{"lsps5", "max_webhooks", "x"}, []string{"lsps2_fee", "1"})(without("protocol")(t))
		}},
	} {
		parse(c.name, raw(c.edit), nil)
	}
	at := client
	at.Now = lspExpires
	parse("at its expiration", k1, &at)
	after := client
	after.Now = lspExpires + 1
	parse("step 4: a second after its expiration", k1, &after)
	parse("step 5: a chain the client does not use", k1, &lspClient{Chains: []string{"flokicoin"}, Networks: []string{"mainnet"}, Now: client.Now})
	parse("step 5: a network the client does not use", k1, &lspClient{Chains: []string{"bitcoin"}, Networks: []string{"testnet", "regtest"}, Now: client.Now})
	parse("step 4 before step 5", k1, &lspClient{Chains: []string{"flokicoin"}, Networks: []string{"mainnet"}, Now: lspExpires + 1})

	a := must(niplsp.ParseAnnouncement(&k1, opts(client)))
	live := func(name string, protocols []int, l1, l2 string) {
		orNull := func(s string) json.RawMessage {
			if s == "" {
				return json.RawMessage("null")
			}
			return json.RawMessage(s)
		}
		c := lspLiveCase{Name: name, Protocols: protocols, LSPS1: orNull(l1), LSPS2: orNull(l2)}
		l := niplsp.Live{Protocols: protocols}
		if l1 != "" {
			l.LSPS1 = must(niplsp.ParseLSPS1Info(json.RawMessage(l1)))
		}
		if l2 != "" {
			l.LSPS2Menu = must(niplsp.ParseLSPS2Menu(json.RawMessage(l2)))
		}
		d := niplsp.CheckLive(a, l)
		c.MissingProtocol, c.Changed = nonNilInts(d.MissingProtocol), d.Changed()
		if c.Changed == nil {
			c.Changed = []niplsp.FieldDiff{}
		}
		c.Same, c.Worse, c.Usable = d.Same(), d.Worse(), d.Usable()
		f.Live = append(f.Live, c)
	}
	repl := func(s, from, to string) string { return replaceOnce(s, from, to) }
	live("same", []int{1, 2, 5}, lsps1Loki, lsps2Sat)
	live("same, the sat dialect", []int{1, 2, 5}, lsps1Sat, lsps2Loki)
	live("a higher live min_fee: worse", []int{1, 2, 5}, lsps1Sat, repl(lsps2Sat, `"min_fee_msat":"2000000"`, `"min_fee_msat":"2000001"`))
	live("a lower max_channel_balance: worse", []int{1, 2, 5}, repl(lsps1Sat, `"max_channel_balance_sat":"10000000"`, `"max_channel_balance_sat":"5000000"`), lsps2Sat)
	live("a missing protocol: not usable", []int{1, 2}, lsps1Sat, lsps2Sat)
	live("better live values", []int{1, 2, 5}, repl(repl(lsps1Sat, `"max_channel_balance_sat":"10000000"`, `"max_channel_balance_sat":"20000000"`), `"supports_zero_channel_reserve":false`, `"supports_zero_channel_reserve":true`),
		repl(lsps2Sat, `"proportional":4000`, `"proportional":3000`))
	live("only list_protocols asked", []int{1, 2, 5}, "", "")

	ans := func(name, l1, l2, l5 string) {
		c := lspAnswersCase{Name: name, LSPS1: json.RawMessage(l1), LSPS2: json.RawMessage(l2), LSPS5: json.RawMessage(l5)}
		var r5 json.RawMessage
		if l5 != "" {
			r5 = json.RawMessage(l5)
		}
		fl, err := niplsp.FromLSPSInfo([]int{1, 2, 5}, json.RawMessage(l1), json.RawMessage(l2), r5, lspExampleFields().Meta)
		c.Error = errString(err)
		if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(fl)), &c.Fields)
		}
		f.Answers = append(f.Answers, c)
	}
	ans("the sat dialect", lsps1Sat, lsps2Sat, lsps5Ans)
	ans("the loki dialect", lsps1Loki, lsps2Loki, lsps5Ans)
	ans("an unreadable lsps1 answer", `{"min_channel_balance_sat":true}`, lsps2Sat, lsps5Ans)
	return f, nil
}

func cloneTagList(tags [][]string) [][]string {
	out := make([][]string, len(tags))
	for i, t := range tags {
		out[i] = append([]string(nil), t...)
	}
	return out
}

func nonNilInts(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

func replaceOnce(s, from, to string) string {
	if !strings.Contains(s, from) {
		panic("replaceOnce: " + from + " not found")
	}
	return strings.Replace(s, from, to, 1)
}
