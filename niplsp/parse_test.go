package niplsp

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// mainnet is the client of the NIP-LSP example: bitcoin mainnet, a day after
// created_at.
var mainnet = CheckOptions{Chains: []string{"bitcoin"}, Networks: []string{"mainnet"}, Now: exampleCreatedAt + 86400}

// withTags signs the example's content and tags after edit, as key 1.
func withTags(t testing.TB, edit func([][]string) [][]string) *nip01.Event {
	t.Helper()
	return signRaw(t, Kind, exampleCreatedAt, "Inbound channels and just-in-time channels.", edit(cloneTags(exampleTags)))
}

// without drops every tag named name.
func without(name string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		var out [][]string
		for _, t := range tags {
			if t[0] != name {
				out = append(out, t)
			}
		}
		return out
	}
}

// set replaces the value of the first tag named name.
func set(name string, value ...string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		for i, t := range tags {
			if t[0] == name {
				tags[i] = append([]string{name}, value...)
				return tags
			}
		}
		panic("no " + name)
	}
}

// plus appends tags.
func plus(extra ...[]string) func([][]string) [][]string {
	return func(tags [][]string) [][]string { return append(tags, extra...) }
}

func chain(edits ...func([][]string) [][]string) func([][]string) [][]string {
	return func(tags [][]string) [][]string {
		for _, e := range edits {
			tags = e(tags)
		}
		return tags
	}
}

func wantStep(t *testing.T, err error, step int) {
	t.Helper()
	var ae *AnnouncementError
	if !errors.As(err, &ae) || ae.Step != step {
		t.Fatalf("got %v, want a step %d failure", err, step)
	}
}

func TestParseAnnouncementExample(t *testing.T) {
	ev := signed(t, exampleFields(), exampleCreatedAt)
	a, err := ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	want := exampleFields()
	if !reflect.DeepEqual(a.Fields, want) {
		t.Fatalf("fields\n got %+v\nwant %+v", a.Fields, want)
	}
	if a.CreatedAt != exampleCreatedAt || a.Event != ev {
		t.Fatal("header")
	}
	if !a.Shown() || !a.Selling() || a.Expired(exampleExpiration) || !a.Expired(exampleExpiration+1) {
		t.Fatal("status helpers")
	}
	if a.NodeIDs()[1] != "03"+key1Pub {
		t.Fatal("node ids")
	}
	if a.DisplayTitle() != "Alice's Liquidity" || a.DisplayContent() != a.Display.Content {
		t.Fatal("display")
	}
	if v, ok := a.LSPS1Value("max_channel_balance"); !ok || v != "10000000" {
		t.Fatal("LSPS1Value")
	}
	if v, ok := a.LSPS5Value("max_webhooks"); !ok || v != "10" {
		t.Fatal("LSPS5Value")
	}
	if !a.HasProtocol(5) || a.HasProtocol(7) {
		t.Fatal("HasProtocol")
	}

	// The same tags, signed outside the builder, read the same.
	raw := withTags(t, func(tags [][]string) [][]string { return tags })
	if raw.ID != exampleID {
		t.Fatalf("raw id %s", raw.ID)
	}
	if _, err := ParseAnnouncement(raw, mainnet); err != nil {
		t.Fatal(err)
	}
}

// K-LSP-2: the example with status closed parses, and is not shown.
func TestParseAnnouncementClosed(t *testing.T) {
	f := exampleFields()
	f.Status = StatusClosed
	ev := signed(t, f, exampleCreatedAt)
	if ev.ID != kLSP2ID {
		t.Fatalf("K-LSP-2 id %s", ev.ID)
	}
	a, err := ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if a.Shown() || a.Selling() {
		t.Fatal("closed shown or selling")
	}
	f.Status = StatusPaused
	a, err = ParseAnnouncement(signed(t, f, exampleCreatedAt), mainnet)
	if err != nil || !a.Shown() || a.Selling() {
		t.Fatalf("paused: %v", err)
	}
}

// Frozen ids of K-LSP-2..6 (key 1, created_at 1792713600; also computed with
// python3 -I from the same tags).
const (
	kLSP2ID = "4888cfb893cec3cd2ab49f26504f9914e841933a8e3f3e5725eb27313b951158"
	kLSP3ID = "9e63298039c075dc61ff438ff8b642ed7463d15f6d9e10b14f738f9cddf1c0ba"
	kLSP4ID = "b9d668ad9b8dc89a01df7fe8f8c429204e946110c9a8768bafbf76c9503d4b8c"
	kLSP5ID = "c49b0d6188e1829ffd507ee217589a05cd4eeaed22014bcf3a57d41c58b9adff"
	kLSP6ID = "b9601b6f837a62e054285d0b2c62ece02d3db65be8f1d27c2ea107806ed3b974"
)

// kLSP3..6 are the step 2-5 fixtures.
func kLSP3(t testing.TB) *nip01.Event { return withTags(t, without(TagNetwork)) }
func kLSP4(t testing.TB) *nip01.Event {
	return withTags(t, func(tags [][]string) [][]string {
		// a second max_channel_balance right after the first
		for i, tg := range tags {
			if tg[0] == TagLSPS1 && tg[1] == "max_channel_balance" {
				dup := []string{TagLSPS1, "max_channel_balance", "20000000"}
				return append(tags[:i+1], append([][]string{dup}, tags[i+1:]...)...)
			}
		}
		panic("no max_channel_balance")
	})
}
func kLSP5(t testing.TB) *nip01.Event { return withTags(t, set(TagExpiration, "1795305601")) }
func kLSP6(t testing.TB) *nip01.Event { return withTags(t, set(TagNetwork, "regtest")) }

// T23-03..T23-07: one fixture per step, the step reported.
func TestParseAnnouncementSteps(t *testing.T) {
	// T23-03, step 1: a bad signature, another kind, an id that is not the hash.
	ev := signed(t, exampleFields(), exampleCreatedAt)
	bad := ev.Copy()
	bad.Sig = strings.Repeat("0", 128)
	_, err := ParseAnnouncement(bad, mainnet)
	wantStep(t, err, 1)
	other := signRaw(t, 10736, exampleCreatedAt, "", exampleTags)
	_, err = ParseAnnouncement(other, mainnet)
	wantStep(t, err, 1)
	tampered := ev.Copy()
	tampered.Content = "Cheaper than anyone."
	_, err = ParseAnnouncement(tampered, mainnet)
	wantStep(t, err, 1)
	_, err = ParseAnnouncement(nil, mainnet)
	wantStep(t, err, 1)

	// T23-04..T23-07: K-LSP-3..6.
	for _, c := range []struct {
		name string
		ev   *nip01.Event
		id   string
		step int
	}{
		{"K-LSP-3 no network", kLSP3(t), kLSP3ID, 2},
		{"K-LSP-4 lsps1 option twice", kLSP4(t), kLSP4ID, 3},
		{"K-LSP-5 expiration 30 days + 1 s", kLSP5(t), kLSP5ID, 4},
		{"K-LSP-6 regtest for a mainnet client", kLSP6(t), kLSP6ID, 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.ev.ID != c.id {
				t.Errorf("id %s", c.ev.ID)
			}
			_, err := ParseAnnouncement(c.ev, mainnet)
			wantStep(t, err, c.step)
		})
	}
}

func TestParseAnnouncementStepCases(t *testing.T) {
	cases := []struct {
		name string
		edit func([][]string) [][]string
		step int
	}{
		// Step 2: counts.
		{"no n", without(TagChain), 2},
		{"two n", plus([]string{"n", "bitcoin"}), 2},
		{"no status", without(TagStatus), 2},
		{"two expiration", plus([]string{"expiration", "1795305600"}), 2},
		{"no addr", without(TagAddr), 2},
		{"no protocol", without(TagProtocol), 2},
		{"protocol 2 without lsps2_fee", without(TagLSPS2Fee), 2},
		{"two titles", plus([]string{"title", "Bob"}), 2},
		{"two p", plus([]string{"p", key2Pub}), 2},
		{"two alt", plus([]string{"alt", "x"}), 2},
		{"step 2 before step 3", chain(without(TagNetwork), set(TagAddr, "nowhere")), 2},

		// Step 3: forms.
		{"addr hostname", set(TagAddr, "lsp.example.com:9735"), 3},
		{"addr no port", set(TagAddr, "203.0.113.7"), 3},
		{"addr port 0", set(TagAddr, "203.0.113.7:0"), 3},
		{"chain uppercase", set(TagChain, "Bitcoin"), 3},
		{"network", set(TagNetwork, "main"), 3},
		{"status", set(TagStatus, "gone"), 3},
		{"expiration fraction", set(TagExpiration, "1795305600.0"), 3},
		{"expiration leading zero", set(TagExpiration, "01795305600"), 3},
		{"expiration missing value", set(TagExpiration), 3},
		{"protocol word", plus([]string{"protocol", "two"}), 3},
		{"lsps1 number as bool", set(TagLSPS1, "min_required_channel_confirmations", "false"), 3},
		{"lsps1 bool as number", plus([]string{"lsps1", "supports_zero_channel_reserve", "0"}), 3},
		{"lsps1 negative", set(TagLSPS1, "min_required_channel_confirmations", "-1"), 3},
		{"lsps1 no value", set(TagLSPS1, "min_required_channel_confirmations"), 3},
		{"unknown lsps1 option twice", plus([]string{"lsps1", "future", "1"}, []string{"lsps1", "future", "2"}), 3},
		{"lsps2_fee five positions", set(TagLSPS2Fee, "2000000", "4000", "4320", "2016", "10000000"), 3},
		{"lsps2_fee leading zero", set(TagLSPS2Fee, "02000000", "4000", "4320", "2016", "10000000", "4000000000"), 3},
		{"lsps5 twice", plus([]string{"lsps5", "max_webhooks", "3"}), 3},
		{"lsps5 bool", set(TagLSPS5, "max_webhooks", "true"), 3},
		{"http website", set(TagWebsite, "http://lsp.example.com"), 3},
		{"http image", plus([]string{"image", "http://lsp.example.com/logo.png"}), 3},
		{"p not hex", set(TagOperator, "npub1xyz", "wss://relay.example.com"), 3},
		{"p relay not ws", set(TagOperator, key2Pub, "https://relay.example.com"), 3},
		{"l three letters", set(TagLabel, "eng", "ISO-639-1"), 3},
		{"r not ws", set(TagRelay, "https://relay.example.com"), 3},
		{"title without value", set(TagTitle), 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseAnnouncement(withTags(t, c.edit), mainnet)
			wantStep(t, err, c.step)
		})
	}
}

func TestParseAnnouncementTimeAndChain(t *testing.T) {
	ev := signed(t, exampleFields(), exampleCreatedAt)

	o := mainnet
	o.Now = exampleExpiration
	if _, err := ParseAnnouncement(ev, o); err != nil {
		t.Fatalf("at expiration: %v", err)
	}
	o.Now = exampleExpiration + 1
	_, err := ParseAnnouncement(ev, o)
	wantStep(t, err, 4)

	for _, o := range []CheckOptions{
		{Chains: []string{"flokicoin"}, Networks: []string{"mainnet"}, Now: mainnet.Now},
		{Chains: []string{"bitcoin"}, Networks: []string{"testnet", "regtest"}, Now: mainnet.Now},
		{Now: mainnet.Now},
	} {
		_, err := ParseAnnouncement(ev, o)
		wantStep(t, err, 5)
	}

	// created_at at most 15 minutes ahead of the clock.
	o = mainnet
	o.Now = exampleCreatedAt - MaxFutureSecs
	if _, err := ParseAnnouncement(ev, o); err != nil {
		t.Fatalf("created 15 minutes ahead: %v", err)
	}
	o.Now--
	_, err = ParseAnnouncement(ev, o)
	wantStep(t, err, 4)

	// Step 4 before step 5: expired and on a chain the client does not use.
	o = CheckOptions{Chains: []string{"flokicoin"}, Networks: []string{"mainnet"}, Now: exampleExpiration + 1}
	_, err = ParseAnnouncement(ev, o)
	wantStep(t, err, 4)

	// The clock is used when Now is zero: the example expired long before
	// this test runs only if the clock is past 2026-11-21.
	o = CheckOptions{Chains: []string{"bitcoin"}, Networks: []string{"mainnet"}}
	if _, err := ParseAnnouncement(ev, o); err != nil {
		wantStep(t, err, 4)
	}
}

// T23-08: what a client ignores.
func TestParseAnnouncementIgnores(t *testing.T) {
	ev := withTags(t, plus(
		[]string{"x", "an unknown tag"},
		[]string{"nonce", "1", "0"},
		[]string{"lsps1", "future_option", "not a number"},
		[]string{"lsps5", "future_field", "1"},
		[]string{"L", "other.namespace"},
		[]string{"l", "anything at all", "other.namespace"},
		[]string{},
	))
	a, err := ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.LSPS1) != 10 || len(a.LSPS5) != 1 || !reflect.DeepEqual(a.Display.Languages, []string{"en"}) {
		t.Fatalf("unknown options kept: %+v", a.Fields)
	}

	// lsps1, lsps2_fee and lsps5 tags whose protocol is missing are ignored,
	// even malformed or repeated ones.
	ev = withTags(t, chain(
		without(TagProtocol),
		plus([]string{"protocol", "1"},
			[]string{"lsps5", "max_webhooks", "10"},
			[]string{"lsps5", "max_webhooks", "x"},
			[]string{"lsps2_fee", "1"}),
	))
	a, err = ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Protocols, []int{1}) || a.LSPS2 != nil || a.LSPS5 != nil || len(a.LSPS1) != 10 {
		t.Fatalf("protocol-less step data read: %+v", a.Fields)
	}

	// Content over 280 characters is the publisher's fault, not a check: it
	// is cut for display. A protocol given twice is read once.
	long := strings.Repeat("x", 300)
	ev = signRaw(t, Kind, exampleCreatedAt, long, append(cloneTags(exampleTags), []string{"protocol", "1"}))
	a, err = ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if a.Display.Content != long || len(a.DisplayContent()) != MaxContent || len(a.Protocols) != 3 {
		t.Fatal("long content or repeated protocol")
	}
}

func TestDisplayText(t *testing.T) {
	ev := withTags(t, set(TagTitle, "✅ Verified\u200b LSP\nwith a very long title that keeps going on"))
	a, err := ParseAnnouncement(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.DisplayTitle(); got != " Verified LSP with a very long title that"[1:] {
		t.Fatalf("%q", got)
	}
}
