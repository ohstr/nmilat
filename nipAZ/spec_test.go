package nipAZ_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"
)

// The T13-xx tests pin NIP-AZ's Verification Algorithm, rule by rule, for
// the LNURL server (ValidateAltZapRequest, ValidateAltZapReceipt) and the
// relay subset (the *ForRelay validators).

const (
	ownEndpoint   = "https://pay.example.com/lnurlp/alice"
	otherEndpoint = "https://pay.example.org/lnurlp/alice"
	githubUserID  = "1234567"
	discordUserID = "80351110224678912"
	testRelay     = "wss://relay.example.com"
	zapAmount     = int64(21000)
)

var (
	senderKey = nip57test.NewKey(1)
	proxyKey  = nip57test.NewKey(2)
	serverKey = nip57test.NewKey(3)
	recvKey   = nip57test.NewKey(4)
	ia1       = nip57test.NewKey(5)
	ia2       = nip57test.NewKey(6)
	ia3       = nip57test.NewKey(7) // never trusted
	aliceKey  = nip57test.NewKey(8)
	malloryKy = nip57test.NewKey(9)

	ownLnurl   = mustLnurl(ownEndpoint)
	otherLnurl = mustLnurl(otherEndpoint)
	githubCK   = mustAttestedKey("github", githubUserID)
	discordCK  = mustAttestedKey("discord", discordUserID)

	serverPolicy = nipAZ.ServerPolicy{
		Chains:      []nipAZ.Chain{"bitcoin"},
		OwnEndpoint: ownEndpoint,
		TrustedIA:   func(ia string) bool { return ia == ia1.Pub || ia == ia2.Pub },
	}
	receiptPolicy = nipAZ.ReceiptPolicy{NostrPubkeyFor: func(u string) (string, error) {
		if u == ownEndpoint {
			return serverKey.Pub, nil
		}
		return "", errors.New("unknown endpoint")
	}}
)

func mustLnurl(u string) string {
	s, err := utils.EncodeLNURL(u)
	if err != nil {
		panic(err)
	}
	return s
}

func mustAttestedKey(platform, id string) string {
	k, err := nipIC.ConnectionKeyFromAttested(nipIC.WebIdentity(platform), id)
	if err != nil {
		panic(err)
	}
	return k.String()
}

// baseRequestTags is a valid request to recvKey on bitcoin; a 9523 carries a
// discord ConnectionKey as its P.
func baseRequestTags(kind int) [][]string {
	tags := [][]string{
		{"p", recvKey.Pub},
		{"amount", "21000"},
		{"chain", "bitcoin"},
		{"lnurl", ownLnurl},
		{"relays", testRelay},
	}
	if kind == nipAZ.KindAltZapOnBehalfRequest {
		tags = append(tags, []string{"P", discordCK, "discord"})
	}
	return tags
}

// setTag replaces every tag named name with value (nil drops them), or
// appends value when there was none.
func setTag(tags [][]string, name string, value []string) [][]string {
	var out [][]string
	done := false
	for _, tag := range tags {
		if tag[0] != name {
			out = append(out, tag)
			continue
		}
		if value != nil && !done {
			out = append(out, value)
			done = true
		}
	}
	if value != nil && !done {
		out = append(out, value)
	}
	return out
}

func signed(t *testing.T, kind int, tags [][]string, key nip57test.Key) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: kind, CreatedAt: 1720000000, Tags: tags, Content: "zap"}
	if err := ev.Sign(key.Priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

func signerFor(kind int) nip57test.Key {
	if kind == nipAZ.KindAltZapOnBehalfRequest {
		return proxyKey
	}
	return senderKey
}

func serverValidate(ev *nip01.Event) error {
	_, err := nipAZ.ValidateAltZapRequest(ev, serverPolicy, zapAmount)
	return err
}

// T13-01: request rule table, server and relay, signature checked first.
func TestT13_01_RequestRuleTable(t *testing.T) {
	ckP := []string{"P", discordCK, "discord"}
	cases := []struct {
		name   string
		kind   int
		edit   func([][]string) [][]string
		server error // nil = accepted
		relay  error
	}{
		{"valid 9520", nipAZ.KindAltZapRequest, nil, nil, nil},
		{"valid 9523", nipAZ.KindAltZapOnBehalfRequest, nil, nil, nil},
		{"unadvertised chain", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return setTag(tg, "chain", []string{"chain", "examplecoin"}) }, nipAZ.ErrChainNotAdvertised, nil},
		{"no chain", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return setTag(tg, "chain", nil) }, nipAZ.ErrMissingChainTag, nipAZ.ErrMissingChainTag},
		{"empty chain", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return setTag(tg, "chain", []string{"chain", ""}) }, nipAZ.ErrMissingChainTag, nipAZ.ErrMissingChainTag},
		{"two chains", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return append(tg, []string{"chain", "examplecoin"}) }, nipAZ.ErrDuplicateTag, nipAZ.ErrDuplicateTag},
		{"no p", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return setTag(tg, "p", nil) }, nip57.ErrRecipientTagCount, nip57.ErrRecipientTagCount},
		{"two p", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return append(tg, []string{"p", aliceKey.Pub}) }, nip57.ErrRecipientTagCount, nip57.ErrRecipientTagCount},
		{"P on 9520", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return append(tg, ckP) }, nipAZ.ErrSenderTagNotAllowed, nipAZ.ErrSenderTagNotAllowed},
		{"no P on 9523", nipAZ.KindAltZapOnBehalfRequest, func(tg [][]string) [][]string { return setTag(tg, "P", nil) }, nipAZ.ErrMissingSenderTag, nipAZ.ErrMissingSenderTag},
		{"two P on 9523", nipAZ.KindAltZapOnBehalfRequest, func(tg [][]string) [][]string { return append(tg, ckP) }, nipAZ.ErrSenderTagCount, nipAZ.ErrSenderTagCount},
		{"two e", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string {
			return append(tg, []string{"e", strings.Repeat("a", 64)}, []string{"e", strings.Repeat("b", 64)})
		}, nip57.ErrTooManyEventTags, nip57.ErrTooManyEventTags},
		{"non-hex e", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return append(tg, []string{"e", strings.Repeat("z", 64)}) }, nip57.ErrInvalidEventTag, nip57.ErrInvalidEventTag},
		{"uppercase e", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string { return append(tg, []string{"e", strings.Repeat("A", 64)}) }, nip57.ErrInvalidEventTag, nip57.ErrInvalidEventTag},
		{"two a", nipAZ.KindAltZapRequest, func(tg [][]string) [][]string {
			return append(tg, []string{"a", "30023:" + aliceKey.Pub + ":x"}, []string{"a", "30023:" + aliceKey.Pub + ":y"})
		}, nipAZ.ErrTooManyATags, nipAZ.ErrTooManyATags},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tags := baseRequestTags(tc.kind)
			if tc.edit != nil {
				tags = tc.edit(tags)
			}
			ev := signed(t, tc.kind, tags, signerFor(tc.kind))
			if err := serverValidate(ev); !matches(err, tc.server) {
				t.Errorf("server: got %v, want %v", err, tc.server)
			}
			if err := nipAZ.ValidateAltZapRequestForRelay(ev); !matches(err, tc.relay) {
				t.Errorf("relay: got %v, want %v", err, tc.relay)
			}
		})
	}

	// Signature first: a broken event fails on its signature even when its
	// tags are broken too.
	ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "p", nil), senderKey)
	ev.Sig = strings.Repeat("0", 128)
	for name, err := range map[string]error{"server": serverValidate(ev), "relay": nipAZ.ValidateAltZapRequestForRelay(ev)} {
		if !errors.Is(err, nip57.ErrInvalidSignature) {
			t.Errorf("%s bad sig: got %v", name, err)
		}
	}
	ev = signed(t, nipAZ.KindAltZapRequest, baseRequestTags(nipAZ.KindAltZapRequest), senderKey)
	ev.Content = "changed after signing"
	if err := serverValidate(ev); !errors.Is(err, nip57.ErrInvalidSignature) {
		t.Errorf("id mismatch: got %v", err)
	}
}

func matches(err, want error) bool {
	if want == nil {
		return err == nil
	}
	return errors.Is(err, want)
}

// T13-02: p/P values and platforms that are refused, never repaired.
func TestT13_02_IdentityTagStrictness(t *testing.T) {
	values := map[string]string{
		"uppercase": strings.ToUpper(recvKey.Pub),
		"63 chars":  recvKey.Pub[:63],
		"65 chars":  recvKey.Pub + "0",
		"npub":      "npub1" + strings.Repeat("q", 58),
		"prefixed":  "discord:" + discordCK[:56],
	}
	for name, v := range values {
		for _, tagName := range []string{"p", "P"} {
			kind := nipAZ.KindAltZapOnBehalfRequest
			tags := setTag(baseRequestTags(kind), tagName, []string{tagName, v, "discord"})
			if tagName == "p" {
				tags = setTag(tags, "p", []string{"p", v})
			}
			ev := signed(t, kind, tags, proxyKey)
			if err := serverValidate(ev); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) {
				t.Errorf("%s %s server: got %v", tagName, name, err)
			}
			if err := nipAZ.ValidateAltZapRequestForRelay(ev); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) {
				t.Errorf("%s %s relay: got %v", tagName, name, err)
			}
		}
	}
	for _, platform := range []string{"Discord", "x:y", "git hub"} {
		tags := setTag(baseRequestTags(nipAZ.KindAltZapRequest), "p", []string{"p", discordCK, platform})
		tags = append(tags, []string{"ia", ia1.Pub})
		ev := signed(t, nipAZ.KindAltZapRequest, tags, senderKey)
		if err := nipAZ.ValidateAltZapRequestForRelay(ev); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) {
			t.Errorf("platform %q: got %v", platform, err)
		}
		if ev.Tags[0][2] != platform {
			t.Errorf("platform %q was rewritten to %q", platform, ev.Tags[0][2])
		}
	}
}

// T13-03: an omitted, empty or "nostr" platform is a native pubkey.
func TestT13_03_OmittedPlatformIsPubkey(t *testing.T) {
	for _, p := range [][]string{{"p", recvKey.Pub}, {"p", recvKey.Pub, ""}, {"p", recvKey.Pub, "nostr"}} {
		ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "p", p), senderKey)
		req, err := nipAZ.ValidateAltZapRequest(ev, serverPolicy, zapAmount)
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		if req.Recipient.WebIdentity() != "" || req.Recipient.Value() != recvKey.Pub {
			t.Errorf("%v: got %+v", p, req.Recipient)
		}
	}
}

// T13-04: the ia tag.
func TestT13_04_IATag(t *testing.T) {
	github := []string{"p", githubCK, "github"}
	discord := []string{"p", discordCK, "discord"}
	iaTag := func(v string) []string { return []string{"ia", v} }
	cases := []struct {
		name   string
		p      []string
		ia     [][]string
		server error
		relay  error
	}{
		{"github without ia", github, nil, nipAZ.ErrIARequired, nipAZ.ErrIARequired},
		{"github with ia", github, [][]string{iaTag(ia1.Pub)}, nil, nil},
		{"two ia", github, [][]string{iaTag(ia1.Pub), iaTag(ia2.Pub)}, nipAZ.ErrInvalidIATag, nipAZ.ErrInvalidIATag},
		{"uppercase ia", github, [][]string{iaTag(strings.ToUpper(ia1.Pub))}, nipAZ.ErrInvalidIATag, nipAZ.ErrInvalidIATag},
		{"pubkey with ia", []string{"p", recvKey.Pub}, [][]string{iaTag(ia1.Pub)}, nipAZ.ErrIANotAllowed, nipAZ.ErrIANotAllowed},
		{"discord without ia", discord, nil, nil, nil},
		{"discord with ia", discord, [][]string{iaTag(ia1.Pub)}, nil, nil},
		{"untrusted ia", github, [][]string{iaTag(ia3.Pub)}, nipAZ.ErrUntrustedIA, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tags := append(setTag(baseRequestTags(nipAZ.KindAltZapRequest), "p", tc.p), tc.ia...)
			ev := signed(t, nipAZ.KindAltZapRequest, tags, senderKey)
			if err := serverValidate(ev); !matches(err, tc.server) {
				t.Errorf("server: got %v, want %v", err, tc.server)
			}
			if err := nipAZ.ValidateAltZapRequestForRelay(ev); !matches(err, tc.relay) {
				t.Errorf("relay: got %v, want %v", err, tc.relay)
			}
		})
	}

	// The receipt copies the request's ia; leaving it out is refused.
	recipient := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")
	req := buildRequest(t, nipAZ.AltZapRequestParams{Recipient: recipient, IA: ia1.Pub})
	f := receiptFor(t, req, zapAmount)
	f.params.IA = ia1.Pub
	receipt, err := nipAZ.NewAltZapReceipt(f.params)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := nipAZ.ValidateAltZapReceipt(receipt, receiptPolicy)
	if err != nil || parsed.IA != ia1.Pub {
		t.Fatalf("receipt ia: %v, %+v", err, parsed)
	}
	f.params.IA = ""
	if _, err := nipAZ.NewAltZapReceipt(f.params); !errors.Is(err, nipAZ.ErrIAMismatch) {
		t.Errorf("receipt without the request's ia: got %v", err)
	}
}

// T13-05: amount strictness and the callback amount.
func TestT13_05_Amount(t *testing.T) {
	for _, a := range []string{"0", "-1000", "1.5", "1e6", "", "+1000", "021000", " 21000", "9223372036854775808"} {
		ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "amount", []string{"amount", a}), senderKey)
		if err := serverValidate(ev); !errors.Is(err, nip57.ErrInvalidAmount) {
			t.Errorf("amount %q server: got %v", a, err)
		}
		if err := nipAZ.ValidateAltZapRequestForRelay(ev); !errors.Is(err, nip57.ErrInvalidAmount) {
			t.Errorf("amount %q relay: got %v", a, err)
		}
	}
	ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "amount", nil), senderKey)
	if err := nipAZ.ValidateAltZapRequestForRelay(ev); !errors.Is(err, nip57.ErrInvalidAmount) {
		t.Errorf("missing amount: got %v", err)
	}
	ev = signed(t, nipAZ.KindAltZapRequest, baseRequestTags(nipAZ.KindAltZapRequest), senderKey)
	for _, cb := range []int64{zapAmount + 1, 0} {
		if _, err := nipAZ.ValidateAltZapRequest(ev, serverPolicy, cb); !errors.Is(err, nip57.ErrAmountMismatch) {
			t.Errorf("callback %d: got %v", cb, err)
		}
	}
}

// T13-06: the lnurl tag, both cases, compared as decoded URLs.
func TestT13_06_Lnurl(t *testing.T) {
	mixed := strings.ToUpper(ownLnurl[:10]) + ownLnurl[10:]
	cases := []struct {
		name   string
		lnurl  []string
		server error
		relay  error
	}{
		{"lowercase", []string{"lnurl", ownLnurl}, nil, nil},
		{"uppercase", []string{"lnurl", strings.ToUpper(ownLnurl)}, nil, nil},
		{"mixed case", []string{"lnurl", mixed}, nip57.ErrInvalidLNURL, nil},
		{"another endpoint", []string{"lnurl", otherLnurl}, nipAZ.ErrLnurlNotOwnEndpoint, nil},
		{"lightning address", []string{"lnurl", "alice@pay.example.com"}, nip57.ErrInvalidLNURL, nil},
		{"missing", nil, nipAZ.ErrMissingLNURLTag, nil},
	}
	for _, tc := range cases {
		ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "lnurl", tc.lnurl), senderKey)
		if err := serverValidate(ev); !matches(err, tc.server) {
			t.Errorf("%s server: got %v, want %v", tc.name, err, tc.server)
		}
		if err := nipAZ.ValidateAltZapRequestForRelay(ev); !matches(err, tc.relay) {
			t.Errorf("%s relay: got %v", tc.name, err)
		}
		// The NIP-57-tolerant path never accepts a missing lnurl.
		if tc.lnurl == nil {
			if _, err := nipAZ.ParseAltZapRequest(ev); !errors.Is(err, nipAZ.ErrMissingLNURLTag) {
				t.Errorf("ParseAltZapRequest accepted a missing lnurl: %v", err)
			}
		}
	}
	// The own endpoint compares after normalising scheme and host case.
	ev := signed(t, nipAZ.KindAltZapRequest, baseRequestTags(nipAZ.KindAltZapRequest), senderKey)
	p := serverPolicy
	p.OwnEndpoint = "HTTPS://PAY.Example.com/lnurlp/alice"
	if _, err := nipAZ.ValidateAltZapRequest(ev, p, zapAmount); err != nil {
		t.Errorf("host case: %v", err)
	}
	p.OwnEndpoint = ""
	if _, err := nipAZ.ValidateAltZapRequest(ev, p, zapAmount); !errors.Is(err, nipAZ.ErrLnurlNotOwnEndpoint) {
		t.Errorf("no own endpoint: %v", err)
	}
}

// T13-07: relays.
func TestT13_07_Relays(t *testing.T) {
	cases := map[string]struct {
		tag  []string
		want error
	}{
		"missing":    {nil, nip57.ErrMissingRelaysTag},
		"https only": {[]string{"relays", "https://relay.example.com"}, nip57.ErrInvalidRelayScheme},
		"empty":      {[]string{"relays"}, nip57.ErrMissingRelaysTag},
	}
	for name, tc := range cases {
		ev := signed(t, nipAZ.KindAltZapRequest, setTag(baseRequestTags(nipAZ.KindAltZapRequest), "relays", tc.tag), senderKey)
		if err := serverValidate(ev); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
		if err := nipAZ.ValidateAltZapRequestForRelay(ev); err != nil {
			t.Errorf("%s relay: %v", name, err)
		}
	}
}

// --- receipts ---

const goodPreimage = "2222222222222222222222222222222222222222222222222222222222222222"

func paymentHash(preimage string) []byte {
	b, _ := hex.DecodeString(preimage)
	sum := sha256.Sum256(b)
	return sum[:]
}

func descHash(desc string) []byte {
	sum := sha256.Sum256([]byte(desc))
	return sum[:]
}

func bolt11(t *testing.T, currency string, amount int64, preimage, desc string) string {
	t.Helper()
	s, err := nip57test.Bolt11(currency, amount, paymentHash(preimage), descHash(desc))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildRequest fills a valid 9520 (or 9523 when p.Sender is set) to the own
// endpoint and returns it.
func buildRequest(t *testing.T, p nipAZ.AltZapRequestParams) *nip01.Event {
	t.Helper()
	if p.Recipient.IsZero() {
		p.Recipient = nipAZ.Pubkey(recvKey.Pub)
	}
	if p.Chain == "" {
		p.Chain = "bitcoin"
	}
	if p.Lnurl == "" {
		p.Lnurl = ownLnurl
	}
	if p.AmountMloki == 0 {
		p.AmountMloki = zapAmount
	}
	if p.Relays == nil {
		p.Relays = []string{testRelay}
	}
	var ev *nip01.Event
	var err error
	if !p.Sender.IsZero() {
		p.PrivateKey = proxyKey.Priv
		sender := p.Sender
		p.Sender = nipAZ.Identity{}
		ev, err = nipAZ.NewAltZapOnBehalfRequest(sender, p)
	} else {
		p.PrivateKey = senderKey.Priv
		ev, err = nipAZ.NewAltZapRequest(p)
	}
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

type receiptFixture struct {
	desc   string
	params nipAZ.AltZapReceiptParams
}

// receiptFor builds receipt params settling req for an invoice of amount.
func receiptFor(t *testing.T, req *nip01.Event, amount int64) receiptFixture {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	desc := string(raw)
	parsed, err := nipAZ.ParseAltZapRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	pre := goodPreimage
	return receiptFixture{desc: desc, params: nipAZ.AltZapReceiptParams{
		PrivateKey: serverKey.Priv, Chain: parsed.Chain, Recipient: parsed.Recipient,
		Sender: parsed.EconomicSender(), IA: parsed.IA, Bolt11: bolt11(t, "bc", amount, goodPreimage, desc),
		Description: desc, Preimage: &pre,
	}}
}

// rawReceipt signs a 9521 with exactly tags, bypassing the builder's checks.
func rawReceipt(t *testing.T, tags [][]string, key nip57test.Key) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: nipAZ.KindAltZapReceipt, CreatedAt: 1720000100, Tags: tags}
	if err := ev.Sign(key.Priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// validReceiptTags is a receipt for a fresh 9520 (or a 9523 when onBehalf).
func validReceiptTags(t *testing.T, onBehalf bool, ia bool) [][]string {
	t.Helper()
	p := nipAZ.AltZapRequestParams{}
	if onBehalf {
		p.Sender = nipAZ.ResolvedConnection(nipAZ.ConnectionKey(discordCK), "discord")
	}
	if ia {
		p.Recipient = nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")
		p.IA = ia1.Pub
	}
	f := receiptFor(t, buildRequest(t, p), zapAmount)
	ev, err := nipAZ.NewAltZapReceipt(f.params)
	if err != nil {
		t.Fatal(err)
	}
	return ev.Tags
}

func tagValue(tags [][]string, name string) string {
	for _, tag := range tags {
		if tag[0] == name {
			return tag[1]
		}
	}
	return ""
}

// T13-08: receipt rules 1-10, LNURL server and relay.
func TestT13_08_ReceiptRules(t *testing.T) {
	base := validReceiptTags(t, false, false)
	desc := tagValue(base, "description")
	withBolt := func(currency string, amount int64, pre, d string) func([][]string) [][]string {
		return func(tg [][]string) [][]string {
			return setTag(tg, "bolt11", []string{"bolt11", bolt11(t, currency, amount, pre, d)})
		}
	}
	withDesc := func(d string) func([][]string) [][]string {
		return func(tg [][]string) [][]string {
			tg = setTag(tg, "description", []string{"description", d})
			return withBolt("bc", zapAmount, goodPreimage, d)(tg)
		}
	}
	signedOther := func(kind int, tags [][]string) string {
		raw, _ := json.Marshal(signed(t, kind, tags, senderKey))
		return string(raw)
	}
	badSig := func() string {
		var ev nip01.Event
		_ = json.Unmarshal([]byte(desc), &ev)
		ev.Content = "tampered"
		raw, _ := json.Marshal(&ev)
		return string(raw)
	}()
	ckP := []string{"P", discordCK, "discord"}

	type rcase struct {
		name   string
		tags   [][]string
		signer nip57test.Key
		server error
		relay  error
	}
	mk := func(name string, edit func([][]string) [][]string, server, relay error) rcase {
		tags := append([][]string(nil), base...)
		if edit != nil {
			tags = edit(tags)
		}
		return rcase{name, tags, serverKey, server, relay}
	}
	cases := []rcase{
		mk("valid", nil, nil, nil),
		mk("missing bolt11", func(tg [][]string) [][]string { return setTag(tg, "bolt11", nil) }, nip57.ErrMissingBolt11Tag, nip57.ErrMissingBolt11Tag),
		mk("missing chain", func(tg [][]string) [][]string { return setTag(tg, "chain", nil) }, nipAZ.ErrMissingChainTag, nipAZ.ErrMissingChainTag),
		mk("missing preimage", func(tg [][]string) [][]string { return setTag(tg, "preimage", nil) }, nipAZ.ErrMissingPreimageTag, nipAZ.ErrMissingPreimageTag),
		mk("wrong preimage", func(tg [][]string) [][]string {
			return setTag(tg, "preimage", []string{"preimage", strings.Repeat("3", 64)})
		}, nipAZ.ErrHashLockMismatch, nipAZ.ErrHashLockMismatch),
		mk("invoice of another network", withBolt("fc", zapAmount, goodPreimage, desc), nipAZ.ErrChainMismatch, nipAZ.ErrChainMismatch),
		mk("unknown chain", func(tg [][]string) [][]string { return setTag(tg, "chain", []string{"chain", "examplecoin"}) }, nipAZ.ErrUnknownChain, nipAZ.ErrUnknownChain),
		mk("description not JSON", withDesc("not json"), nip57.ErrInvalidDescriptionJSON, nip57.ErrInvalidDescriptionJSON),
		mk("embedded bad signature", withDesc(badSig), nip57.ErrInvalidEmbeddedRequest, nip57.ErrInvalidEmbeddedRequest),
		mk("embedded 9734", withDesc(signedOther(nip57.KindZapRequest, baseRequestTags(nipAZ.KindAltZapRequest))), nip57.ErrInvalidEmbeddedRequest, nip57.ErrInvalidEmbeddedRequest),
		mk("embedded 9522", withDesc(signedOther(9522, baseRequestTags(nipAZ.KindAltZapRequest))), nip57.ErrInvalidEmbeddedRequest, nip57.ErrInvalidEmbeddedRequest),
		mk("hash != description_hash", withBolt("bc", zapAmount, goodPreimage, desc+" "), nip57.ErrDescriptionHashMismatch, nip57.ErrDescriptionHashMismatch),
		mk("p != embedded", func(tg [][]string) [][]string { return setTag(tg, "p", []string{"p", aliceKey.Pub}) }, nip57.ErrRecipientMismatch, nip57.ErrRecipientMismatch),
		mk("p platform added", func(tg [][]string) [][]string {
			return append(setTag(tg, "p", []string{"p", recvKey.Pub, "discord"}), []string{"ia", ia1.Pub})
		}, nip57.ErrRecipientMismatch, nip57.ErrRecipientMismatch),
		mk("missing p", func(tg [][]string) [][]string { return setTag(tg, "p", nil) }, nip57.ErrMissingRecipientTag, nip57.ErrMissingRecipientTag),
		mk("chain != embedded", func(tg [][]string) [][]string {
			return withBolt("fc", zapAmount, goodPreimage, desc)(setTag(tg, "chain", []string{"chain", "flokicoin"}))
		}, nipAZ.ErrChainMismatch, nipAZ.ErrChainMismatch),
		mk("ia added", func(tg [][]string) [][]string { return append(tg, []string{"ia", ia1.Pub}) }, nipAZ.ErrIAMismatch, nipAZ.ErrIAMismatch),
		mk("9520 receipt P names another", func(tg [][]string) [][]string { return setTag(tg, "P", []string{"P", aliceKey.Pub}) }, nipAZ.ErrSenderMismatch, nipAZ.ErrSenderMismatch),
		mk("9520 receipt without P", func(tg [][]string) [][]string { return setTag(tg, "P", nil) }, nil, nil),
		mk("invoice amount != request", withBolt("bc", zapAmount+1, goodPreimage, desc), nip57.ErrAmountMismatch, nip57.ErrAmountMismatch),
		mk("amount tag != invoice", func(tg [][]string) [][]string { return setTag(tg, "amount", []string{"amount", "21001"}) }, nip57.ErrAmountMismatch, nip57.ErrAmountMismatch),
		mk("amount tag malformed", func(tg [][]string) [][]string { return setTag(tg, "amount", []string{"amount", "21000.0"}) }, nip57.ErrInvalidAmount, nip57.ErrInvalidAmount),
		mk("uppercase p", func(tg [][]string) [][]string { return setTag(tg, "p", []string{"p", strings.ToUpper(recvKey.Pub)}) }, nipAZ.ErrInvalidIdentityTag, nipAZ.ErrInvalidIdentityTag),
	}
	other := mk("signer != nostrPubkey", nil, nipAZ.ErrReceiptSigner, nil)
	other.signer = aliceKey
	cases = append(cases, other)

	// 9523: P must equal the embedded P.
	b23 := validReceiptTags(t, true, false)
	cases = append(cases,
		rcase{"9523 valid", b23, serverKey, nil, nil},
		rcase{"9523 P != embedded", setTag(append([][]string(nil), b23...), "P", []string{"P", aliceKey.Pub}), serverKey, nipAZ.ErrSenderMismatch, nipAZ.ErrSenderMismatch},
		rcase{"9523 receipt without P", setTag(append([][]string(nil), b23...), "P", nil), serverKey, nipAZ.ErrSenderMismatch, nipAZ.ErrSenderMismatch},
		rcase{"9523 P handle ignored", setTag(append([][]string(nil), b23...), "P", append(ckP, "alice#0001")), serverKey, nil, nil},
	)
	// ia changed or missing.
	bia := validReceiptTags(t, false, true)
	cases = append(cases,
		rcase{"ia valid", bia, serverKey, nil, nil},
		rcase{"ia changed", setTag(append([][]string(nil), bia...), "ia", []string{"ia", ia2.Pub}), serverKey, nipAZ.ErrIAMismatch, nipAZ.ErrIAMismatch},
		rcase{"ia missing", setTag(append([][]string(nil), bia...), "ia", nil), serverKey, nipAZ.ErrIAMismatch, nipAZ.ErrIAMismatch},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := rawReceipt(t, tc.tags, tc.signer)
			if _, err := nipAZ.ValidateAltZapReceipt(ev, receiptPolicy); !matches(err, tc.server) {
				t.Errorf("server: got %v, want %v", err, tc.server)
			}
			if err := nipAZ.ValidateAltZapReceiptForRelay(ev); !matches(err, tc.relay) {
				t.Errorf("relay: got %v, want %v", err, tc.relay)
			}
		})
	}

	// Rule 1: a forged signature.
	ev := rawReceipt(t, base, serverKey)
	ev.Sig = strings.Repeat("0", 128)
	if _, err := nipAZ.ValidateAltZapReceipt(ev, receiptPolicy); !errors.Is(err, nip57.ErrInvalidSignature) {
		t.Errorf("bad sig: %v", err)
	}
	if err := nipAZ.ValidateAltZapReceiptForRelay(ev); !errors.Is(err, nip57.ErrInvalidSignature) {
		t.Errorf("bad sig relay: %v", err)
	}
	// Rule 10 is never skipped by the strict validator.
	if _, err := nipAZ.ValidateAltZapReceipt(rawReceipt(t, base, serverKey), nipAZ.ReceiptPolicy{}); !errors.Is(err, nipAZ.ErrNostrPubkeyUnknown) {
		t.Errorf("nil NostrPubkeyFor: %v", err)
	}
	// Rule 8: a plain payment of zero.
	plain := [][]string{{"bolt11", bolt11(t, "bc", 0, goodPreimage, "")}, {"chain", "bitcoin"}, {"preimage", goodPreimage}}
	if _, err := nipAZ.ValidateAltZapReceipt(rawReceipt(t, plain, serverKey), receiptPolicy); !errors.Is(err, nipAZ.ErrInvalidInvoiceAmount) {
		t.Errorf("plain zero: %v", err)
	}
	plain[0] = []string{"bolt11", bolt11(t, "bc", 5000, goodPreimage, "")}
	if _, err := nipAZ.ValidateAltZapReceipt(rawReceipt(t, plain, serverKey), receiptPolicy); err != nil {
		t.Errorf("plain payment: %v", err)
	}
}

// T13-09: description_hash is over the exact received JSON.
func TestT13_09_DescriptionHashExactJSON(t *testing.T) {
	req := buildRequest(t, nipAZ.AltZapRequestParams{})
	compact, _ := json.Marshal(req)
	spaced, _ := json.MarshalIndent(req, " ", "   ")
	f := receiptFor(t, req, zapAmount)
	f.params.Description = string(spaced)
	f.params.Bolt11 = bolt11(t, "bc", zapAmount, goodPreimage, string(spaced))
	ev, err := nipAZ.NewAltZapReceipt(f.params)
	if err != nil {
		t.Fatal(err)
	}
	if tagValue(ev.Tags, "description") != string(spaced) {
		t.Fatal("description re-serialised")
	}
	if _, err := nipAZ.ValidateAltZapReceipt(ev, receiptPolicy); err != nil {
		t.Fatalf("odd spacing: %v", err)
	}
	reserialised := rawReceipt(t, setTag(ev.Tags, "description", []string{"description", string(compact)}), serverKey)
	if _, err := nipAZ.ValidateAltZapReceipt(reserialised, receiptPolicy); !errors.Is(err, nip57.ErrDescriptionHashMismatch) {
		t.Errorf("re-serialised: %v", err)
	}
	if nipAZ.DescriptionHash(string(spaced)) != hex.EncodeToString(descHash(string(spaced))) {
		t.Error("DescriptionHash is not SHA256 of the raw bytes")
	}
}

// T13-10: the economic sender, and handles never identify.
func TestT13_10_EconomicSender(t *testing.T) {
	sender := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(discordCK), "discord")
	on := buildRequest(t, nipAZ.AltZapRequestParams{Sender: sender})
	req, err := nipAZ.ValidateAltZapRequest(on, serverPolicy, zapAmount)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.EconomicSender(); got.Value() != discordCK || got.WebIdentity() != "discord" || got.Value() == proxyKey.Pub {
		t.Errorf("9523 economic sender: %+v", got)
	}
	direct, err := nipAZ.ParseAltZapRequest(buildRequest(t, nipAZ.AltZapRequestParams{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := direct.EconomicSender(); got.Value() != senderKey.Pub || got.WebIdentity() != "" {
		t.Errorf("9520 economic sender: %+v", got)
	}
	// A handle on the receipt neither changes nor establishes identity.
	f := receiptFor(t, on, zapAmount)
	f.params.Sender = sender.WithHandle("mallory")
	ev, err := nipAZ.NewAltZapReceipt(f.params)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nipAZ.ValidateAltZapReceipt(ev, receiptPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if r.Sender.Value() != discordCK || r.Sender.Handle() != "mallory" {
		t.Errorf("receipt sender: %+v", r.Sender)
	}
}

// T13-11: SupportsAltZap.
func TestT13_11_SupportsAltZap(t *testing.T) {
	meta := `[["text/plain","pay alice"],["chain/examplecoin","examplecoin"],["chain/bitcoin","bitcoin"]]`
	if chains, ok := nipAZ.SupportsAltZap(utils.PayResponse{AllowsNostr: true, Metadata: meta}); !ok || !slices.Equal(chains, []nipAZ.Chain{"examplecoin", "bitcoin"}) {
		t.Errorf("AltZap endpoint: %v %v", chains, ok)
	}
	for name, pr := range map[string]utils.PayResponse{
		"allowsNostr without chain": {AllowsNostr: true, Metadata: `[["text/plain","x"]]`, Chains: []string{"bitcoin"}},
		"chain without allowsNostr": {Metadata: meta},
		"malformed metadata":        {AllowsNostr: true, Metadata: `chain/bitcoin`},
		"empty chain name":          {AllowsNostr: true, Metadata: `[["chain/",""]]`},
	} {
		if _, ok := nipAZ.SupportsAltZap(pr); ok {
			t.Errorf("%s: reported as AltZap", name)
		}
	}
}

// T13-12: the kind set, never a range.
func TestT13_12_KindSet(t *testing.T) {
	for _, kind := range []int{nipAZ.KindAltZapReceipt, 9522, 9524, nip57.KindZapRequest} {
		ev := signed(t, kind, baseRequestTags(nipAZ.KindAltZapRequest), senderKey)
		if err := serverValidate(ev); !errors.Is(err, nip57.ErrWrongKind) {
			t.Errorf("kind %d at the callback: %v", kind, err)
		}
		if err := nipAZ.ValidateAltZapRequestForRelay(ev); !errors.Is(err, nip57.ErrWrongKind) {
			t.Errorf("kind %d relay: %v", kind, err)
		}
	}
	ev := signed(t, 9522, baseRequestTags(nipAZ.KindAltZapRequest), senderKey)
	if err := nipAZ.ValidateAltZapReceiptForRelay(ev); !errors.Is(err, nip57.ErrWrongKind) {
		t.Errorf("9522 as a receipt: %v", err)
	}
}

// T13-13: builders.
func TestT13_13_Builders(t *testing.T) {
	if _, err := nipAZ.Connection("nostr", recvKey.Pub); err == nil {
		t.Error("a pubkey was hashed into a ConnectionKey")
	}
	if _, err := nipAZ.Connection("github", githubUserID); !errors.Is(err, nipIC.ErrTypedInputNotCanonical) {
		t.Errorf("github from typed input: %v", err)
	}
	if id, err := nipAZ.Connection("discord", discordUserID); err != nil || id.Value() != discordCK {
		t.Errorf("discord typed id: %v %v", id, err)
	}
	base := nipAZ.AltZapRequestParams{PrivateKey: senderKey.Priv, Chain: "bitcoin", Lnurl: ownLnurl, AmountMloki: zapAmount, Relays: []string{testRelay}}
	github := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")
	cases := []struct {
		name string
		edit func(*nipAZ.AltZapRequestParams)
		want error
	}{
		{"uppercase pubkey", func(p *nipAZ.AltZapRequestParams) { p.Recipient = nipAZ.Pubkey(strings.ToUpper(recvKey.Pub)) }, nipAZ.ErrInvalidIdentityTag},
		{"bad platform", func(p *nipAZ.AltZapRequestParams) {
			p.Recipient = nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "GitHub")
		}, nipAZ.ErrInvalidIdentityTag},
		{"github without ia", func(p *nipAZ.AltZapRequestParams) { p.Recipient = github }, nipAZ.ErrIARequired},
		{"github with ia", func(p *nipAZ.AltZapRequestParams) { p.Recipient, p.IA = github, ia1.Pub }, nil},
		{"pubkey with ia", func(p *nipAZ.AltZapRequestParams) { p.Recipient, p.IA = nipAZ.Pubkey(recvKey.Pub), ia1.Pub }, nipAZ.ErrIANotAllowed},
		{"zero amount", func(p *nipAZ.AltZapRequestParams) { p.Recipient, p.AmountMloki = nipAZ.Pubkey(recvKey.Pub), 0 }, nip57.ErrInvalidAmount},
		{"lightning address", func(p *nipAZ.AltZapRequestParams) {
			p.Recipient, p.Lnurl = nipAZ.Pubkey(recvKey.Pub), "alice@example.com"
		}, nip57.ErrInvalidLNURL},
		{"no relays", func(p *nipAZ.AltZapRequestParams) { p.Recipient, p.Relays = nipAZ.Pubkey(recvKey.Pub), nil }, nip57.ErrMissingRelaysTag},
	}
	for _, tc := range cases {
		p := base
		tc.edit(&p)
		ev, err := nipAZ.NewAltZapRequest(p)
		if !matches(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if err != nil && ev != nil {
			t.Errorf("%s: an event came back with the error", tc.name)
		}
	}
	upperSender := nipAZ.Pubkey(strings.ToUpper(senderKey.Pub))
	p := base
	p.Recipient = nipAZ.Pubkey(recvKey.Pub)
	if _, err := nipAZ.NewAltZapOnBehalfRequest(upperSender, p); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) {
		t.Errorf("uppercase P: %v", err)
	}
}

// T13-14: the relay keeps a receipt whose embedded request breaks a rule
// only the LNURL server enforces (a lightning address in lnurl).
func TestT13_14_RelayKeepsServerOnlyFailure(t *testing.T) {
	tags := setTag(baseRequestTags(nipAZ.KindAltZapRequest), "lnurl", []string{"lnurl", "alice@pay.example.com"})
	req := signed(t, nipAZ.KindAltZapRequest, tags, senderKey)
	raw, _ := json.Marshal(req)
	desc := string(raw)
	receipt := rawReceipt(t, [][]string{
		{"bolt11", bolt11(t, "bc", zapAmount, goodPreimage, desc)},
		{"chain", "bitcoin"},
		{"preimage", goodPreimage},
		{"p", recvKey.Pub},
		{"P", senderKey.Pub},
		{"description", desc},
		{"amount", "21000"},
	}, serverKey)
	if err := nipAZ.ValidateAltZapReceiptForRelay(receipt); err != nil {
		t.Fatalf("relay refused: %v", err)
	}
	if _, err := nipAZ.ValidateAltZapReceipt(receipt, receiptPolicy); !errors.Is(err, nip57.ErrInvalidLNURL) {
		t.Errorf("server accepted: %v", err)
	}
}
