package vectors

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCZ"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

// ---- zap.json (NIP-CZ)

type zapFile struct {
	header
	Keys   map[string]string `json:"keys"`
	Target nip01.Event       `json:"target"`
	Info   []zapInfoCase     `json:"info"`
	Parse  []zapParseCase    `json:"parse"`
	Verify []zapVerifyCase   `json:"verify"`
	Count  []zapCountCase    `json:"count"`
}

type zapInfoCase struct {
	Name    string          `json:"name"`
	Event   nip01.Event     `json:"event"`
	Error   string          `json:"error,omitempty"`
	Accepts map[string]bool `json:"accepts,omitempty"`
	Lists   map[string]bool `json:"listsMinter,omitempty"`
	Relays  []string        `json:"relays,omitempty"`
}

// zapParseCase: ParseCashZap on Event: the rule that fails (0 = parses).
type zapParseCase struct {
	ID    string      `json:"id,omitempty"`
	Name  string      `json:"name"`
	Event nip01.Event `json:"event"`
	Rule  int         `json:"rule"`
	Error string      `json:"error,omitempty"`
}

// zapVerifyCase: VerifyClient(Event, target, the recipient's 10522, the
// reader trusting TrustedMinters): each rule's outcome, the minter, and
// whether the zap counts.
type zapVerifyCase struct {
	Name      string        `json:"name"`
	Event     nip01.Event   `json:"event"`
	WithInfo  bool          `json:"withInfo"`
	Trusted   []string      `json:"trustedMinters"`
	Rules     []zapRuleJSON `json:"rules"`
	Minter    string        `json:"minter"`
	ZapSigned bool          `json:"zapSigned"`
	Countable bool          `json:"countable"`
	Reason    string        `json:"reason,omitempty"`
	Valid     bool          `json:"valid"`
}

type zapRuleJSON struct {
	N       int    `json:"n"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
}

type zapCountCase struct {
	Name     string   `json:"name"`
	Zaps     []string `json:"zaps"` // names of verify cases
	Deleted  []string `json:"deletedBySender"`
	MinLife  int64    `json:"minLifeSeconds"`
	Collapse bool     `json:"collapse"`
	Total    uint64   `json:"total"`
	Counted  []string `json:"counted"`
}

type trustSet map[string]bool

func (t trustSet) TrustsMinter(x, chain string) bool { return t[x+"/"+chain] }

const (
	zMinterKey = "0000000000000000000000000000000000000000000000000000000000000001"
	zRecipKey  = "0000000000000000000000000000000000000000000000000000000000000005"
	zSenderKey = "0000000000000000000000000000000000000000000000000000000000000006"
	zOtherKey  = "0000000000000000000000000000000000000000000000000000000000000007"
)

func buildZap() (any, error) {
	minter := must(utils.GetPublicKey(zMinterKey))
	recip := must(utils.GetPublicKey(zRecipKey))
	sender := must(utils.GetPublicKey(zSenderKey))
	f := zapFile{header: newHeader(
		"NIP-CZ Cash Zaps (kind 9522, cash-zap:v1 tokens): the recipient's 10522, the strict tag rules (K-CZ-1..6) and rules 1-8 of the client verification (a scheme-1 mint bill carries no zap payload; there is no legacy payload), and counting.",
		"nipCZ/{event,verify,count,info}.go; nipCZ/event_test.go, verify_test.go, count_test.go, info_test.go (K-CZ-1..6)",
	), Keys: map[string]string{"minter": minter, "minterSecret": zMinterKey, "recipient": recip, "recipientSecret": zRecipKey, "sender": sender, "senderSecret": zSenderKey}}

	signed := func(priv string, kind int, at uint64, content string, tags ...[]string) nip01.Event {
		ev := nip01.Event{Kind: kind, CreatedAt: at, Content: content, Tags: tags}
		if ev.Tags == nil {
			ev.Tags = [][]string{}
		}
		if err := ev.Sign(priv); err != nil {
			panic(err)
		}
		return ev
	}
	note := signed(zRecipKey, 1, 1720000000, "a note")
	f.Target = note
	c02 := "02" + minter
	info := signed(zRecipKey, 10522, 1720000000, "", []string{"chain", "bitcoin"}, []string{"mint", c02, "bitcoin"}, []string{"relay", "wss://relay.example.com"})
	addInfo := func(name string, ev nip01.Event) {
		c := zapInfoCase{Name: name, Event: ev}
		i, err := nipCZ.ParseCashZapInfo(&ev)
		c.Error = errString(err)
		if err == nil {
			c.Accepts = map[string]bool{"bitcoin": i.Accepts("bitcoin"), "flokicoin": i.Accepts("flokicoin")}
			c.Lists = map[string]bool{minter + "/bitcoin": i.ListsMinter(minter, "bitcoin"), minter + "/flokicoin": i.ListsMinter(minter, "flokicoin")}
			c.Relays = nonNil(i.Relays)
		}
		f.Info = append(f.Info, c)
	}
	addInfo("one chain, one minter", info)
	addInfo("no chain: any chain", signed(zRecipKey, 10522, 1720000000, "", []string{"mint", c02, "flokicoin"}))
	addInfo("a mint for an unaccepted chain, without a chain, x-only: ignored", signed(zRecipKey, 10522, 1720000000, "", []string{"chain", "bitcoin"},
		[]string{"mint", c02, "flokicoin"}, []string{"mint", c02}, []string{"mint", minter, "bitcoin"}))
	addInfo("wrong kind", note)
	infoParsed := must(nipCZ.ParseCashZapInfo(&info))

	// A zap bill signed by the minter for this zap.
	token := func(z nipcash.ZapContext, amount uint64, wallet string) string {
		sign, err := nipcash.LocalMintSigner(zMinterKey, "satscash")
		if err != nil {
			panic(err)
		}
		tok := nipcash.Token{HRP: "satscash", WalletPubkey: wallet, Secret: strings.Repeat("ce", 32), RelayURLs: []string{specRelay1}, AttestedAmountMillis: &amount}
		tok, err = nipcash.SignToken(tok, nipcash.SchemeZapV1, &z, minter, sign)
		if err != nil {
			panic(err)
		}
		return must(nipcash.Encode(tok))
	}
	wallet := strings.Repeat("ab", 32)
	ctx := nipcash.ZapContext{Recipient: recip, Sender: sender, ZapTarget: note.ID, IssuedAt: 1720000060}
	cash := token(ctx, 21000, wallet)
	tags := func() [][]string {
		return [][]string{{"e", note.ID}, {"k", "1"}, {"p", recip}, {"amount", "21000"}, {"chain", "bitcoin"}, {"cash", cash}, {"w", wallet},
			{"issued_at", "1720000060"}, {"expires_at", "0"}}
	}
	zap := func(mod func([][]string) [][]string) nip01.Event {
		t := tags()
		if mod != nil {
			t = mod(t)
		}
		return signed(zSenderKey, nipCZ.KindCashZap, 1720000060, "Great post!", t...)
	}
	set := func(name string, v ...string) func([][]string) [][]string {
		return func(t [][]string) [][]string {
			for i, tg := range t {
				if tg[0] == name {
					t[i] = append([]string{name}, v...)
				}
			}
			return t
		}
	}
	drop := func(name string) func([][]string) [][]string {
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
	add := func(tag ...string) func([][]string) [][]string {
		return func(t [][]string) [][]string { return append(t, tag) }
	}
	parse := func(id, name string, ev nip01.Event) {
		c := zapParseCase{ID: id, Name: name, Event: ev}
		_, err := nipCZ.ParseCashZap(&ev)
		var re *nipCZ.RuleError
		if errors.As(err, &re) {
			c.Rule = re.Rule
		}
		c.Error = errString(err)
		f.Parse = append(f.Parse, c)
	}
	ck := wdCK1
	parse("", "valid", zap(nil))
	parse("K-CZ-1", "issued_at 0", zap(set("issued_at", "0")))
	parse("K-CZ-2", "amount 021000", zap(set("amount", "021000")))
	parse("K-CZ-3", "uppercase w", zap(set("w", strings.ToUpper(wallet))))
	parse("K-CZ-4", "amount 0", zap(set("amount", "0")))
	parse("K-CZ-5", "expires_at 00", zap(set("expires_at", "00")))
	parse("K-CZ-6", "uppercase p", zap(set("p", strings.ToUpper(recip))))
	parse("", "no p", zap(drop("p")))
	parse("", "two p", zap(add("p", sender)))
	parse("", "no amount", zap(drop("amount")))
	parse("", "no chain", zap(drop("chain")))
	parse("", "no cash", zap(drop("cash")))
	parse("", "no w", zap(drop("w")))
	parse("", "two e", zap(add("e", note.ID)))
	parse("", "two k", zap(add("k", "1")))
	parse("", "ia beside a pubkey p", zap(add("ia", sender)))
	parse("", "connection key p without ia", zap(set("p", ck, "discord")))
	parse("", "pubkey P", zap(add("P", ck)))
	parse("", "amount +21000", zap(set("amount", "+21000")))
	parse("", "issued_at 01720000060", zap(set("issued_at", "01720000060")))
	parse("", "a zap bill without issued_at", zap(drop("issued_at")))
	parse("", "a zap bill without expires_at", zap(drop("expires_at")))
	parse("", "w not the token's wallet", zap(set("w", strings.Repeat("cd", 32))))
	parse("", "undecodable cash", zap(set("cash", "satscash1qqqq")))
	bad := zap(nil)
	bad.Sig = flipHex(bad.Sig)
	parse("", "bad signature (rule 1)", bad)
	parse("", "an expiration tag is kept, listed never counted", zap(add("expiration", "1730000000")))

	verdicts := map[string]nipCZ.Verdict{}
	zaps := map[string]*nipCZ.CashZap{}
	verify := func(name string, ev nip01.Event, withInfo bool, trusted ...string) {
		var i *nipCZ.CashZapInfo
		if withInfo {
			i = infoParsed
		}
		tr := trustSet{}
		for _, t := range trusted {
			tr[t+"/bitcoin"] = true
		}
		v := nipCZ.VerifyClient(&ev, &note, i, tr)
		c := zapVerifyCase{Name: name, Event: ev, WithInfo: withInfo, Trusted: nonNil(trusted), Minter: v.Minter, ZapSigned: v.ZapSigned,
			Countable: v.Countable, Reason: v.Reason, Valid: v.Valid()}
		for _, r := range v.Rules {
			c.Rules = append(c.Rules, zapRuleJSON{r.N, r.OK, r.Skipped, r.Reason})
		}
		f.Verify = append(f.Verify, c)
		verdicts[name] = v
		if z, err := nipCZ.ParseCashZap(&ev); err == nil {
			zaps[name] = z
		}
	}
	verify("listed minter: countable", zap(nil), true)
	verify("trusted minter, no 10522: countable", zap(nil), false, minter)
	verify("neither listed nor trusted (rule 8)", zap(nil), false)
	other := token(nipcash.ZapContext{Recipient: recip, Sender: sender, ZapTarget: note.ID, IssuedAt: 1720000061}, 21000, wallet)
	verify("the zap signature over another issued_at: another key recovered (rule 8)", zap(set("cash", other)), true)
	verify("retargeted: another e (rule 7)", zap(set("e", strings.Repeat("0f", 32))), true)
	verify("an expiration tag: listed, never counted", zap(add("expiration", "1730000000")), true)
	resigned := signed(zOtherKey, nipCZ.KindCashZap, 1720000060, "Great post!", tags()...)
	verify("re-signed by another sender: another key recovered (rule 8)", resigned, true)
	exp := token(nipcash.ZapContext{Recipient: recip, Sender: sender, ZapTarget: note.ID, IssuedAt: 1720000060, ExpiresAt: 1720000060 + 3600}, 21000, strings.Repeat("ac", 32))
	verify("amount tag differs from the token's", zap(set("amount", "20000")), true)
	verify("chain tag differs from the token's prefix", zap(set("chain", "flokicoin")), true)
	mint := func() string {
		sign, err := nipcash.LocalMintSigner(zMinterKey, "satscash")
		if err != nil {
			panic(err)
		}
		amt := uint64(21000)
		tok := nipcash.Token{HRP: "satscash", WalletPubkey: wallet, Secret: strings.Repeat("ce", 32), RelayURLs: []string{specRelay1}, AttestedAmountMillis: &amt}
		tok, err = nipcash.SignToken(tok, nipcash.SchemeMintV1, nil, minter, sign)
		if err != nil {
			panic(err)
		}
		return must(nipcash.Encode(tok))
	}()
	verify("a mint bill (scheme 1), no zap payload", zap(set("cash", mint)), true)
	verify("an expiring zap bill", zap(func(t [][]string) [][]string {
		t = set("cash", exp)(t)
		t = set("w", strings.Repeat("ac", 32))(t)
		return set("expires_at", strconv.Itoa(1720000060+3600))(t)
	}), true)

	count := func(name string, names []string, deleted []string, minLife time.Duration, collapse bool) {
		var zs []*nipCZ.CashZap
		var vs []nipCZ.Verdict
		del := map[string]bool{}
		for _, n := range names {
			if z, ok := zaps[n]; ok {
				zs, vs = append(zs, z), append(vs, verdicts[n])
				for _, d := range deleted {
					if d == n {
						del[z.Event.ID] = true
					}
				}
			}
		}
		total, counted := nipCZ.Count(zs, vs, del, minLife, collapse)
		f.Count = append(f.Count, zapCountCase{name, names, nonNil(deleted), int64(minLife / time.Second), collapse, total, nonNil(counted)})
	}
	count("one countable zap", []string{"listed minter: countable"}, nil, 0, false)
	count("two copies of one token count once", []string{"listed minter: countable", "trusted minter, no 10522: countable"}, nil, 0, false)
	count("an uncountable zap adds nothing", []string{"neither listed nor trusted (rule 8)"}, nil, 0, false)
	count("deleted by its sender", []string{"listed minter: countable"}, []string{"listed minter: countable"}, 0, false)
	count("a bill living less than the minimum", []string{"an expiring zap bill"}, nil, 2*time.Hour, false)
	count("a bill living at least the minimum", []string{"an expiring zap bill"}, nil, time.Hour, false)
	return f, nil
}
