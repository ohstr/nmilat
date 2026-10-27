package nipCZ

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

func wantRule(t *testing.T, err error, n int) {
	t.Helper()
	var re *RuleError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want a rule %d failure", err, n)
	}
	if re.Rule != n {
		t.Fatalf("rule %d failed (%s), want rule %d", re.Rule, re.Reason, n)
	}
}

func TestParseCashZap_Valid(t *testing.T) {
	f := newFx(t)
	ev, tok := f.zap(t, zapOpts{target: f.note})
	z, err := ParseCashZap(ev)
	if err != nil {
		t.Fatal(err)
	}
	if z.Recipient != (Identity{Value: f.recip}) || z.Amount != 21000 || z.W != tok.WalletPubkey || z.E != f.note.ID || z.A != "" || z.K != "1" {
		t.Fatalf("parsed %+v", z)
	}
	if *z.IssuedAt != f.note.CreatedAt+60 || *z.ExpiresAt != 0 || z.HasExpirationTag || z.Sender != nil {
		t.Fatalf("times/flags %+v", z)
	}
}

// T14-01: the rule 2 matrix (S-CZ-03..10, 23) and K-CZ-1..6.
func TestParseCashZap_Rule2Matrix(t *testing.T) {
	f := newFx(t)
	ck := hexKey(t)
	cases := []struct {
		name   string
		o      zapOpts
		rule   int // 0 = parses
		mutate func([][]string) [][]string
	}{
		{name: "no p", mutate: dropTag("p"), rule: 2},
		{name: "two p", mutate: addTag("p", hexKey(t)), rule: 2},
		{name: "no amount", mutate: dropTag("amount"), rule: 2},
		{name: "two amount", mutate: addTag("amount", "21000"), rule: 2},
		{name: "no chain", mutate: dropTag("chain"), rule: 2},
		{name: "two chain", mutate: addTag("chain", "bitcoin"), rule: 2},
		{name: "no cash", mutate: dropTag("cash"), rule: 2},
		{name: "no w", mutate: dropTag("w"), rule: 2},
		{name: "two w", mutate: addTag("w", hexKey(t)), rule: 2},
		{name: "two e", mutate: addTag("e", hexKey(t)), rule: 2},
		{name: "two k", mutate: addTag("k", "1"), rule: 2},
		{name: "two issued_at", mutate: addTag("issued_at", "1760000000"), rule: 2},
		{name: "two P", mutate: chain(addTag("P", hexKey(t), "discord"), addTag("P", hexKey(t), "discord")), rule: 2},
		{name: "ia beside pubkey p", mutate: addTag("ia", hexKey(t)), rule: 2},
		{name: "CK p without ia", mutate: setTag("p", ck, "discord"), rule: 2},
		{name: "uppercase p", mutate: setTag("p", strings.ToUpper(f.recip)), rule: 2},
		{name: "uppercase P", mutate: addTag("P", strings.ToUpper(ck), "discord"), rule: 2},
		{name: "pubkey P", mutate: addTag("P", ck), rule: 2},
		{name: "bad platform", mutate: chain(setTag("p", ck, "Discord"), addTag("ia", hexKey(t))), rule: 2},
		{name: "amount 021000 (K-CZ-2)", mutate: setTag("amount", "021000"), rule: 2},
		{name: "amount +21000", mutate: setTag("amount", "+21000"), rule: 2},
		{name: "amount 21000.0", mutate: setTag("amount", "21000.0"), rule: 2},
		{name: "amount 0 (K-CZ-4)", mutate: setTag("amount", "0"), rule: 2},
		{name: "issued_at 01760000000", mutate: setTag("issued_at", "01760000000"), rule: 2},
		{name: "issued_at 0 (K-CZ-1)", mutate: setTag("issued_at", "0")},
		{name: "expires_at 00 (K-CZ-5)", mutate: setTag("expires_at", "00"), rule: 2},
		{name: "TLV 8 = 2 without issued_at", mutate: dropTag("issued_at"), rule: 2},
		{name: "TLV 8 = 2 without expires_at", mutate: dropTag("expires_at"), rule: 2},
		{name: "w not TLV 0", mutate: setTag("w", hexKey(t)), rule: 2},
		{name: "undecodable cash", mutate: setTag("cash", "satscash1qqqq"), rule: 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := c.o
			o.target = f.note
			o.mutate = c.mutate
			ev, _ := f.zap(t, o)
			_, err := ParseCashZap(ev)
			if c.rule == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRule(t, err, c.rule)
		})
	}

	t.Run("uppercase w (K-CZ-3)", func(t *testing.T) {
		ev, tok := f.zap(t, zapOpts{target: f.note})
		ev, _ = f.zap(t, zapOpts{target: f.note, mutate: setTag("w", strings.ToUpper(tok.WalletPubkey))})
		_, err := ParseCashZap(ev)
		wantRule(t, err, 2)
	})
	t.Run("uppercase p (K-CZ-6)", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note, recipient: f.recip, mutate: setTag("p", strings.ToUpper(f.recip))})
		_, err := ParseCashZap(ev)
		wantRule(t, err, 2)
	})
	t.Run("expires_at 0 ok", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note, expiresAt: 0})
		if _, err := ParseCashZap(ev); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("CK p with ia and nostr platform", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{mutate: chain(setTag("p", ck, "discord"), addTag("ia", hexKey(t)))})
		z, err := ParseCashZap(ev)
		if err != nil {
			t.Fatal(err)
		}
		if !z.Recipient.IsConnectionKey() || z.IA == "" {
			t.Fatalf("%+v", z)
		}
		ev, _ = f.zap(t, zapOpts{target: f.note, mutate: setTag("p", f.recip, "nostr")})
		z, err = ParseCashZap(ev)
		if err != nil || z.Recipient.IsConnectionKey() {
			t.Fatalf("nostr platform: %v %+v", err, z)
		}
	})
	t.Run("NIP-40 expiration is parsed and flagged", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note, mutate: addTag("expiration", "1790000000")})
		z, err := ParseCashZap(ev)
		if err != nil || !z.HasExpirationTag {
			t.Fatalf("%v %+v", err, z)
		}
	})
	t.Run("a authored by someone other than p parses", func(t *testing.T) {
		// Whether e and a name one event is checked against the target, and
		// authorship only decides counting (rule 7): the parse accepts it.
		other := hexKey(t)
		ev, _ := f.zap(t, zapOpts{target: f.article, useA: true, mutate: setTag("a", "30023:"+other+":my:slug")})
		if _, err := ParseCashZap(ev); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("CK p with e and a parses", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.article, useA: true, mutate: chain(setTag("p", ck, "discord"), addTag("ia", hexKey(t)))})
		z, err := ParseCashZap(ev)
		if err != nil || z.E == "" || z.A == "" {
			t.Fatalf("%v %+v", err, z)
		}
	})
	t.Run("wrong kind", func(t *testing.T) {
		if _, err := ParseCashZap(f.note); !errors.Is(err, ErrWrongKind) {
			t.Fatal(err)
		}
	})
}

// T14-02: a bad signature fails rule 1 before any tag is decoded (S-CZ-01, 02).
func TestParseCashZap_SignatureFirst(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note})
	ev.Content = "tampered"
	calls := 0
	orig := decodeToken
	decodeToken = func(s string) (nipcash.Token, error) { calls++; return orig(s) }
	defer func() { decodeToken = orig }()
	_, err := ParseCashZap(ev)
	wantRule(t, err, 1)
	if calls != 0 {
		t.Fatalf("decoded the token %d times before the signature verified", calls)
	}
}

func TestZapTargetFor(t *testing.T) {
	f := newFx(t)
	got, err := ZapTargetFor(f.article)
	if err != nil || got != "30023:"+f.recip+":my:slug" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = ZapTargetFor(f.note)
	if err != nil || got != f.note.ID {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ZapTargetFor(nil); !errors.Is(err, ErrNoTarget) {
		t.Fatal(err)
	}
}

func TestZapContextFromEvent(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.article, useA: true, expiresAt: 1790000000})
	z, err := ParseCashZap(ev)
	if err != nil {
		t.Fatal(err)
	}
	zc, err := ZapContextFromEvent(z)
	if err != nil {
		t.Fatal(err)
	}
	want := nipcash.ZapContext{Recipient: f.recip, Sender: f.sender, ZapTarget: z.A, IssuedAt: *z.IssuedAt, ExpiresAt: 1790000000}
	if zc != want {
		t.Fatalf("%+v want %+v", zc, want)
	}
	ev, _ = f.zap(t, zapOpts{scheme: nipcash.SchemeMintV1})
	z, err = ParseCashZap(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ZapContextFromEvent(z); !errors.Is(err, ErrNoTarget) {
		t.Fatal(err)
	}
}

func TestIdentityConstructors(t *testing.T) {
	id, err := IdentityFromTyped("discord", "123456789")
	if err != nil || id.Platform != "discord" || !isLowerHex(id.Value, 64) {
		t.Fatalf("%+v %v", id, err)
	}
	if _, err := IdentityFromTyped("github", "alice"); err == nil {
		t.Fatal("a platform with no canonical form derived a key from typed input")
	}
	if _, err := PubkeyIdentity(strings.ToUpper(hexKey(t))); !errors.Is(err, ErrIdentity) {
		t.Fatal(err)
	}
}

// F-CZ-1: ParseCashZap never panics.
func FuzzParseCashZap(f *testing.F) {
	f.Add("p", "x", "amount", "1", "cash", "satscash1")
	f.Add("e", "", "a", "1:2:3", "w", strings.Repeat("a", 64))
	f.Fuzz(func(t *testing.T, a, b, c, d, e, g string) {
		ev := &nip01.Event{Kind: KindCashZap, Tags: [][]string{{a, b}, {c, d}, {e, g}, {a}, {}}}
		_, _ = ParseCashZap(ev)
		_, _ = parseCashZap(ev)
		_ = VerifyClient(ev, nil, nil, nil)
		_ = VerifyWallet(context.Background(), ev, nil, nil, true, nil)
	})
}
