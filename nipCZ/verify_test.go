package nipCZ

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

type trustSet map[string]string // x-only → chain

func (s trustSet) TrustsMinter(x, chain string) bool { return s[x] == chain }

type proxyTrust struct {
	trustSet
	proxies map[string]bool
}

func (p proxyTrust) TrustsProxy(signer string) bool { return p.proxies[signer] }

func (f *fx) trust() trustSet { return trustSet{f.minterX: "bitcoin"} }

func firstFailure(v Verdict) int {
	for _, r := range v.Rules {
		if !r.OK && !r.Skipped {
			return r.N
		}
	}
	return 0
}

func TestVerifyClient_Countable(t *testing.T) {
	f := newFx(t)
	for _, useA := range []bool{false, true} {
		target := f.note
		if useA {
			target = f.article
		}
		ev, _ := f.zap(t, zapOpts{target: target, useA: useA})
		v := VerifyClient(ev, target, nil, f.trust())
		if !v.Countable || !v.ZapSigned || !v.ExpiresAtTrusted || v.MinterUnlisted || v.Received() || !SameMinter(v.Minter, f.minterX) {
			t.Fatalf("useA=%v: %+v", useA, v)
		}
		if len(v.Rules) != 8 {
			t.Fatalf("%d rules recorded", len(v.Rules))
		}
	}
	// An a target needs no target event: the coordinate names the author.
	ev, _ := f.zap(t, zapOpts{target: f.article, useA: true})
	if v := VerifyClient(ev, nil, nil, f.trust()); !v.Countable {
		t.Fatalf("%+v", v)
	}
}

// T14-01, rules 4-6.
func TestVerifyClient_Rules4to6(t *testing.T) {
	f := newFx(t)
	no := false
	yes := true
	cases := []struct {
		name string
		o    zapOpts
		rule int
	}{
		{name: "chain mismatch", o: zapOpts{mutate: setTag("chain", "flokicoin")}, rule: 4},
		{name: "TLV 3 = 0", o: zapOpts{idReq: &no}, rule: 5},
		{name: "TLV 3 = 1 passes", o: zapOpts{idReq: &yes}},
		{name: "TLV 6 not amount", o: zapOpts{amount: 21000, mutate: setTag("amount", "22000")}, rule: 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.o.target = f.note
			ev, _ := f.zap(t, c.o)
			v := VerifyClient(ev, f.note, nil, f.trust())
			if got := firstFailure(v); got != c.rule {
				t.Fatalf("first failure rule %d, want %d: %+v", got, c.rule, v)
			}
			if c.rule != 0 && (v.Valid() || v.Countable) {
				t.Fatalf("invalid zap valid: %+v", v)
			}
		})
	}
	t.Run("unknown prefix fails rule 6", func(t *testing.T) {
		// An HRP with no row: rule 4 cannot mismatch, rule 6 has no prefix.
		_, s := f.token(t, tokenOpts{hrp: "zzzcash", scheme: nipcash.SchemeMintV1})
		tok, _ := nipcash.Decode(s)
		ev, _ := f.zap(t, zapOpts{target: f.note, mutate: chain(setTag("cash", s), setTag("w", tok.WalletPubkey))})
		v := VerifyClient(ev, f.note, nil, f.trust())
		if got := firstFailure(v); got != 6 {
			t.Fatalf("first failure rule %d: %+v", got, v)
		}
	})
}

// T14-02 (verdict half).
func TestVerifyClient_SignatureFirst(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note})
	ev.Tags = append(ev.Tags, []string{"x", "added after signing"})
	calls := 0
	orig := decodeToken
	decodeToken = func(s string) (nipcash.Token, error) { calls++; return orig(s) }
	defer func() { decodeToken = orig }()
	v := VerifyClient(ev, f.note, nil, f.trust())
	if firstFailure(v) != 1 || v.Valid() || v.Minter != "" || calls != 0 {
		t.Fatalf("calls=%d %+v", calls, v)
	}
	if w := VerifyWallet(context.Background(), ev, nil, f.trust(), true, func(context.Context, *CashZap) error {
		t.Fatal("rule 9 dialled for a bad signature")
		return nil
	}); w.Valid() || calls != 0 {
		t.Fatalf("%+v", w)
	}
}

// T14-03: rule 7 (S-CZ-17..22, 26).
func TestVerifyClient_Rule7(t *testing.T) {
	f := newFx(t)
	other := newFx(t)
	otherNote, _ := nip01.NewSignedEvent(1, "other", f.recipPriv)
	otherNote.CreatedAt = f.note.CreatedAt
	_ = otherNote.Sign(f.recipPriv)

	countable := func(ev, target *nip01.Event) Verdict {
		return VerifyClient(ev, target, nil, f.trust())
	}
	t.Run("a present: payload over a", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.article, useA: true})
		if v := countable(ev, f.article); !v.Countable {
			t.Fatalf("%+v", v)
		}
		// Signed over the e id, then an a tag added: the rebuilt payload is over a.
		ev, _ = f.zap(t, zapOpts{target: f.article, useA: true, ctxTarget: f.article.ID})
		if v := countable(ev, f.article); v.Countable || !v.MinterUnlisted || v.ExpiresAtTrusted {
			t.Fatalf("signed over e, a added: %+v", v)
		}
	})
	t.Run("re-tagged copies", func(t *testing.T) {
		// Another signer re-publishing the token.
		ev, _ := f.zap(t, zapOpts{target: f.note, ctxSender: f.sender, signer: other.senderPriv})
		if v := countable(ev, f.note); v.Countable {
			t.Fatalf("other signer: %+v", v)
		}
		// Re-tagged to another e.
		ev, _ = f.zap(t, zapOpts{target: otherNote, ctxTarget: f.note.ID})
		if v := countable(ev, otherNote); v.Countable {
			t.Fatalf("other e: %+v", v)
		}
		// Re-tagged to another p.
		ev, _ = f.zap(t, zapOpts{target: f.note, ctxRecip: f.recip, recipient: other.recip})
		if v := countable(ev, f.note); v.Countable {
			t.Fatalf("other p: %+v", v)
		}
	})
	t.Run("e and a naming different events", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.article, useA: true, mutate: setTag("e", f.note.ID)})
		v := countable(ev, f.article)
		if v.Countable || firstFailure(v) != 2 {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("e and a on another author's event: valid, not counted", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: other.article, useA: true})
		v := countable(ev, other.article)
		if !v.Valid() || v.Countable || firstFailure(v) != 7 {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("issued before its target", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note, issuedAt: f.note.CreatedAt - 1})
		if v := countable(ev, f.note); v.Countable || firstFailure(v) != 7 {
			t.Fatalf("%+v", v)
		}
		// On an a target the created_at check does not apply.
		ev, _ = f.zap(t, zapOpts{target: f.article, useA: true, issuedAt: f.article.CreatedAt - 1})
		if v := countable(ev, f.article); !v.Countable {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("p not the target's author", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: other.note, recipient: f.recip})
		if v := countable(ev, other.note); v.Countable || firstFailure(v) != 7 {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("signer not the bill's pubkey", func(t *testing.T) {
		// The Hub signed the bill to sender A; B publishes it as their own zap.
		ev, _ := f.zap(t, zapOpts{target: f.note, signer: other.senderPriv, ctxSender: f.sender})
		v := countable(ev, f.note)
		if v.Countable || SameMinter(v.Minter, f.minterX) {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("e only without the target event", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note})
		if v := countable(ev, nil); v.Countable || firstFailure(v) != 7 {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("scheme 1 token: valid, never countable", func(t *testing.T) {
		ev, _ := f.zap(t, zapOpts{target: f.note, scheme: nipcash.SchemeMintV1})
		v := countable(ev, f.note)
		if !v.Valid() || v.Countable || v.ZapSigned || v.ExpiresAtTrusted {
			t.Fatalf("%+v", v)
		}
	})
}

// T14-04: rule 8 (S-CZ-11..13, 15, 55).
func TestVerifyClient_Rule8(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note})
	c02, c03 := compressed(f.minterX)
	listed := func(tags ...[]string) *CashZapInfo {
		i, err := ParseCashZapInfo(signInfo(t, f.recipPriv, tags...))
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	cases := []struct {
		name  string
		info  *CashZapInfo
		trust Trust
		want  bool
	}{
		{name: "trusted by the reader", trust: f.trust(), want: true},
		{name: "trusted for another chain", trust: trustSet{f.minterX: "flokicoin"}},
		{name: "a get_info pubkey K in the reader's trust", trust: trustSet{f.minterX: "bitcoin"}, want: true},
		{name: "listed 02", info: listed([]string{"mint", c02, "bitcoin"}), want: true},
		{name: "listed 03", info: listed([]string{"mint", c03, "bitcoin"}), want: true},
		{name: "listed for another chain only", info: listed([]string{"mint", c02, "flokicoin"})},
		{name: "10522 without chain lists it", info: listed([]string{"mint", c02, "bitcoin"}), want: true},
		{name: "mint without a chain is ignored", info: listed([]string{"mint", c02})},
		{name: "mint for an unaccepted chain is ignored", info: listed([]string{"chain", "flokicoin"}, []string{"mint", c02, "bitcoin"})},
		{name: "no 10522, no trust"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := VerifyClient(ev, f.note, c.info, c.trust)
			if v.Countable != c.want || v.MinterUnlisted == c.want {
				t.Fatalf("%+v", v)
			}
		})
	}
	t.Run("someone else's 10522 does not list for p", func(t *testing.T) {
		other := newFx(t)
		i, _ := ParseCashZapInfo(signInfo(t, other.recipPriv, []string{"mint", c02, "bitcoin"}))
		if v := VerifyClient(ev, f.note, i, nil); v.Countable {
			t.Fatalf("%+v", v)
		}
	})
}

// T14-06: the rule 9 hook (S-CZ-44..46).
func TestVerifyWallet_Rule9(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	ev, _ := f.zap(t, zapOpts{target: f.note})
	status := func(rows ...nipcash.RecipientStatus) func(context.Context, *CashZap) error {
		return func(_ context.Context, z *CashZap) error {
			return CheckStatus(z, &nipcash.CashStatusResult{Recipients: rows})
		}
	}
	mine := nipcash.RecipientStatus{IdentityType: "pubkey", IdentityValue: f.recip, AmountMillis: 21000}

	v := VerifyWallet(ctx, ev, nil, f.trust(), false, status(mine))
	if !v.Received() || v.Countable {
		t.Fatalf("%+v", v)
	}

	// A 1-sat slice of a multi-slice bill without a zap signature: TLV 6 attests
	// the whole wallet, so only rule 9 catches it.
	ev1, _ := f.zap(t, zapOpts{scheme: nipcash.SchemeMintV1, target: f.note})
	slice := mine
	slice.AmountMillis = 1000
	other := nipcash.RecipientStatus{IdentityType: "pubkey", IdentityValue: hexKey(t), AmountMillis: 20000}
	v = VerifyWallet(ctx, ev1, nil, f.trust(), false, status(slice, other))
	if v.Received() {
		t.Fatalf("%+v", v)
	}
	if r, _ := v.Rule(9); !errors.Is(r.Err, ErrRule9Amount) {
		t.Fatalf("%+v", r)
	}

	claimed := mine
	claimed.Claimed = true
	if v := VerifyWallet(ctx, ev, nil, f.trust(), false, status(claimed)); v.Received() {
		t.Fatal("claimed slice received")
	}
	if err := CheckStatus(nil, &nipcash.CashStatusResult{Tombstone: &nipcash.Tombstone{}}); !errors.Is(err, ErrRule9Gone) {
		t.Fatal(err)
	}

	// A ConnectionKey p: a full in-place transfer; RESTRICTED is not received.
	ck := hexKey(t)
	ia := hexKey(t)
	evck, _ := f.zap(t, zapOpts{scheme: nipcash.SchemeMintV1, recipient: ck, mutate: chain(setTag("p", ck, "discord"), addTag("ia", ia))})
	inPlace := func(res *nipcash.CashTransferResult, err error) func(context.Context, *CashZap) error {
		return func(_ context.Context, z *CashZap) error {
			if err != nil {
				return err
			}
			return CheckInPlaceTransfer(z, res)
		}
	}
	if v := VerifyWallet(ctx, evck, nil, f.trust(), false, inPlace(&nipcash.CashTransferResult{AmountMillis: 21000}, nil)); !v.Received() {
		t.Fatalf("%+v", v)
	}
	restricted := errors.New("RESTRICTED: untrusted IA")
	if v := VerifyWallet(ctx, evck, nil, f.trust(), false, inPlace(nil, restricted)); v.Received() {
		t.Fatal("RESTRICTED received")
	}
	if v := VerifyWallet(ctx, evck, nil, f.trust(), false, inPlace(&nipcash.CashTransferResult{AmountMillis: 21000, NewWalletPubkey: hexKey(t)}, nil)); v.Received() {
		t.Fatal("a spin-off counted as in place")
	}

	// A timeout is never spent.
	v = VerifyWallet(ctx, ev, nil, f.trust(), false, func(context.Context, *CashZap) error { return context.DeadlineExceeded })
	r, _ := v.Rule(9)
	if v.Received() || !errors.Is(r.Err, context.DeadlineExceeded) || strings.Contains(r.Reason, "spent") && !strings.Contains(r.Reason, "never spent") {
		t.Fatalf("%+v", r)
	}
}

// T14-09: P is credited only with trust (S-CZ-36).
func TestVerify_ProxySender(t *testing.T) {
	f := newFx(t)
	ck := hexKey(t)
	ev, _ := f.zap(t, zapOpts{target: f.note, mutate: addTag("P", ck, "discord")})
	if v := VerifyClient(ev, f.note, nil, f.trust()); !v.Countable || v.CreditSender {
		t.Fatalf("credited without proxy trust: %+v", v)
	}
	pt := proxyTrust{trustSet: f.trust(), proxies: map[string]bool{f.sender: true}}
	if v := VerifyClient(ev, f.note, nil, pt); !v.CreditSender {
		t.Fatalf("%+v", v)
	}
	for _, m := range []func([][]string) [][]string{addTag("P", ck), addTag("P", strings.ToUpper(ck), "discord")} {
		ev, _ := f.zap(t, zapOpts{target: f.note, mutate: m})
		if v := VerifyClient(ev, f.note, nil, pt); v.CreditSender || v.Valid() {
			t.Fatalf("%+v", v)
		}
	}
}

// T14-10 (S-CZ-11, 43, 49, 50; S-CASH-176), T14-15 (CZ-INFO-02).
func TestVerdict_NotReceivedAndMinterContact(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note})
	v := VerifyClient(ev, f.note, nil, f.trust())
	if v.Received() {
		t.Fatal("a client verdict is received")
	}
	if _, ok := v.Rule(9); ok {
		t.Fatal("a client ran rule 9")
	}

	// Unlisted: neither trusted nor listed for the chain.
	c02, _ := compressed(f.minterX)
	otherChain, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"mint", c02, "flokicoin"}))
	called := false
	hook := func(context.Context, *CashZap) error { called = true; return nil }
	w := VerifyWallet(context.Background(), ev, otherChain, nil, false, hook)
	if !w.MinterUnlisted || w.MayContactMinter(false) || !w.MayContactMinter(true) || called || w.Received() {
		t.Fatalf("%+v", w)
	}
	if r, _ := w.Rule(9); !r.Skipped {
		t.Fatalf("%+v", r)
	}
	// Approved: rule 8 passes, rule 9 runs.
	w = VerifyWallet(context.Background(), ev, otherChain, nil, true, hook)
	if !called || !w.Received() || !w.MinterUnlisted {
		t.Fatalf("%+v", w)
	}
	// Listed for the chain, or trusted: not unlisted.
	listed, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"mint", c02, "bitcoin"}))
	if w := VerifyWallet(context.Background(), ev, listed, nil, false, nil); w.MinterUnlisted || !w.MayContactMinter(false) {
		t.Fatalf("%+v", w)
	}
	if w := VerifyWallet(context.Background(), ev, nil, f.trust(), false, nil); w.MinterUnlisted || w.Received() {
		t.Fatalf("no rule 9 check, yet %+v", w)
	}
}

// T14-12: ExpiresAtTrusted only for a verifying zap signature (S-CZ-37, 52).
func TestVerdict_ExpiresAtTrusted(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note, expiresAt: 1790000000})
	if v := VerifyClient(ev, f.note, nil, f.trust()); !v.ExpiresAtTrusted {
		t.Fatalf("%+v", v)
	}
	if v := VerifyClient(ev, f.note, nil, nil); v.ExpiresAtTrusted {
		t.Fatal("untrusted minter's times trusted")
	}
	ev1, _ := f.zap(t, zapOpts{target: f.note, scheme: nipcash.SchemeMintV1, expiresAt: 1790000000})
	if v := VerifyClient(ev1, f.note, nil, f.trust()); v.ExpiresAtTrusted {
		t.Fatal("scheme 1 times trusted")
	}
	if v := VerifyWallet(context.Background(), ev1, nil, f.trust(), false, nil); v.ExpiresAtTrusted {
		t.Fatal("scheme 1 times trusted by a wallet")
	}
	if v := VerifyWallet(context.Background(), ev, nil, f.trust(), false, nil); !v.ExpiresAtTrusted {
		t.Fatal("wallet")
	}
}

// T14-14: rule 6 in the wallet column fails a token without TLV 8; the zap
// payload label is cash-zap:v1 (K-ZAP-1).
func TestVerifyWallet_NoLegacyProvenance(t *testing.T) {
	f := newFx(t)
	ev, tok := f.zap(t, zapOpts{target: f.note})
	tok.Scheme = nipcash.SchemeNone
	z, err := ParseCashZap(ev)
	if err != nil {
		t.Fatal(err)
	}
	z.Token = tok
	if m, reason := provenance(z); m != "" || !strings.Contains(reason, "TLV 8") {
		t.Fatalf("%q %q", m, reason)
	}
	zc, _ := ZapContextFromEvent(z)
	z.Token.Scheme = nipcash.SchemeZapV1
	payload, err := nipcash.ProvenancePayload(z.Token, &zc)
	if err != nil || !strings.HasPrefix(payload, "cash-zap:v1:satscash:") {
		t.Fatalf("%q %v", payload, err)
	}
}

// T14-10, S-CZ-49: the below-base-fee hint is the wallet's, from cash_status.
func TestBelowRedeemFee(t *testing.T) {
	if !BelowRedeemFee(1000, 1000) || !BelowRedeemFee(999, 1000) || BelowRedeemFee(1001, 1000) {
		t.Fatal("BelowRedeemFee")
	}
}

// T14-10 (S-CZ-50): a relay applies rules 1-6 only.
func TestValidateForRelay(t *testing.T) {
	f := newFx(t)
	ev, _ := f.zap(t, zapOpts{target: f.note, issuedAt: f.note.CreatedAt - 1}) // fails rule 7 only
	if err := ValidateForRelay(ev); err != nil {
		t.Fatalf("rule 7 refused at a relay: %v", err)
	}
	ev, _ = f.zap(t, zapOpts{target: f.note, mutate: setTag("amount", "22000")})
	var re *RuleError
	if err := ValidateForRelay(ev); !errors.As(err, &re) || re.Rule != 6 {
		t.Fatal(err)
	}
}
