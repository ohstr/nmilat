package nipCZ

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
)

func u64(v uint64) *uint64 { return &v }

// zapReply is the reply a Hub gives a zap transfer to f.recip on target.
func (f *fx) zapReply(t *testing.T, target *nip01.Event, issued, expires uint64) *nipcash.CashTransferResult {
	t.Helper()
	zt, _ := ZapTargetFor(target)
	z := &nipcash.ZapContext{Recipient: f.recip, Sender: f.sender, ZapTarget: zt, IssuedAt: issued, ExpiresAt: expires}
	tok, s := f.token(t, tokenOpts{scheme: nipcash.SchemeZapV1, z: z})
	return &nipcash.CashTransferResult{AmountMillis: 21000, IdentityType: "pubkey", IdentityValue: f.recip,
		NewWalletPubkey: tok.WalletPubkey, NewWalletToken: s, IssuedAt: u64(issued), ExpiresAt: u64(expires)}
}

// T14-13 and a full round trip through VerifyClient.
func TestNewCashZap(t *testing.T) {
	f := newFx(t)
	for _, target := range []*nip01.Event{f.note, f.article} {
		issued := target.CreatedAt + 5
		reply := f.zapReply(t, target, issued, 1790000123)
		ev, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: target, Content: "gm", Transfer: reply}, f.senderPriv)
		if err != nil {
			t.Fatal(err)
		}
		z, err := ParseCashZap(ev)
		if err != nil {
			t.Fatal(err)
		}
		if *z.IssuedAt != issued || *z.ExpiresAt != 1790000123 || z.HasExpirationTag || z.Chain != "bitcoin" {
			t.Fatalf("%+v", z)
		}
		if (target == f.article) != (z.A != "") || z.E != target.ID {
			t.Fatalf("e=%q a=%q", z.E, z.A)
		}
		if v := VerifyClient(ev, target, nil, f.trust()); !v.Countable {
			t.Fatalf("%+v", v)
		}
		for _, tg := range ev.Tags {
			if tg[0] == "expiration" {
				t.Fatal("expiration tag written")
			}
		}
	}

	reply := f.zapReply(t, f.note, f.note.CreatedAt, 0)
	bad := *reply
	bad.NewWalletPubkey = hexKey(t)
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: f.note, Transfer: &bad}, f.senderPriv); !errors.Is(err, ErrTokenWallet) {
		t.Fatal(err)
	}
	unsigned := *reply
	unsigned.IssuedAt = nil
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: f.note, Transfer: &unsigned}, f.senderPriv); !errors.Is(err, ErrZapNotSigned) {
		t.Fatal(err)
	}
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: f.note}, f.senderPriv); !errors.Is(err, ErrNoTransferResult) {
		t.Fatal(err)
	}
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: f.note, Transfer: reply, Amount: 1}, f.senderPriv); !errors.Is(err, ErrAmount) {
		t.Fatal(err)
	}
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, Target: f.note, Transfer: reply, Chain: "flokicoin"}, f.senderPriv); err == nil {
		t.Fatal("chain mismatch built")
	}
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: f.recip}, IA: hexKey(t), Target: f.note, Transfer: reply}, f.senderPriv); !errors.Is(err, ErrZapIAForPubkey) {
		t.Fatal(err)
	}

	// A proxy agent's ConnectionKey zap: P and ia, no times on a scheme-1 bill.
	ck, sck, ia := hexKey(t), hexKey(t), hexKey(t)
	tok, s := f.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	ev, err := NewCashZap(CashZapParams{Recipient: Identity{Value: ck, Platform: "discord"}, Sender: &Identity{Value: sck, Platform: "discord"}, IA: ia,
		Transfer: &nipcash.CashTransferResult{AmountMillis: 21000, NewWalletPubkey: tok.WalletPubkey, NewWalletToken: s}}, f.senderPriv)
	if err != nil {
		t.Fatal(err)
	}
	z, err := ParseCashZap(ev)
	if err != nil || z.Sender == nil || z.IA != ia || z.IssuedAt != nil {
		t.Fatalf("%v %+v", err, z)
	}
	if v := VerifyClient(ev, nil, nil, f.trust()); !v.Valid() || v.Countable {
		t.Fatalf("a ConnectionKey zap is listed, never counted: %+v", v)
	}
	if _, err := NewCashZap(CashZapParams{Recipient: Identity{Value: ck, Platform: "discord"}, Transfer: &nipcash.CashTransferResult{NewWalletToken: s}}, f.senderPriv); !errors.Is(err, ErrZapIARequired) {
		t.Fatal(err)
	}
}

// T14-08: sending (S-CZ-14, 18, 25, 27..35, 51).
func TestZapTransfer(t *testing.T) {
	f := newFx(t)
	src := nipcash.BySigning(f.senderPriv)
	wallet := hexKey(t)

	p, err := ZapTransfer(src, true, Identity{Value: f.recip}, "", 21000, f.article)
	if err != nil {
		t.Fatal(err)
	}
	if p.ZapTarget != "30023:"+f.recip+":my:slug" || !nipcash.ValidRequestID(p.RequestID) || *p.SplitAmount != 21000 {
		t.Fatalf("%+v", p)
	}
	req, err := p.Request(wallet)
	if err != nil {
		t.Fatal(err)
	}
	if req.NewIdentity.IdentityType != "pubkey" || req.NewIdentity.IdentityValue != f.recip || *req.AmountMillis != 21000 || *req.ZapTarget != p.ZapTarget || req.RequestID == "" {
		t.Fatalf("pubkey never hashed, amount_millis = zap amount: %+v", req)
	}
	p, _ = ZapTransfer(src, true, Identity{Value: f.recip}, "", 21000, f.note)
	if p.ZapTarget != f.note.ID {
		t.Fatal(p.ZapTarget)
	}
	p, _ = ZapTransfer(src, true, Identity{Value: f.recip}, "", 21000, nil)
	if p.ZapTarget != "" {
		t.Fatal("zap_target without a target")
	}

	if _, err := ZapTransfer(src, false, Identity{Value: f.recip}, "", 21000, f.note); !errors.Is(err, ErrZapNeedsPubkeyBill) {
		t.Fatal(err)
	}
	if _, err := ZapTransfer(src, true, Identity{Value: hexKey(t), Platform: "cash"}, "", 21000, nil); !errors.Is(err, ErrZapCashTarget) {
		t.Fatal(err)
	}
	if _, err := ZapTransfer(src, true, Identity{Value: f.recip}, "", 0, nil); !errors.Is(err, ErrAmount) {
		t.Fatal(err)
	}
	if _, err := ZapTransfer(src, true, Identity{Value: f.recip}, hexKey(t), 21000, nil); !errors.Is(err, ErrZapIAForPubkey) {
		t.Fatal(err)
	}

	// ConnectionKey recipients: canonical discord id; no zap_target; ia required.
	discord, err := IdentityFromTyped(nipIC.PlatformDiscord, "123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := nipIC.NewConnectionKey(nipIC.PlatformDiscord, "123456789012345678")
	if discord.Value != string(want) {
		t.Fatal("discord key not canonical")
	}
	ia1 := hexKey(t)
	if _, err := ZapTransfer(src, true, discord, ia1, 21000, f.note); !errors.Is(err, ErrZapTargetForConnectionKey) {
		t.Fatal(err)
	}
	if _, err := ZapTransfer(src, true, discord, "", 21000, nil); !errors.Is(err, ErrZapIARequired) {
		t.Fatal(err)
	}
	p, err = ZapTransfer(src, true, discord, ia1, 21000, nil)
	if err != nil || p.ZapTarget != "" {
		t.Fatalf("%v %+v", err, p)
	}
	req, err = p.Request(wallet)
	if err != nil || req.NewIdentity.IdentityType != "connection_key" || req.NewIdentity.IAPubkey != ia1 || req.ZapTarget != nil {
		t.Fatalf("%v %+v", err, req)
	}

	// github: no key from typed input; from the attestation, with its IA.
	if _, err := IdentityFromTyped("github", "alice"); !errors.Is(err, nipIC.ErrTypedInputNotCanonical) {
		t.Fatal(err)
	}
	iaPriv, iaPub := keypairFor(t)
	_, iaOther := keypairFor(t)
	att := attestation(t, iaPriv, f.recip, "github", "alice")
	id, gotIA, err := IdentityFromAttestation(att)
	if err != nil || gotIA != iaPub || gotIA == iaOther || id.Platform != "github" {
		t.Fatalf("%v %q %+v", err, gotIA, id)
	}
	key, _ := nipIC.ConnectionKeyFromAttested("github", "alice")
	if id.Value != string(key) {
		t.Fatal("key not taken from the attestation byte for byte")
	}
	p, err = ZapTransfer(src, true, id, gotIA, 21000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req, _ := p.Request(wallet); req.NewIdentity.IAPubkey != iaPub {
		t.Fatal("ia is not the attesting IA")
	}

	// The Nostr pubkey is never hashed into a ConnectionKey.
	if _, err := ZapTransfer(src, true, Identity{Value: f.recip, Platform: "nostr"}, ia1, 21000, nil); err == nil {
		t.Fatal(`"nostr" accepted as a ConnectionKey platform`)
	}

	// A ConnectionKey-bound bill moved first: its own credential refuses zap_target.
	if _, err := ZapTransfer(src, false, Identity{Value: f.recip}, "", 21000, nil); err != nil {
		t.Fatal(err)
	}
}

// T14-08: the plan (S-CZ-14, 51).
func TestPlanSend(t *testing.T) {
	f := newFx(t)
	other := newFx(t)
	now := time.Unix(1_800_000_000, 0)
	listedTok, _ := f.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	unlisted, _ := other.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	loki, _ := f.token(t, tokenOpts{hrp: "lokicash", scheme: nipcash.SchemeMintV1})
	c02, _ := compressed(f.minterX)
	info, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"chain", "bitcoin"}, []string{"mint", c02, "bitcoin"}))

	got, err := PlanSend(info, []nipcash.Token{unlisted, loki, listedTok}, now)
	if err != nil || len(got) != 2 || got[0].WalletPubkey != listedTok.WalletPubkey {
		t.Fatalf("%v %+v", err, got)
	}
	onlyLoki, _ := ParseCashZapInfo(signInfo(t, f.recipPriv, []string{"chain", "flokicoin"}))
	if _, err := PlanSend(onlyLoki, []nipcash.Token{unlisted, listedTok}, now); !errors.Is(err, ErrChainNotAccepted) {
		t.Fatal(err)
	}

	// Longest remaining life first; expired dropped; never beats any date.
	a, _ := other.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	b, _ := other.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	c, _ := other.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	d, _ := other.token(t, tokenOpts{scheme: nipcash.SchemeMintV1})
	cands := []SendCandidate{
		{Token: a, Expiry: nipcash.Expiry{At: now.Unix() + 3600, Present: true}},
		{Token: b, Expiry: nipcash.Expiry{At: now.Unix() + 90*86400, Present: true}},
		{Token: c, Expiry: nipcash.Expiry{At: now.Unix() - 1, Present: true}},
		{Token: d},
	}
	planned, err := PlanSendCandidates(nil, cands, now)
	if err != nil || len(planned) != 3 || planned[0].Token.WalletPubkey != d.WalletPubkey || planned[1].Token.WalletPubkey != b.WalletPubkey {
		t.Fatalf("%v %+v", err, planned)
	}
}
