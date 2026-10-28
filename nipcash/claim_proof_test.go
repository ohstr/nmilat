package nipcash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"
)

const k1Pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func eventID(t *testing.T, kind int, pubkey string, createdAt uint64, tags [][]string) string {
	t.Helper()
	ev := &nip01.Event{Kind: kind, PubKey: pubkey, CreatedAt: createdAt, Tags: tags}
	id, err := ev.HashID()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id)
}

// T06-01 (K-CLAIM-1..4).
func TestT06_01_KClaim(t *testing.T) {
	ones, fours := strings.Repeat("1", 64), strings.Repeat("4", 64)
	redeem := ClaimBinding{Method: MethodCashRedeem, Wallet: ones, Bolt11Hash: fours}
	if id := eventID(t, KindClaimProof, k1Pub, 1720000000, redeem.Tags()); id != "ad995b77237f369c79c5df82729d465eb9b5b4ddafb815995dee99db8d6b07c8" {
		t.Errorf("K-CLAIM-1 %s", id)
	}
	nih := NewIdentityHashOf("pubkey", k1Pub, "")
	if nih != "90aad9efdfc1980322c6248a266df6bca9d766bb360654f5e2bfecccc941bed0" {
		t.Errorf("K-CLAIM-4 %s", nih)
	}
	if neg := sha256Hex("pubkey:" + k1Pub); neg != "7d09e57d9def2934d5cbedff5bad3a5c871ea3bf55a674df919e5eb92fc83df4" || neg == nih {
		t.Errorf("K-CLAIM-4 negative %s", neg)
	}
	amt := uint64(5000)
	transfer := ClaimBinding{Method: MethodCashTransfer, Wallet: ones, NewIdentityHash: nih, AmountMillis: &amt}
	if id := eventID(t, KindClaimProof, k1Pub, 1720000000, transfer.Tags()); id != "c466018a22842f8b79c7447cebf3a023add78ff7d053d8b715205343ae4ad8df" {
		t.Errorf("K-CLAIM-2 %s", id)
	}
	if s, _ := SourcesHash([]string{ones, strings.Repeat("2", 64)}); s != "ca9034371c79ec26ec0496b53420a1117d4f765800dfdce138138b139d591f13" {
		t.Errorf("K-CLAIM-3 %s", s)
	}
}

// T06-02: the builder's tag set per method; empty content; decimal amount.
func TestT06_02_BuilderTags(t *testing.T) {
	w, h := strings.Repeat("1", 64), strings.Repeat("4", 64)
	amt := uint64(7)
	for b, want := range map[*ClaimBinding][]string{
		{Method: MethodCashRedeem, Wallet: w, Bolt11Hash: h}:                                               {"d", "m", "bolt11_hash"},
		{Method: "cash_withdraw", Wallet: w, QuoteID: h}:                                                   {"d", "m", "q"},
		{Method: MethodCashTransfer, Wallet: w, NewIdentityHash: h, AmountMillis: &amt}:                    {"d", "m", "new_identity_hash", "amount_millis"},
		{Method: MethodCashConsolidate, Wallet: w, NewIdentityHash: h, AmountMillis: &amt, SourcesHash: h}: {"d", "m", "new_identity_hash", "amount_millis", "s"},
	} {
		var got []string
		for _, tag := range b.Tags() {
			got = append(got, tag[0])
			if tag[0] == "amount_millis" && tag[1] != "7" {
				t.Errorf("amount %q", tag[1])
			}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v", b.Method, got)
		}
	}
	priv, _ := generateTestKeypair(t)
	_, _, ev, _, _, err := BySigning(priv).buildProof(ClaimBinding{Method: MethodCashRedeem, Wallet: w, Bolt11Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	var e nip01.Event
	_ = json.Unmarshal(ev, &e)
	if e.Content != "" || e.Kind != KindClaimProof {
		t.Errorf("content %q kind %d", e.Content, e.Kind)
	}
}

type claimFixture struct {
	priv, pub string
	wallet    string
	binding   ClaimBinding
	now       time.Time
}

func newClaimFixture(t *testing.T) claimFixture {
	priv, pub := generateTestKeypair(t)
	return claimFixture{priv: priv, pub: pub, wallet: strings.Repeat("1", 64), now: time.Unix(1720000000, 0),
		binding: ClaimBinding{Method: MethodCashRedeem, Wallet: strings.Repeat("1", 64), Bolt11Hash: strings.Repeat("4", 64)}}
}

func (f claimFixture) sign(t *testing.T, kind int, createdAt int64, tags [][]string, content string) string {
	t.Helper()
	ev := &nip01.Event{Kind: kind, CreatedAt: uint64(createdAt), Tags: tags, Content: content}
	if err := ev.Sign(f.priv); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

func (f claimFixture) want() ClaimExpectation {
	return ClaimExpectation{Binding: f.binding, SliceType: identityTypePubkey, SliceValue: f.pub}
}

func isCode(err error, code string) bool {
	var ce *ClaimError
	return errors.As(err, &ce) && ce.Code == code
}

// T06-03, T06-12: the verifier's refusals, each UNAUTHORIZED; it never consumes.
func TestT06_03_VerifyClaimProof(t *testing.T) {
	f := newClaimFixture(t)
	now := f.now.Unix()
	good := f.sign(t, KindClaimProof, now, f.binding.Tags(), "")
	v, err := VerifyClaimProof(good, f.want(), f.now)
	if err != nil || v.Signer != f.pub {
		t.Fatalf("good: %v", err)
	}
	if _, err := VerifyClaimProof(good, f.want(), f.now); err != nil {
		t.Fatal("a verified proof does not verify again: verifying consumed it")
	}
	if ClaimRetainUntil(now) != now+360 {
		t.Error("ClaimRetainUntil")
	}
	for _, c := range []int64{now - 300, now + 60} {
		if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, c, f.binding.Tags(), ""), f.want(), f.now); err != nil {
			t.Errorf("created_at %+d refused: %v", c-now, err)
		}
	}
	tags := func(edit func([][]string) [][]string) [][]string { return edit(f.binding.Tags()) }
	cases := map[string]string{
		"kind 35521":       f.sign(t, 35521, now, f.binding.Tags(), ""),
		"kind 23192":       f.sign(t, 23192, now, f.binding.Tags(), ""),
		"now-301":          f.sign(t, KindClaimProof, now-301, f.binding.Tags(), ""),
		"now+61":           f.sign(t, KindClaimProof, now+61, f.binding.Tags(), ""),
		"content":          f.sign(t, KindClaimProof, now, f.binding.Tags(), "x"),
		"uppercase d":      f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { x[0][1] = strings.ToUpper(strings.Repeat("a", 64)); return x }), ""),
		"missing m":        f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { return append(x[:1], x[2:]...) }), ""),
		"m cash_transfer":  f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { x[1][1] = MethodCashTransfer; return x }), ""),
		"second bolt11":    f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { return append(x, x[2]) }), ""),
		"uppercase bolt11": f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { x[2][1] = strings.Repeat("A", 64); return x }), ""),
		"another wallet":   f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { x[0][1] = strings.Repeat("2", 64); return x }), ""),
		"extra tag":        f.sign(t, KindClaimProof, now, tags(func(x [][]string) [][]string { return append(x, []string{"amount_millis", "1"}) }), ""),
	}
	// An id altered after signing.
	var ev nip01.Event
	_ = json.Unmarshal([]byte(good), &ev)
	ev.ID = strings.Repeat("0", 64)
	altered, _ := json.Marshal(&ev)
	cases["id altered"] = string(altered)
	_ = json.Unmarshal([]byte(good), &ev)
	ev.Sig = strings.Repeat("0", 128)
	badSig, _ := json.Marshal(&ev)
	cases["bad sig"] = string(badSig)
	other, _ := generateTestKeypair(t)
	cases["another signer"] = claimFixture{priv: other}.sign(t, KindClaimProof, now, f.binding.Tags(), "")
	for name, raw := range cases {
		if _, err := VerifyClaimProof(raw, f.want(), f.now); !isCode(err, "UNAUTHORIZED") {
			t.Errorf("%s: %v", name, err)
		}
	}
	consumed := f.want()
	consumed.Consumed = func(id string) bool { return id == v.RecomputedID }
	if _, err := VerifyClaimProof(good, consumed, f.now); !isCode(err, "UNAUTHORIZED") {
		t.Errorf("consumed: %v", err)
	}

	// Transfer amounts and identity hashes.
	amt := uint64(5000)
	tb := ClaimBinding{Method: MethodCashTransfer, Wallet: f.wallet, NewIdentityHash: NewIdentityHashOf("pubkey", f.pub, ""), AmountMillis: &amt}
	tw := ClaimExpectation{Binding: tb, SliceType: identityTypePubkey, SliceValue: f.pub}
	for _, a := range []string{"05000", "+5000", "5000.0", "", "*", "2000"} {
		bad := tb.Tags()
		bad[3][1] = a
		if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, now, bad, ""), tw, f.now); !isCode(err, "UNAUTHORIZED") {
			t.Errorf("amount %q: %v", a, err)
		}
	}
	otherTarget := tb
	otherTarget.NewIdentityHash = NewIdentityHashOf("connection_key", strings.Repeat("9", 64), strings.Repeat("8", 64))
	if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, now, otherTarget.Tags(), ""), tw, f.now); !isCode(err, "UNAUTHORIZED") {
		t.Errorf("another target: %v", err)
	}
	// m for consolidate on a transfer proof.
	asCons := tb.Tags()
	asCons[1][1] = MethodCashConsolidate
	if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, now, asCons, ""), tw, f.now); !isCode(err, "UNAUTHORIZED") {
		t.Errorf("m consolidate on transfer: %v", err)
	}
	// cash_withdraw: d, m, q only.
	q := strings.Repeat("7", 64)
	wb := ClaimBinding{Method: "cash_withdraw", Wallet: f.wallet, QuoteID: q}
	ww := ClaimExpectation{Binding: wb, SliceType: identityTypePubkey, SliceValue: f.pub}
	if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, now, wb.Tags(), ""), ww, f.now); err != nil {
		t.Errorf("withdraw: %v", err)
	}
	for name, tg := range map[string][][]string{
		"no q":        wb.Tags()[:2],
		"two q":       append(wb.Tags(), []string{"q", q}),
		"uppercase q": {{"d", f.wallet}, {"m", "cash_withdraw"}, {"q", strings.ToUpper(strings.Repeat("a", 64))}},
		"bolt11 too":  append(wb.Tags(), []string{"bolt11_hash", q}),
		"other quote": {{"d", f.wallet}, {"m", "cash_withdraw"}, {"q", strings.Repeat("6", 64)}},
	} {
		if _, err := VerifyClaimProof(f.sign(t, KindClaimProof, now, tg, ""), ww, f.now); !isCode(err, "UNAUTHORIZED") {
			t.Errorf("withdraw %s: %v", name, err)
		}
	}
}

// T06-04: connection_key slices.
func TestT06_04_ConnectionKeySlice(t *testing.T) {
	f := newClaimFixture(t)
	iaPriv, iaPub := generateTestKeypair(t)
	now := time.Now()
	att := buildTestAttestation(t, iaPriv, f.pub, testDiscordKey(t), 1)
	attRaw, _ := json.Marshal(att.Event)
	key := string(att.ConnectionKey)
	tagsFor := func(attID string) [][]string {
		return append(f.binding.Tags(), []string{"connection_key", key}, []string{"e", attID})
	}
	want := ClaimExpectation{Binding: f.binding, SliceType: identityTypeConnectionKey, SliceValue: key, SliceIA: iaPub,
		Attestation: string(attRaw), IATrusted: func(string) bool { return true }}
	good := f.sign(t, KindClaimProof, now.Unix(), tagsFor(att.ID), "")
	if _, err := VerifyClaimProof(good, want, now); err != nil {
		t.Fatalf("good: %v", err)
	}
	untrusted := want
	untrusted.IATrusted = func(string) bool { return false }
	if _, err := VerifyClaimProof(good, untrusted, now); !isCode(err, "RESTRICTED") {
		t.Errorf("untrusted IA: %v", err)
	}
	reattest := func(edit func(*nip01.Event), signer string) string {
		ev := att.Copy()
		edit(ev)
		if signer != "" {
			_ = ev.Sign(signer)
		}
		b, _ := json.Marshal(ev)
		return string(b)
	}
	otherIA, _ := generateTestKeypair(t)
	other, _ := generateTestKeypair(t)
	otherPub, _ := utils.GetPublicKey(other)
	drop := func(name string) func(*nip01.Event) {
		return func(ev *nip01.Event) {
			var kept [][]string
			for _, tag := range ev.Tags {
				if tag[0] != name {
					kept = append(kept, tag)
				}
			}
			ev.Tags = kept
		}
	}
	set := func(name, v string) func(*nip01.Event) {
		return func(ev *nip01.Event) {
			for _, tag := range ev.Tags {
				if tag[0] == name {
					tag[1] = v
				}
			}
		}
	}
	for name, raw := range map[string]string{
		"not 35522":     reattest(func(ev *nip01.Event) { ev.Kind = nipIC.KindIdentityConnection }, iaPriv),
		"id mismatch":   reattest(func(ev *nip01.Event) { ev.ID = strings.Repeat("0", 64) }, ""),
		"bad sig":       reattest(func(ev *nip01.Event) { ev.Sig = strings.Repeat("0", 128) }, ""),
		"other author":  reattest(func(*nip01.Event) {}, otherIA),
		"d differs":     reattest(set("d", strings.Repeat("5", 64)), iaPriv),
		"p differs":     reattest(set("p", otherPub), iaPriv),
		"no platform":   reattest(drop("platform"), iaPriv),
		"no evidence":   reattest(drop("evidence"), iaPriv),
		"no expiration": reattest(drop("expiration"), iaPriv),
		"expired":       reattest(set("expiration", "1"), iaPriv),
	} {
		w := want
		w.Attestation = raw
		if _, err := VerifyClaimProof(good, w, now); !isCode(err, "UNAUTHORIZED") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A repeated d, p or expiration is refused even when its last copy is the
	// right one; the claim proof names the re-signed attestation, so only the
	// repeat can fail it.
	for _, name := range []string{"d", "p", "expiration"} {
		ev := att.Copy()
		var first []string
		for _, tag := range ev.Tags {
			if tag[0] == name {
				first = []string{name, map[string]string{"d": strings.Repeat("5", 64), "p": otherPub, "expiration": "1"}[name]}
			}
		}
		ev.Tags = append([][]string{first}, ev.Tags...)
		_ = ev.Sign(iaPriv)
		b, _ := json.Marshal(ev)
		w := want
		w.Attestation = string(b)
		proof := f.sign(t, KindClaimProof, now.Unix(), tagsFor(ev.ID), "")
		if _, err := VerifyClaimProof(proof, w, now); !isCode(err, "UNAUTHORIZED") {
			t.Errorf("%s repeated: %v", name, err)
		}
	}
	noCK := f.sign(t, KindClaimProof, now.Unix(), append(f.binding.Tags(), []string{"e", att.ID}), "")
	if _, err := VerifyClaimProof(noCK, want, now); !isCode(err, "UNAUTHORIZED") {
		t.Errorf("no connection_key: %v", err)
	}
	wrongE := f.sign(t, KindClaimProof, now.Unix(), tagsFor(strings.Repeat("3", 64)), "")
	if _, err := VerifyClaimProof(wrongE, want, now); !isCode(err, "UNAUTHORIZED") {
		t.Errorf("e is not the attestation: %v", err)
	}
	if trusted, err := VerifySliceAttestation(string(attRaw), AttestationExpectation{SliceValue: key, SliceIA: iaPub, Signer: f.pub,
		IATrusted: func(string) bool { return false }}, now.Unix()); err != nil || trusted {
		t.Errorf("VerifySliceAttestation: %v %v", trusted, err)
	}
}

// T06-05: the cheap checks run before the signature: a proof with a bad signature
// and a wrong binding fails on the binding.
func TestT06_05_CheapChecksFirst(t *testing.T) {
	f := newClaimFixture(t)
	tags := f.binding.Tags()
	tags[0][1] = strings.Repeat("2", 64)
	raw := f.sign(t, KindClaimProof, f.now.Unix(), tags, "")
	var ev nip01.Event
	_ = json.Unmarshal([]byte(raw), &ev)
	ev.Sig = strings.Repeat("0", 128)
	b, _ := json.Marshal(&ev)
	_, err := VerifyClaimProof(string(b), f.want(), f.now)
	var ce *ClaimError
	if !errors.As(err, &ce) || !strings.Contains(ce.Reason, "does not match the call") {
		t.Fatalf("got %v, want the binding refusal before any signature work", err)
	}
}

// T06-09, T06-10.
func TestT06_09_FreshAtAndItemSigner(t *testing.T) {
	now := time.Unix(1720000000, 900_000_000)
	if !FreshAt(1720000000-300, now) || FreshAt(1720000000-301, now) || !FreshAt(1720000060, now) || FreshAt(1720000061, now) {
		t.Error("FreshAt bounds")
	}
	v := ClaimVerdict{Signer: k1Pub}
	if !ItemSignerMatchesClaim(k1Pub, v) || ItemSignerMatchesClaim(strings.Repeat("2", 64), v) || ItemSignerMatchesClaim("", ClaimVerdict{}) {
		t.Error("ItemSignerMatchesClaim")
	}
}

// F-CLAIM-1.
func FuzzVerifyClaimProof(f *testing.F) {
	priv := strings.Repeat("0", 63) + "1"
	ev := &nip01.Event{Kind: KindClaimProof, CreatedAt: 1720000000,
		Tags: ClaimBinding{Method: MethodCashRedeem, Wallet: strings.Repeat("1", 64), Bolt11Hash: strings.Repeat("4", 64)}.Tags()}
	_ = ev.Sign(priv)
	good, _ := json.Marshal(ev)
	f.Add(string(good))
	want := ClaimExpectation{Binding: ClaimBinding{Method: MethodCashRedeem, Wallet: strings.Repeat("1", 64), Bolt11Hash: strings.Repeat("4", 64)},
		SliceType: identityTypePubkey, SliceValue: k1Pub}
	now := time.Unix(1720000000, 0)
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := VerifyClaimProof(raw, want, now)
		if err == nil && raw != string(good) {
			var e nip01.Event
			if json.Unmarshal([]byte(raw), &e) != nil || e.ID != ev.ID {
				t.Fatalf("a mutated proof verified: %s", raw)
			}
		}
	})
}

// A transfer or consolidate expectation with no AmountMillis is refused, never
// read as "any amount": a proof for some amount would otherwise pass.
func TestVerifyClaimProof_UnboundAmount(t *testing.T) {
	f := newClaimFixture(t)
	amt := uint64(5000)
	for _, method := range []string{MethodCashTransfer, MethodCashConsolidate} {
		bound := ClaimBinding{Method: method, Wallet: f.wallet, NewIdentityHash: strings.Repeat("3", 64), AmountMillis: &amt,
			SourcesHash: strings.Repeat("5", 64)}
		if method == MethodCashTransfer {
			bound.SourcesHash = ""
		}
		raw := f.sign(t, KindClaimProof, f.now.Unix(), bound.Tags(), "")
		want := ClaimExpectation{Binding: bound, SliceType: identityTypePubkey, SliceValue: f.pub}
		if _, err := VerifyClaimProof(raw, want, f.now); err != nil {
			t.Fatalf("%s bound: %v", method, err)
		}
		want.Binding.AmountMillis = nil
		if _, err := VerifyClaimProof(raw, want, f.now); !errors.Is(err, ErrClaimAmountUnbound) {
			t.Errorf("%s with a nil amount: %v, want ErrClaimAmountUnbound", method, err)
		}
	}
}
