package nipCZ

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

func (f *fx) parsed(t *testing.T, ev *nip01.Event) *CashZap {
	t.Helper()
	z, err := ParseCashZap(ev)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// T14-07 (S-CZ-15, 24, 37..42, 53, 54).
func TestCount(t *testing.T) {
	f := newFx(t)
	day := uint64(86400)
	issued := f.note.CreatedAt + 60
	mk := func(o zapOpts) (*CashZap, Verdict) {
		if o.target == nil {
			o.target = f.note
		}
		ev, _ := f.zap(t, o)
		return f.parsed(t, ev), VerifyClient(ev, o.target, nil, f.trust())
	}
	long, vLong := mk(zapOpts{issuedAt: issued, expiresAt: issued + 40*day})
	short, vShort := mk(zapOpts{issuedAt: issued, expiresAt: issued + 2*day})
	never, vNever := mk(zapOpts{issuedAt: issued, expiresAt: 0})

	total, ids := Count([]*CashZap{long, short, never}, []Verdict{vLong, vShort, vNever}, nil, 30*24*time.Hour, false)
	if total != 42000 || len(ids) != 2 {
		t.Fatalf("30 d: %d %v", total, ids)
	}
	if total, _ := Count([]*CashZap{long, short, never}, []Verdict{vLong, vShort, vNever}, nil, 24*time.Hour, false); total != 63000 {
		t.Fatalf("1 d: %d", total)
	}

	// Once per w: a copy of long's token published again.
	cp := *long
	cpEv := *long.Event
	cpEv.ID = "ff" + cpEv.ID[2:]
	cpEv.CreatedAt++
	cp.Event = &cpEv
	if total, _ := Count([]*CashZap{long, &cp}, []Verdict{vLong, vLong}, nil, 0, false); total != 21000 {
		t.Fatalf("copies: %d", total)
	}

	// The sender's own deletion stops counting.
	if total, _ := Count([]*CashZap{long, never}, []Verdict{vLong, vNever}, map[string]bool{long.Event.ID: true}, 0, false); total != 21000 {
		t.Fatalf("deleted: %d", total)
	}

	// Listed, never totalled: no target, a ConnectionKey, a scheme-1 token, an
	// expiration tag, an untrusted Minter.
	noTarget, _ := f.zap(t, zapOpts{scheme: nipcash.SchemeMintV1})
	ck := hexKey(t)
	ckEv, _ := f.zap(t, zapOpts{scheme: nipcash.SchemeMintV1, recipient: ck, mutate: chain(setTag("p", ck, "discord"), addTag("ia", hexKey(t)))})
	mint1, _ := f.zap(t, zapOpts{target: f.note, scheme: nipcash.SchemeMintV1})
	exp, _ := f.zap(t, zapOpts{target: f.note, mutate: addTag("expiration", "1790000000")})
	for name, ev := range map[string]*nip01.Event{"no target": noTarget, "ck": ckEv, "scheme 1": mint1, "expiration": exp} {
		z := f.parsed(t, ev)
		v := VerifyClient(ev, f.note, nil, f.trust())
		if !v.Valid() {
			t.Fatalf("%s: listed zaps are valid: %+v", name, v)
		}
		if total, _ := Count([]*CashZap{z}, []Verdict{v}, nil, 0, false); total != 0 {
			t.Fatalf("%s totalled", name)
		}
	}
	if total, _ := Count([]*CashZap{long}, []Verdict{VerifyClient(long.Event, f.note, nil, nil)}, nil, 0, false); total != 0 {
		t.Fatal("an untrusted minter totalled (S-CZ-15: a recipient with no 10522 trusts none)")
	}

	// Ping-pong: A (the sender) zaps B, B zaps A back.
	aNote, _ := nip01.NewSignedEvent(1, "A's note", f.senderPriv)
	ab, vab := mk(zapOpts{target: f.note})
	ba, _ := f.zap(t, zapOpts{target: aNote, signer: f.recipPriv, recipient: f.sender, issuedAt: aNote.CreatedAt + 120})
	zba, vba := f.parsed(t, ba), VerifyClient(ba, aNote, nil, f.trust())
	if total, _ := Count([]*CashZap{ab, zba}, []Verdict{vab, vba}, nil, 0, false); total != 42000 {
		t.Fatalf("no collapse: %d", total)
	}
	if total, _ := Count([]*CashZap{ab, zba}, []Verdict{vab, vba}, nil, 0, true); total != 21000 {
		t.Fatalf("collapse: %d", total)
	}

	// Possibly expired.
	if !PossiblyExpired(short, time.Unix(int64(issued+3*day), 0)) || PossiblyExpired(never, time.Unix(1<<40, 0)) || PossiblyExpired(short, time.Unix(int64(issued), 0)) {
		t.Fatal("PossiblyExpired")
	}
}

// T14-05: SelectCopy (S-CZ-16).
func TestSelectCopy(t *testing.T) {
	f := newFx(t)
	ev, tok := f.zap(t, zapOpts{target: f.note})
	good := f.parsed(t, ev)

	// The same wallet re-encoded with another relay hint, under a later 9522: its
	// signature recovers some other key.
	other := tok
	other.RelayURLs = []string{"wss://evil.example"}
	s, err := nipcash.Encode(other)
	if err != nil {
		t.Fatal(err)
	}
	evilEv, _ := f.zap(t, zapOpts{target: f.note, mutate: chain(setTag("cash", s), setTag("w", tok.WalletPubkey))})
	evil := f.parsed(t, evilEv)
	evilEv.CreatedAt = 0 // earlier, so a naive "first copy" pick would take it
	if _, err := SelectCopy([]*CashZap{evil, good}); !errors.Is(err, ErrCopiesDisagree) {
		t.Fatalf("disagreeing copies: %v", err)
	}
	got, err := SelectTrustedCopy([]*CashZap{evil, good}, nil, f.trust())
	if err != nil || got != good {
		t.Fatalf("%v %+v", err, got)
	}
	if got, err := SelectCopy([]*CashZap{good}); err != nil || got != good {
		t.Fatal(err)
	}

	// A copy whose token has no provenance is never dialled.
	bare := *good
	bare.Token.Scheme = nipcash.SchemeNone
	if _, err := SelectCopy([]*CashZap{&bare}); !errors.Is(err, ErrNoVerifiedCopy) {
		t.Fatal(err)
	}
	if got, err := SelectCopy([]*CashZap{&bare, good}); err != nil || got != good {
		t.Fatal(err)
	}
	// Different tokens are not copies.
	ev2, _ := f.zap(t, zapOpts{target: f.note})
	if _, err := SelectCopy([]*CashZap{good, f.parsed(t, ev2)}); !errors.Is(err, ErrCopiesOfDifferentTokens) {
		t.Fatal(err)
	}
	if _, err := SelectTrustedCopy([]*CashZap{good}, nil, nil); !errors.Is(err, ErrNoVerifiedCopy) {
		t.Fatal(err)
	}
}
