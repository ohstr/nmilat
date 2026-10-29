package nipCP

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipcash"
)

// T15-01, T15-02: Seal records the wrap key; Open keeps only the user's own
// unsigned 9525s (S-CP-01..04, 07).
func TestSealOpen(t *testing.T) {
	userPriv, userPub := key(t)
	e := bill(hx('1', 64), 1, StateLive)
	wrap, sealed, err := Seal(e, userPriv, nip59.WithWrapExpiration(1790000000))
	if err != nil {
		t.Fatal(err)
	}
	wrapPub, _ := keyPub(t, sealed.WrapKey)
	if wrap.PubKey != wrapPub || sealed.WrapID != wrap.ID || wrap.GetTag("p")[0] != userPub {
		t.Fatalf("wrap %+v, sealed %+v", wrap, sealed)
	}
	got, err := Open(wrap, userPriv)
	if err != nil {
		t.Fatal(err)
	}
	if got.WrapKey != sealed.WrapKey || got.RumorID != sealed.RumorID || got.Cash != e.Cash {
		t.Fatalf("opened %+v", got)
	}
	// A second seal of the same entry uses a new wrap key.
	_, again, _ := Seal(e, userPriv)
	if again.WrapKey == sealed.WrapKey {
		t.Fatal("wrap key reused")
	}

	strangerPriv, _ := key(t)
	wk, _ := key(t)
	r, _ := entryRumor(t, e, userPub)
	// Sealed by a stranger, rumor pubkey the user: refused at unwrap.
	forged, err := nip59.Wrap(r, strangerPriv, userPub)
	if err != nil {
		t.Fatal(err)
	}
	// Sealed by a stranger with the stranger as author.
	r2, _ := entryRumor(t, e, "")
	foreign, err := nip59.WrapWithKey(r2, strangerPriv, userPub, wk)
	if err != nil {
		t.Fatal(err)
	}
	// A NIP-17 DM to the user.
	dm, err := nip59.WrapWithKey(nip01.NewEvent(14, "hi"), strangerPriv, userPub, wk)
	if err != nil {
		t.Fatal(err)
	}
	// A signed 9525 inside the user's own seal.
	signed, _ := entryRumor(t, e, "")
	if err := signed.Sign(userPriv); err != nil {
		t.Fatal(err)
	}
	signedWrap, err := nip59.Wrap(signed, userPriv, userPub)
	if err != nil {
		t.Fatal(err)
	}
	for name, w := range map[string]*nip01.Event{"forged": forged, "foreign": foreign, "dm": dm, "signed": signedWrap} {
		if _, err := Open(w, userPriv); !errors.Is(err, ErrNotEntry) {
			t.Errorf("%s: err = %v, want ErrNotEntry", name, err)
		}
	}
	all, err := OpenAll([]*nip01.Event{forged, wrap, dm, foreign, signedWrap}, userPriv)
	if err != nil || len(all) != 1 || all[0].WrapID != wrap.ID {
		t.Fatalf("OpenAll = %v, %v", all, err)
	}
}

func keyPub(t *testing.T, priv string) (string, error) {
	t.Helper()
	ev, err := nip01.NewSignedEvent(1, "", priv)
	if err != nil {
		t.Fatal(err)
	}
	return ev.PubKey, nil
}

func entryRumor(t *testing.T, e Entry, user string) (*nip01.Event, error) {
	t.Helper()
	e.WrapKey = hx('c', 64)
	r, err := e.Rumor(user, 1760000001)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = ""
	return r, nil
}

// T15-13: the deletion is signed by the old wrap key, created_at randomized
// (S-CP-40).
func TestDeletionFor(t *testing.T) {
	fixClock(t, 1760000000)
	userPriv, _ := key(t)
	_, sealed, err := Seal(bill(hx('1', 64), 1, StateLive), userPriv)
	if err != nil {
		t.Fatal(err)
	}
	del, err := DeletionFor(sealed, bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0x10, 0}))
	if err != nil {
		t.Fatal(err)
	}
	wrapPub, _ := keyPub(t, sealed.WrapKey)
	if del.Kind != 5 || del.PubKey != wrapPub || del.GetTag("e")[0] != sealed.WrapID || del.CreatedAt != 1760000000-4096 {
		t.Fatalf("deletion %+v", del)
	}
	if err := del.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := DeletionFor(Entry{WrapID: sealed.WrapID}, nil); err == nil {
		t.Fatal("a deletion without the wrap key")
	}
	// A deletion by another key deletes nothing at a relay.
	m := newMem()
	wrap, sealed2, _ := Seal(bill(hx('2', 64), 1, StateLive), userPriv)
	_ = m.Publish(context.Background(), "r", wrap)
	other := sealed2
	other.WrapKey, _ = key(t)
	bogus, _ := DeletionFor(other, nil)
	_ = m.Publish(context.Background(), "r", bogus)
	if got, _ := m.Query(context.Background(), "r", nip01.SubscriptionFilter{IDs: []string{wrap.ID}}); len(got) != 1 {
		t.Fatal("another key's deletion removed the wrap")
	}
	genuine, _ := DeletionFor(sealed2, nil)
	_ = m.Publish(context.Background(), "r", genuine)
	if got, _ := m.Query(context.Background(), "r", nip01.SubscriptionFilter{IDs: []string{wrap.ID}}); len(got) != 0 {
		t.Fatal("the wrap key's deletion did not remove it")
	}
}

// T15-06: Resolve and NextVersion (S-CP-10..12, 39; K-POCKET-3).
func TestResolve(t *testing.T) {
	w := hx('1', 64)
	stale := bill(w, 3, StateLive)
	stale.RumorID = hx('3', 64)
	spent := bill(w, 5, StateSpent)
	spent.RumorID = hx('5', 64)
	win, conf := Resolve([]Entry{spent, stale})
	if win[w].Rev != 5 || win[w].State != StateSpent || len(conf) != 0 {
		t.Fatalf("v5 spent vs v3 live: %+v %v", win[w], conf)
	}

	// Tie on rev and time: the lowest rumor id; a rewrapped copy changes nothing.
	a, b := bill(w, 4, StateLive), bill(w, 4, StateLive)
	a.RumorID, b.RumorID = hx('a', 64), hx('0', 64)
	a.RumorCreatedAt, b.RumorCreatedAt = 10, 10
	copyOfA := a
	copyOfA.WrapID = hx('9', 64)
	win, conf = Resolve([]Entry{a, copyOfA, b})
	if win[w].RumorID != b.RumorID || !reflect.DeepEqual(conf, []string{w}) {
		t.Fatalf("tie: %+v %v", win[w], conf)
	}
	_, conf = Resolve([]Entry{a, copyOfA})
	if len(conf) != 0 {
		t.Fatal("a rewrapped copy is a conflict")
	}
	// Latest created_at wins a rev tie.
	b.RumorCreatedAt = 11
	if win, _ = Resolve([]Entry{a, b}); win[w].RumorID != b.RumorID {
		t.Fatal("later created_at lost")
	}
	b.RumorCreatedAt = 9
	if win, _ = Resolve([]Entry{a, b}); win[w].RumorID != a.RumorID {
		t.Fatal("later created_at lost")
	}

	// Final v4 vs live v4: final wins, conflict reported.
	f := bill(w, 4, StateSpent)
	f.RumorID, f.RumorCreatedAt = hx('f', 64), 1
	win, conf = Resolve([]Entry{a, f})
	if win[w].State != StateSpent || len(conf) != 1 {
		t.Fatalf("final v4 vs live v4: %+v %v", win[w], conf)
	}

	// A higher rev supersedes a final state (in-place transfer back).
	back := bill(w, 6, StateLive)
	if win, _ = Resolve([]Entry{spent, back}); win[w].State != StateLive {
		t.Fatal("rev 6 live did not supersede rev 5 spent")
	}

	// Unrecognised entries are ignored by Resolve but count for versions and the
	// derived-id check.
	u := Entry{W: w, Rev: 3, RawState: "frozen"}
	two, five := bill(w, 2, StateLive), bill(w, 5, StateLive)
	if NextVersion([]Entry{two, five, u}, w) != 6 {
		t.Fatal("NextVersion over 2, 5, 3")
	}
	if NextVersion(nil, w) != 1 {
		t.Fatal("NextVersion of a new w")
	}
	if win, _ = Resolve([]Entry{u}); len(win) != 0 {
		t.Fatal("an unrecognised entry won")
	}
}

// T15-09: DerivedEntryExists counts every state, unrecognised included
// (S-CP-24, 45).
func TestDerivedEntryExists(t *testing.T) {
	rid := hx('2', 32)
	d, _ := nipcash.DerivedRequestID(rid)
	for _, e := range []Entry{{W: d, Rev: 1, RawState: "weird"}, {W: d, Rev: 1, State: StateDone}, {W: d, Rev: 1, State: StatePending}} {
		if !DerivedEntryExists([]Entry{pendingEntry(rid), e}, d) {
			t.Fatalf("%+v not counted", e)
		}
	}
	if DerivedEntryExists([]Entry{pendingEntry(rid)}, d) {
		t.Fatal("found a derived entry that is not there")
	}
	// Chained: the id derived from R' is derived from R', not R.
	d2, _ := nipcash.DerivedRequestID(d)
	if d2 == d || DerivedEntryExists([]Entry{{W: d, Rev: 1, State: StatePending}}, d2) {
		t.Fatal("chained derivation")
	}
}

// T15-14: MapStatus (S-CP-12, 41..43, 56).
func TestMapStatus(t *testing.T) {
	tomb := func(r string) StatusInput {
		return StatusInput{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: r}}
	}
	cases := []struct {
		in   StatusInput
		want State
		def  bool
	}{
		{StatusInput{OwnSpend: true}, StateSpent, true},
		{tomb("expired"), StateExpired, true},
		{tomb("reclaimed"), StateReclaimed, true},
		{tomb("redeemed"), StateSpent, true},
		{tomb("transferred"), StateSpent, true},
		{tomb("consolidated"), StateSpent, true},
		{tomb("melted"), StateSpent, true},
		{tomb(""), StateSpent, true},
		{StatusInput{NotFound: true, ProofByEntryKey: true}, StateReclaimed, true},
		{StatusInput{NotFound: true}, StateUnknown, false},
		{StatusInput{NoAnswer: true}, StateUnknown, false},
		{StatusInput{}, StateUnknown, false},
	}
	for i, c := range cases {
		if got, def := MapStatus(c.in); got != c.want || def != c.def {
			t.Errorf("case %d: %s %v, want %s %v", i, got, def, c.want, c.def)
		}
	}
}

// T15-15: Balance per chain over live entries only (S-CP-44, K-POCKET-4).
func TestBalance(t *testing.T) {
	a := bill(hx('1', 64), 1, StateLive)
	b := bill(hx('2', 64), 1, StateLive)
	b.Chain, b.Amount = "flokicoin", 7000
	c := bill(hx('3', 64), 1, StateSpent)
	d := bill(hx('4', 64), 1, StateUnknown)
	e := bill(hx('5', 64), 2, StateLive)
	got := Balance(map[string]Entry{a.W: a, b.W: b, c.W: c, d.W: d, e.W: e})
	if !reflect.DeepEqual(got, map[string]uint64{"bitcoin": 42000, "flokicoin": 7000}) {
		t.Fatalf("balance %v", got)
	}
	// The sum saturates instead of wrapping.
	a.Amount, e.Amount = math.MaxUint64-1, 5
	if got := Balance(map[string]Entry{a.W: a, e.W: e}); got["bitcoin"] != math.MaxUint64 {
		t.Fatalf("overflow %v", got)
	}
}

// NIP-CP §Balance: the balance sums amount over live entries only; a pending
// entry's amount (what a call sends) and every other state count nothing.
func TestBalanceLiveOnly(t *testing.T) {
	live := bill(hx('1', 64), 1, StateLive)
	p := pendingEntry(hx('2', 32))
	all := map[string]Entry{live.W: live, p.W: p}
	for i, s := range []State{StateSpent, StateExpired, StateReclaimed, StateDone, StateUnknown} {
		e := bill(hx(byte('3'+i), 64), 1, s)
		all[e.W] = e
	}
	if got := Balance(all)["bitcoin"]; got != live.Amount {
		t.Fatalf("balance %d, want %d", got, live.Amount)
	}
	second := bill(hx('9', 64), 1, StateLive)
	all[second.W] = second
	if got := Balance(all)["bitcoin"]; got != live.Amount+second.Amount {
		t.Fatalf("balance with two live entries %d, want %d", got, live.Amount+second.Amount)
	}
}

// T15-16: incremental sync filter and seen set (S-CP-46).
func TestFilters(t *testing.T) {
	_, user := key(t)
	f := FullSyncFilter(user)
	if !reflect.DeepEqual(f.Kinds, []int{1059}) || f.Tags["p"][0] != user || f.Since != 0 {
		t.Fatalf("full %+v", f)
	}
	if g := IncrementalFilter(user, 1760000000); g.Since != 1760000000-172800 {
		t.Fatalf("since %d", g.Since)
	}
	s := SeenSet{}
	if !s.Add("x") || s.Add("x") {
		t.Fatal("seen set")
	}
}

// T15-17: WrapExpiration rounds up to a week plus 0..6 days (S-CP-47).
func TestWrapExpiration(t *testing.T) {
	grace := 30 * 24 * time.Hour
	base := int64(1790000000)
	for d := byte(0); d < 14; d++ {
		got := WrapExpiration(base, grace, bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0, d}))
		floor := got - int64(d%7)*86400
		if floor%604800 != 0 || floor < base+int64(grace/time.Second) || floor-(base+int64(grace/time.Second)) >= 604800 {
			t.Fatalf("d=%d: %d", d, got)
		}
	}
}

// T15-18: Prunable, NeedsExpiry, ExpiresSoon, NeedsRekey (S-CP-48, 49).
func TestHelpers(t *testing.T) {
	at := time.Unix(1760000000, 0)
	s := bill(hx('1', 64), 2, StateSpent)
	s.CheckedAt = at.Unix() - 31*86400
	if !Prunable(s, at) {
		t.Fatal("a 31-day-old spent entry is not prunable")
	}
	s.CheckedAt = at.Unix() - 29*86400
	l := bill(hx('2', 64), 1, StateLive)
	l.CheckedAt = 1
	if Prunable(s, at) || Prunable(l, at) {
		t.Fatal("pruned too early, or a live entry")
	}
	if !NeedsExpiry(l) {
		t.Fatal("a live bill without expires_at")
	}
	l.ExpiresAt = i64(at.Unix() + 3600)
	if NeedsExpiry(l) || !ExpiresSoon(l, at, 2*time.Hour) || ExpiresSoon(l, at, 30*time.Minute) {
		t.Fatal("expiry helpers")
	}
	l.Identity = EntryIdentity{Type: IdentityCash}
	if !NeedsRekey(l) {
		t.Fatal("a live cash bill needs rekeying")
	}
}
