package nipcw

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

type setFixture struct {
	providerPriv, provider string
	inboxPriv, inbox       string
	now                    time.Time
	addr                   FollowSetAddress
}

func newSetFixture(t *testing.T) setFixture {
	t.Helper()
	pp, p := generateTestKeypair(t)
	ip, i := generateTestKeypair(t)
	return setFixture{providerPriv: pp, provider: p, inboxPriv: ip, inbox: i, now: time.Unix(1720000000, 0),
		addr: FollowSetAddress{Provider: p, D: "circle-7k2m9q4x"}}
}

func (f setFixture) set(t *testing.T, priv string, kind int, at int64, tags ...[]string) *nip01.Event {
	t.Helper()
	ev := nip01.NewEvent(kind, "", tags...)
	ev.CreatedAt = uint64(at)
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

func members(r *Resolution) []string {
	if r == nil {
		return nil
	}
	var out []string
	for m := range r.Members {
		out = append(out, m)
	}
	slices.Sort(out)
	return out
}

// T12-17 (S-CW-42..49, 51) and T12-26 (CW-S-06).
func TestResolveFollowSet(t *testing.T) {
	f := newSetFixture(t)
	_, a := generateTestKeypair(t)
	_, b := generateTestKeypair(t)
	_, c := generateTestKeypair(t)
	otherPriv, _ := generateTestKeypair(t)
	now := f.now.Unix()
	d := []string{"d", f.addr.D}

	v1 := f.set(t, f.providerPriv, 30000, now-100, d, []string{"p", a})
	v2 := f.set(t, f.providerPriv, 30000, now-50, d, []string{"title", "Ada's Family Circle"},
		[]string{"description", "p " + c}, []string{"p", b, "wss://relay.example.com"}, []string{"p", strings.ToUpper(c)})
	v2.Content = "" // private items are never read
	forged := f.set(t, otherPriv, 30000, now, d, []string{"p", c})
	forged.PubKey = f.provider // claims the provider, signature fails
	foreign := f.set(t, otherPriv, 30000, now, d, []string{"p", c})
	future := f.set(t, f.providerPriv, 30000, now+901, d, []string{"p", c})
	wrongD := f.set(t, f.providerPriv, 30000, now, []string{"d", "other"}, []string{"p", c})
	deletion := f.set(t, f.providerPriv, 5, now, []string{"a", "30000:" + f.provider + ":" + f.addr.D})
	contacts := f.set(t, f.providerPriv, 3, now, []string{"p", c})

	r, ok := ResolveFollowSet([]*nip01.Event{v1, v2, forged, foreign, future, wrongD, deletion, contacts}, f.addr, nil, f.now, nil)
	if !ok || r.EventID != v2.ID || !slices.Equal(members(r), []string{b}) {
		t.Fatalf("resolved %+v %v, want v2 with only %s", r, ok, b)
	}
	if r.Title != "Ada's Family Circle" {
		t.Fatalf("title = %q", r.Title)
	}

	// now+900 is still eligible.
	edge := f.set(t, f.providerPriv, 30000, now+900, d, []string{"p", c})
	if r2, ok := ResolveFollowSet([]*nip01.Event{v2, edge}, f.addr, nil, f.now, r); !ok || r2.EventID != edge.ID {
		t.Fatalf("now+900: %+v %v", r2, ok)
	}

	// v1 after v2 is never adopted, and counts as a failed refresh (Q21).
	if r3, ok := ResolveFollowSet([]*nip01.Event{v1}, f.addr, nil, f.now, r); ok || r3 != r {
		t.Fatalf("rollback: %+v %v", r3, ok)
	}
	// No event is unresolved, not empty.
	if r4, ok := ResolveFollowSet(nil, f.addr, nil, f.now, nil); ok || r4 != nil {
		t.Fatalf("no event: %+v %v", r4, ok)
	}
	// An empty set resolves to no members.
	empty := f.set(t, f.providerPriv, 30000, now, d)
	if r5, ok := ResolveFollowSet([]*nip01.Event{empty}, f.addr, nil, f.now, r); !ok || len(r5.Members) != 0 {
		t.Fatalf("empty: %+v %v", r5, ok)
	}

	// A tie goes to the lowest id.
	t1 := f.set(t, f.providerPriv, 30000, now, d, []string{"p", a})
	t2 := f.set(t, f.providerPriv, 30000, now, d, []string{"p", b})
	low := t1
	if t2.ID < t1.ID {
		low = t2
	}
	for _, order := range [][]*nip01.Event{{t1, t2}, {t2, t1}} {
		if r6, ok := ResolveFollowSet(order, f.addr, nil, f.now, nil); !ok || r6.EventID != low.ID {
			t.Fatalf("tie: %+v", r6)
		}
	}

	// T12-26: a title naming a pubkey or terms changes nothing else.
	titled := f.set(t, f.providerPriv, 30000, now, d, []string{"title", c + " 100000:200000:0:monthly"}, []string{"p", a})
	r7, ok := ResolveFollowSet([]*nip01.Event{titled}, f.addr, nil, f.now, nil)
	if !ok || !slices.Equal(members(r7), []string{a}) || r7.Title != c+" 100000:200000:0:monthly" {
		t.Fatalf("title: %+v", r7)
	}
}

// T12-18 (S-CW-54..56, 58).
func TestHiddenMembers(t *testing.T) {
	f := newSetFixture(t)
	retiredPriv, retired := generateTestKeypair(t)
	_, otherInbox := generateTestKeypair(t)
	_, connKey := generateTestKeypair(t)
	_, hidden := generateTestKeypair(t)
	_, oldHidden := generateTestKeypair(t)
	_, foreignHidden := generateTestKeypair(t)
	_, toConn := generateTestKeypair(t)
	key := func(priv, pub string) []byte {
		k, err := conversationKey(priv, pub)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	enc := func(inbox, m string) string {
		p, err := EncryptHiddenMember(f.providerPriv, inbox, m)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	badPlain := func(plain string) string {
		p, err := encryptRaw(plain, key(f.providerPriv, f.inbox))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	ev := f.set(t, f.providerPriv, 30000, f.now.Unix(), []string{"d", f.addr.D},
		[]string{"hidden_p", enc(f.inbox, hidden)},
		[]string{"hidden_p", enc(retired, oldHidden)},
		[]string{"hidden_p", enc(otherInbox, foreignHidden)},
		[]string{"hidden_p", enc(connKey, toConn)},
		[]string{"hidden_p", badPlain(strings.ToUpper(hidden))},
		[]string{"hidden_p", badPlain("npub1xyz")},
		[]string{"hidden_p", "not base64"},
	)
	r, ok := ResolveFollowSet([]*nip01.Event{ev}, f.addr, []string{f.inboxPriv, retiredPriv}, f.now, nil)
	want := []string{hidden, oldHidden}
	slices.Sort(want)
	if !ok || !slices.Equal(members(r), want) {
		t.Fatalf("members %v, want %v", members(r), want)
	}

	// SealHiddenMembers: fresh payloads, shuffled, one per member per inbox key.
	ms := []string{hidden, oldHidden, foreignHidden}
	a, err := SealHiddenMembers(f.providerPriv, []string{f.inbox, otherInbox}, ms, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealHiddenMembers(f.providerPriv, []string{f.inbox, otherInbox}, ms, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 6 || len(b) != 6 {
		t.Fatalf("got %d and %d entries, want 6", len(a), len(b))
	}
	seen := map[string]bool{}
	for _, tag := range append(a, b...) {
		if tag[0] != "hidden_p" || seen[tag[1]] {
			t.Fatalf("repeated or misnamed entry %v", tag)
		}
		seen[tag[1]] = true
	}
	var order []string
	for _, tag := range a {
		m, err := DecryptHiddenMember(f.inboxPriv, f.provider, tag[1])
		if err == nil {
			order = append(order, m)
		}
	}
	if len(order) != 3 {
		t.Fatalf("inbox reads %d of its entries", len(order))
	}
	shuffled := false
	for i := 0; i < 20 && !shuffled; i++ {
		c, _ := SealHiddenMembers(f.providerPriv, []string{f.inbox}, ms, nil)
		var got []string
		for _, tag := range c {
			m, _ := DecryptHiddenMember(f.inboxPriv, f.provider, tag[1])
			got = append(got, m)
		}
		shuffled = !slices.Equal(got, ms)
	}
	if !shuffled {
		t.Fatal("SealHiddenMembers never changed the order")
	}
}
