package nipCP

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
)

// T15-05: WrapRelays and Store (S-CP-08, 09).
func TestWrapRelaysAndStore(t *testing.T) {
	inbox := &nip01.Event{Kind: 10050, Tags: [][]string{{"relay", "wss://a"}, {"relay", "wss://b"}, {"relay", "wss://a"}}}
	nip65 := &nip01.Event{Kind: 10002, Tags: [][]string{{"r", "wss://w"}, {"r", "wss://r", "read"}, {"r", "wss://x", "write"}}}
	if got := WrapRelays(inbox, nip65); !reflect.DeepEqual(got, []string{"wss://a", "wss://b"}) {
		t.Fatalf("10050: %v", got)
	}
	if got := WrapRelays(nil, nip65); !reflect.DeepEqual(got, []string{"wss://w", "wss://x"}) {
		t.Fatalf("NIP-65: %v", got)
	}
	if got := WrapRelays(&nip01.Event{Kind: 10050}, nip65); !reflect.DeepEqual(got, []string{"wss://w", "wss://x"}) {
		t.Fatalf("empty 10050: %v", got)
	}

	userPriv, _ := key(t)
	wrap, _, _ := Seal(bill(hx('1', 64), 1, StateLive), userPriv)
	m := newMem()
	m.drop["c"] = true
	ctx := context.Background()
	stored, err := Store(ctx, m, []string{"a", "b", "c"}, wrap)
	if err != nil || !reflect.DeepEqual(stored, []string{"a", "b"}) {
		t.Fatalf("stored %v, %v", stored, err)
	}
	m.drop["b"] = true
	m2 := newMem()
	m2.drop["b"], m2.refuse["c"] = true, true
	if stored, err = Store(ctx, m2, []string{"a", "b", "c"}, wrap); !errors.Is(err, ErrNotStored) || !reflect.DeepEqual(stored, []string{"a"}) {
		t.Fatalf("one of three: %v %v", stored, err)
	}
	if _, err := Store(ctx, newMem(), []string{"a"}, wrap); err != nil {
		t.Fatalf("one relay given, one stored: %v", err)
	}
}

func journal(t *testing.T, m *memRelays, dev *memDevice) (*PocketJournal, string) {
	t.Helper()
	priv, _ := key(t)
	return &PocketJournal{UserPriv: priv, Relays: []string{"a", "b"}, IO: m, Device: dev, Chain: "bitcoin"}, priv
}

// T15-07, E-POCKET-01: the pending entry is stored and read back before
// WriteAhead returns; unreadable means not sent (S-CP-08, 15).
func TestPocketJournalWriteAhead(t *testing.T) {
	fixClock(t, 1760000000)
	ctx := context.Background()
	m := newMem()
	dev := newDevice(t)
	j, priv := journal(t, m, dev)
	s := secret(t)
	pc := call(nipcash.MethodCashTransfer, 5000)
	pc.Device, pc.Chain = "", ""
	pc.Secrets = []nipcash.PendingSecret{{Secret: s}}
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		t.Fatal(err)
	}
	user, _ := keyPub(t, priv)
	got, err := Sync(ctx, m, j.Relays, priv, FullSyncFilter(user), nil)
	if err != nil || len(got.Entries) != 1 {
		t.Fatalf("sync %+v %v", got, err)
	}
	e := got.Entries[0]
	if e.State != StatePending || e.Device != dev.id || e.Chain != "bitcoin" || e.Secrets[0].Secret != s || len(got.On[e.WrapID]) != 2 {
		t.Fatalf("entry %+v", e)
	}
	// Written again (the send path's exact deadline): rev 2, the old wrap deleted.
	pc.Deadline++
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		t.Fatal(err)
	}
	got, _ = Sync(ctx, m, j.Relays, priv, FullSyncFilter(user), nil)
	if len(got.Entries) != 1 || got.Entries[0].Rev != 2 || got.Entries[0].Deadline != pc.Deadline {
		t.Fatalf("rewrite %+v", got.Entries)
	}

	// No relay returns it: an error, so the call is not sent and no secret
	// leaves.
	bad := newMem()
	bad.drop["a"], bad.drop["b"] = true, true
	j2, _ := journal(t, bad, dev)
	if err := j2.WriteAhead(ctx, []nipcash.PendingCall{call(nipcash.MethodCashTransfer, 1)}); !errors.Is(err, ErrNotStored) {
		t.Fatalf("unreadable: %v", err)
	}
	// As the client's journal: a call failing write-ahead is never published.
	var _ client.Journal = j2
}

// T15-09, T15-20: the local record and the device id (S-CP-28, 31).
func TestDerivedRecordAndDevice(t *testing.T) {
	fixClock(t, 1760000000)
	ctx := context.Background()
	m := newMem()
	dev := newDevice(t)
	j, priv := journal(t, m, dev)
	pc := call(nipcash.MethodCashTransfer, 5000)
	pc.Device = dev.id
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		t.Fatal(err)
	}
	sent := 0
	send := func(context.Context, nipcash.PendingCall) error { sent++; return nil }
	pc.MaxRequestAge = 60
	a, err := client.Replace(ctx, pc, j, client.ReplaceOptions{DerivedEntryExists: j.DerivedEntryExists}, send)
	if err != nil || a.Kind != client.ActionWait || sent != 1 {
		t.Fatalf("first replace %+v %v", a, err)
	}
	d, _ := nipcash.DerivedRequestID(pc.RequestID)
	if ok, _ := j.DerivedEntryExists(ctx, d); !ok {
		t.Fatal("the derived entry was not written ahead")
	}
	// After a Resync (a fresh journal on the same device): the local record
	// still blocks a second placement.
	j2 := &PocketJournal{UserPriv: priv, Relays: j.Relays, IO: newMem(), Device: dev, Chain: "bitcoin"}
	a, err = client.Replace(ctx, pc, j2, client.ReplaceOptions{}, send)
	if err != nil || a.Kind != client.ActionClose || sent != 1 {
		t.Fatalf("second replace %+v %v", a, err)
	}
	// Another device finds the derived entry in the pocket and does not place it.
	other := newDevice(t)
	j3 := &PocketJournal{UserPriv: priv, Relays: j.Relays, IO: m, Device: other, Chain: "bitcoin"}
	a, err = client.Replace(ctx, pc, j3, client.ReplaceOptions{DerivedEntryExists: j3.DerivedEntryExists}, send)
	if err != nil || a.Kind != client.ActionClose || sent != 1 {
		t.Fatalf("other device %+v %v", a, err)
	}
	// Two copies with one device id derive the same id: the pocket stops the
	// second.
	if d2, _ := nipcash.DerivedRequestID(pc.RequestID); d2 != d {
		t.Fatal("derivation is not deterministic")
	}
	// A restored wallet starts a new device id.
	id1, _ := NewDeviceID()
	id2, _ := NewDeviceID()
	if id1 == id2 || !lowerHex(id1, 32) {
		t.Fatal("device ids")
	}
}

// T15-29: Republish (CP-WRAP-02; S-CP-09).
func TestRepublish(t *testing.T) {
	fixClock(t, 1760000000)
	ctx := context.Background()
	m := newMem()
	priv, user := key(t)
	relays := []string{"a", "b"}
	wrap, e, _ := Seal(bill(hx('1', 64), 1, StateLive), priv)
	if _, err := Store(ctx, m, relays, wrap); err != nil {
		t.Fatal(err)
	}
	// A superseded wrap, deleted from a and never on b.
	oldWrap, _, _ := Seal(bill(hx('2', 64), 1, StateLive), priv)
	_ = m.Publish(ctx, "a", oldWrap)
	newWrap, newer, _ := Seal(bill(hx('2', 64), 2, StateSpent), priv)
	_, _ = Store(ctx, m, relays, newWrap)

	s, _ := Sync(ctx, m, relays, priv, FullSyncFilter(user), nil)
	win, _ := Resolve(s.Entries)
	got, err := Republish(ctx, m, relays, win, s)
	if err != nil || len(got) != 0 {
		t.Fatalf("nothing missing: %v %v", got, err)
	}
	m.remove("b", wrap.ID)
	s, _ = Sync(ctx, m, relays, priv, FullSyncFilter(user), nil)
	win, _ = Resolve(s.Entries)
	got, err = Republish(ctx, m, relays, win, s)
	if err != nil || !reflect.DeepEqual(got, map[string][]string{e.WrapID: {"b"}}) {
		t.Fatalf("republish %v %v", got, err)
	}
	back, _ := m.Query(ctx, "b", nip01.SubscriptionFilter{IDs: []string{wrap.ID}})
	if len(back) != 1 || back[0].Sig != wrap.Sig {
		t.Fatal("the same wrap was not republished")
	}
	if win[hx('2', 64)].WrapID != newer.WrapID {
		t.Fatal("the superseded wrap won")
	}
	if b, _ := m.Query(ctx, "b", nip01.SubscriptionFilter{IDs: []string{oldWrap.ID}}); len(b) != 0 {
		t.Fatal("a superseded wrap was republished")
	}
	// The seen set skips wraps already opened.
	seen := SeenSet{}
	s1, _ := Sync(ctx, m, relays, priv, FullSyncFilter(user), seen)
	s2, _ := Sync(ctx, m, relays, priv, FullSyncFilter(user), seen)
	if len(s1.Entries) != 3 || len(s2.Entries) != 0 {
		t.Fatalf("seen set: %d then %d", len(s1.Entries), len(s2.Entries))
	}
}
