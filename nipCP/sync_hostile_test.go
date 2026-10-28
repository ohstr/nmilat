package nipCP

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
)

// A relay queried first returns garbage under a real wrap's id: the forgery is
// dropped before it is keyed, credited or marked seen, and the honest copy
// from the next relay is opened.
func TestSyncDropsForgedWrapCopy(t *testing.T) {
	fixClock(t, 1760000000)
	ctx := context.Background()
	m := newMem()
	dev := newDevice(t)
	j, priv := journal(t, m, dev)
	pc := call(nipcash.MethodCashTransfer, 5000)
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		t.Fatal(err)
	}
	user, _ := keyPub(t, priv)
	honest, err := Sync(ctx, m, []string{"a"}, priv, FullSyncFilter(user), nil)
	if err != nil || len(honest.Entries) != 1 {
		t.Fatalf("honest sync %+v %v", honest, err)
	}
	id := honest.Entries[0].WrapID
	forged := *honest.Wraps[id]
	forged.Content = "garbage"
	m.store["x"] = []*nip01.Event{&forged}

	seen := SeenSet{}
	got, err := Sync(ctx, m, []string{"x", "a", "b"}, priv, FullSyncFilter(user), seen)
	if err != nil || len(got.Entries) != 1 || got.Entries[0].WrapID != id {
		t.Fatalf("forged first copy hid the entry: %+v %v", got.Entries, err)
	}
	for _, r := range got.On[id] {
		if r == "x" {
			t.Fatalf("the forging relay is credited with the wrap: %v", got.On[id])
		}
	}
	if !seen[id] {
		t.Fatal("the opened wrap is not marked seen")
	}

	// Only the forging relay answers: nothing opens, nothing is marked seen,
	// so a later sync still opens the honest copy.
	seen2 := SeenSet{}
	got, err = Sync(ctx, m, []string{"x"}, priv, FullSyncFilter(user), seen2)
	if err != nil || len(got.Entries) != 0 || len(got.On) != 0 || seen2[id] {
		t.Fatalf("forgery alone: %+v %v seen=%v", got, err, seen2)
	}
}

// A negative DerivedEntryExists needs MinStored relays to answer.
func TestDerivedEntryExistsNeedsEnoughAnswers(t *testing.T) {
	fixClock(t, 1760000000)
	ctx := context.Background()
	m := newMem()
	dev := newDevice(t)
	j, _ := journal(t, m, dev)
	m.down["b"] = true
	if _, err := j.DerivedEntryExists(ctx, hx('e', 64)); !errors.Is(err, ErrTooFewRelays) {
		t.Fatalf("one of two relays answered: %v", err)
	}
	m.down["b"] = false
	if ok, err := j.DerivedEntryExists(ctx, hx('e', 64)); err != nil || ok {
		t.Fatalf("both answered: %v %v", ok, err)
	}
}
