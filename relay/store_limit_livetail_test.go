package relay

import (
	"fmt"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// A subscription reuses one *StoreQuery for the bounded historical fetch and
// then for every live tick, so state the bounded scan leaves behind is state
// the live tail inherits.

// TestBoundedScanLeavesNoCandidatesForTheLiveTail guards the heap clear: a
// bounded scan deliberately over-collects to merge across cursors, and
// anything still queued when the limit is reached is older than everything
// delivered. Left on the heap it would be handed straight to the first live
// tick, re-delivering exactly the events the limit excluded.
func TestBoundedScanLeavesNoCandidatesForTheLiveTail(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 40; i++ {
		all = append(all, signEventAt(t, probeKeyA, regularKinds[i%4], base-uint64(i),
			fmt.Sprintf("hist %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds: regularKinds[:4],
		Limit: 5,
	}))

	assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:5])

	for _, scan := range q.scanners {
		if n := scan.queueEvents.Len(); n != 0 {
			t.Errorf("%d candidates left queued after a bounded scan", n)
		}
	}

	// Nothing new was written, so the first live tick must deliver nothing.
	if got := readEventsCollecting(t, q, true); len(got) != 0 {
		t.Errorf("live tick re-delivered %d events after the bounded fetch", len(got))
	}
}

// The live tail's boundary is the store's arrival watermark, not a key
// position, so an event written with an older created_at than everything
// already delivered still arrives.
func TestLiveTailDeliversBackdatedInserts(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var initial []*nip01.Event
	for i := 0; i < 5; i++ {
		initial = append(initial, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("initial %d", i)))
	}
	insertInOrder(t, store, initial, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), initial)

	// Older than every event already delivered, so it sorts below them in
	// the index rather than above.
	backdated := signEventAt(t, probeKeyA, 1, base-5000, "backdated")
	InsertTestEvents(t, store, []*nip01.Event{backdated})

	got := readEventsCollecting(t, q, true)
	if len(got) != 1 {
		t.Fatalf("live tick delivered %d events, want 1 (the backdated insert)", len(got))
	}
	if got[0].EventID != backdated.ID {
		t.Errorf("live tick delivered %s, want the backdated event %s", got[0].EventID[:8], backdated.ID[:8])
	}
}

// A cursor that contributed nothing to the bounded fetch because the limit
// was already met must still deliver its events once they are new.
func TestStarvedCursorStillDeliversOnTheLiveTail(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// Kind A holds the newest events; kind B holds only older ones, so a
	// small limit is satisfied entirely from A.
	kindA, kindB := regularKinds[0], regularKinds[1]
	var all []*nip01.Event
	for i := 0; i < 10; i++ {
		all = append(all, signEventAt(t, probeKeyA, kindA, base-uint64(i), fmt.Sprintf("fresh %d", i)))
	}
	for i := 0; i < 10; i++ {
		all = append(all, signEventAt(t, probeKeyA, kindB, base-500-uint64(i), fmt.Sprintf("stale %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{kindA, kindB},
		Limit: 3,
	}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:3])

	// Now write a fresh kind-B event: the starved cursor has to pick it up.
	fresh := signEventAt(t, probeKeyA, kindB, base+10, "fresh kind B")
	InsertTestEvents(t, store, []*nip01.Event{fresh})

	got := readEventsCollecting(t, q, true)
	found := false
	for _, pe := range got {
		if pe.EventID == fresh.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("the starved cursor's new event was never delivered (got %d events)", len(got))
	}
}

// Repeated ticks with nothing new must stay silent.
func TestLiveTailIsQuietWithoutNewEvents(t *testing.T) {
	store := newStore(t)
	events := probeEvents(t, 6)
	insertInOrder(t, store, events, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), events)

	for tick := 0; tick < 3; tick++ {
		if got := readEventsCollecting(t, q, true); len(got) != 0 {
			t.Fatalf("tick %d delivered %d events with nothing new written", tick, len(got))
		}
	}
}
