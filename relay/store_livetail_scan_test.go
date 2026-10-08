package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	bolt "go.etcd.io/bbolt"
)

// Production (ohstr/nmilat#77 follow-up): every open REQ without since
// re-walked its whole index on each 50ms live tick, so a few hundred feed
// subscriptions held every scan slot on a cold 86 GB store and new REQs never
// reached EOSE.

// plantTripwire puts an unparseable kind-1 entry below every real one. Any
// walk that reaches it fails with "bad key size".
func plantTripwire(t *testing.T, store *EventStore) {
	t.Helper()
	key := concatKey(itob(1), itob(0), []byte{0, 0, 0, 0})
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(indexKind).Put(key, itob(0))
	}); err != nil {
		t.Fatal(err)
	}
}

// TestLiveTailTickNeverReadsBelowTheWatermark: a tick with one new event must
// read that event, not every index entry under the filter's prefix.
func TestLiveTailTickNeverReadsBelowTheWatermark(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var old []*nip01.Event
	for i := 0; i < 20; i++ {
		old = append(old, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("old %d", i)))
	}
	insertInOrder(t, store, old, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), old)

	plantTripwire(t, store)
	fresh := signEventAt(t, probeKeyA, 1, base+1, "fresh")
	InsertTestEvents(t, store, []*nip01.Event{fresh})

	got := readEventsCollecting(t, q, true)
	if len(got) != 1 || got[0].EventID != fresh.ID {
		t.Fatalf("live tick delivered %d events, want just the fresh one", len(got))
	}
}

// TestIdleLiveTailTickDoesNotWaitForAScanSlot: with nothing new written, a
// tick must return at once even when every scan slot is taken.
func TestIdleLiveTailTickDoesNotWaitForAScanSlot(t *testing.T) {
	f, err := os.CreateTemp("", "test.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	store, err := NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000},
		WithEventStoreLogger(testlogger.New(t)), WithEventStoreMaxConcurrentScans(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	events := probeEvents(t, 5)
	insertInOrder(t, store, events, newestFirst)
	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), events)

	// A slow historical scan holds the only slot.
	store.scanSlots <- struct{}{}
	defer func() { <-store.scanSlots }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := make(chan *PotentialEvent, 1)
	var wg sync.WaitGroup
	start := time.Now()
	if err := q.Fetch(ctx, out, &wg, true); err != nil {
		t.Fatalf("idle tick failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("idle tick took %s waiting for a scan slot", d)
	}
}

// TestLiveTailDeliversABacklogLargerThanOnePass: more new events than one
// pass reads must all arrive, once each.
func TestLiveTailDeliversABacklogLargerThanOnePass(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 10}))
	if got := readEventsCollecting(t, q, false); len(got) != 0 {
		t.Fatalf("empty store returned %d events", len(got))
	}

	n := maxCursorChunk + 50
	backlog := make([]*nip01.Event, 0, n)
	for i := 0; i < n; i++ {
		// A non-matching kind interleaved, so passes also skip entries.
		kind := 1
		if i%7 == 0 {
			kind = 7
		}
		backlog = append(backlog, signEventAt(t, probeKeyA, kind, base+uint64(i), fmt.Sprintf("b %d", i)))
	}
	InsertTestEvents(t, store, backlog)

	want := map[string]bool{}
	for _, ev := range backlog {
		if ev.Kind == 1 {
			want[ev.ID] = true
		}
	}
	got := readEventsCollecting(t, q, true)
	seen := map[string]bool{}
	for _, pe := range got {
		if seen[pe.EventID] {
			t.Fatalf("event %s delivered twice", pe.EventID[:8])
		}
		seen[pe.EventID] = true
		if !want[pe.EventID] {
			t.Fatalf("event %s does not match the filter", pe.EventID[:8])
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("delivered %d of %d new events", len(seen), len(want))
	}
	if got := readEventsCollecting(t, q, true); len(got) != 0 {
		t.Fatalf("next tick re-delivered %d events", len(got))
	}
}

// TestLiveTailWakesOnCommit: with the fallback tick out of reach, a new
// event still arrives, because the write itself wakes the subscription.
func TestLiveTailWakesOnCommit(t *testing.T) {
	store := newStore(t)
	InsertTestEvents(t, store, probeEvents(t, 2))

	sub, events, errs, eose := NewSubscription("wake", newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 1})))
	sub.minGap, sub.fallback = 0, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	go sub.Start(ctx, &wg)
	defer sub.Stop()

	for done := false; !done; {
		select {
		case <-events:
			wg.Done()
		case <-eose:
			done = true
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("no EOSE")
		}
	}

	fresh := signEventAt(t, probeKeyA, 1, uint64(time.Now().Unix())+5, "fresh")
	InsertTestEvents(t, store, []*nip01.Event{fresh})
	select {
	case pe := <-events:
		wg.Done()
		if pe.EventID != fresh.ID {
			t.Fatalf("delivered %s, want the fresh event", pe.EventID[:8])
		}
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("new event not delivered: the commit didn't wake the live tail")
	}
}

func storeWithOneSlot(t *testing.T, opts ...EventStoreOption) *EventStore {
	t.Helper()
	f, err := os.CreateTemp("", "test.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	opts = append([]EventStoreOption{WithEventStoreLogger(testlogger.New(t)), WithEventStoreMaxConcurrentScans(1)}, opts...)
	store, err := NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

// TestREQAnswersWhenNoScanSlotFrees: a REQ queued behind scans that never
// finish must end with an error (CLOSED) rather than never answering.
// Uses only the default wait, so it also runs unchanged against older
// releases.
func TestREQAnswersWhenNoScanSlotFrees(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the default scan-slot wait")
	}
	f, err := os.CreateTemp("", "test.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	store, err := NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	InsertTestEvents(t, store, probeEvents(t, 3))

	for i := 0; i < cap(store.scanSlots); i++ {
		store.scanSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(store.scanSlots); i++ {
			<-store.scanSlots
		}
	}()

	sub, _, errs, eose := NewSubscription("starved", newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100})))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	go sub.Start(ctx, &wg)
	defer sub.Stop()

	select {
	case <-errs:
	case <-eose:
		t.Fatal("EOSE without a scan slot")
	case <-time.After(15 * time.Second):
		t.Fatal("REQ got neither EOSE nor CLOSED in 15s with every scan slot held")
	}
}

// TestBoundedScanGivesUpAfterScanSlotWait: the historical fetch reports
// ErrScanBusy once the wait elapses.
func TestBoundedScanGivesUpAfterScanSlotWait(t *testing.T) {
	store := storeWithOneSlot(t, WithEventStoreScanSlotWait(100*time.Millisecond))
	InsertTestEvents(t, store, probeEvents(t, 3))
	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))

	store.scanSlots <- struct{}{}
	defer func() { <-store.scanSlots }()

	out := make(chan *PotentialEvent, 10)
	var wg sync.WaitGroup
	start := time.Now()
	err := q.Fetch(context.Background(), out, &wg, false)
	if !errors.Is(err, ErrScanBusy) {
		t.Fatalf("got %v, want ErrScanBusy", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("gave up after %s", d)
	}
}

// TestBusyLiveTailTickCatchesUpOnTheNext: a tick that can't get a slot
// delivers nothing and loses nothing.
func TestBusyLiveTailTickCatchesUpOnTheNext(t *testing.T) {
	store := storeWithOneSlot(t, WithEventStoreScanSlotWait(50*time.Millisecond))
	events := probeEvents(t, 3)
	insertInOrder(t, store, events, newestFirst)
	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 100}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), events)

	fresh := signEventAt(t, probeKeyA, 1, uint64(time.Now().Unix())+5, "fresh")
	InsertTestEvents(t, store, []*nip01.Event{fresh})

	store.scanSlots <- struct{}{}
	if got := readEventsCollecting(t, q, true); len(got) != 0 {
		t.Fatalf("busy tick delivered %d events", len(got))
	}
	<-store.scanSlots

	got := readEventsCollecting(t, q, true)
	if len(got) != 1 || got[0].EventID != fresh.ID {
		t.Fatalf("next tick delivered %d events, want the fresh one", len(got))
	}
}
