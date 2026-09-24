package relay

import (
	"fmt"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// A limit has to hold up against everything else in a filter: a since/until
// window, candidates the index matches but the filter rejects, ephemeral
// kinds, and other filters sharing the same REQ.

// windowEvents returns 40 kind-1 events, newest first, one per second.
func windowEvents(t testing.TB, store *EventStore, base uint64) []*nip01.Event {
	t.Helper()
	var all []*nip01.Event
	for i := 0; i < 40; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("window %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)
	return all
}

func TestLimitWithSinceUntilWindow(t *testing.T) {
	base := uint64(time.Now().Unix())

	t.Run("since excludes the newest", func(t *testing.T) {
		store := newStore(t)
		all := windowEvents(t, store, base)

		// Only events at base-9 .. base are in range; ask for 5.
		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1},
			Since: base - 9,
			Limit: 5,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:5])
	})

	t.Run("until excludes the newest", func(t *testing.T) {
		store := newStore(t)
		all := windowEvents(t, store, base)

		// The newest allowed is base-10, so the answer starts there.
		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1},
			Until: base - 10,
			Limit: 5,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), all[10:15])
	})

	t.Run("both bounds", func(t *testing.T) {
		store := newStore(t)
		all := windowEvents(t, store, base)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1},
			Since: base - 20,
			Until: base - 10,
			Limit: 100,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), all[10:21])
	})

	t.Run("window excludes everything", func(t *testing.T) {
		store := newStore(t)
		windowEvents(t, store, base)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1},
			Since: base + 1000,
			Limit: 10,
		}))
		if got := readEventsCollecting(t, q, false); len(got) != 0 {
			t.Errorf("got %d events for an empty window, want 0", len(got))
		}
	})

	t.Run("bounds are inclusive", func(t *testing.T) {
		store := newStore(t)
		all := windowEvents(t, store, base)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1},
			Since: base - 3,
			Until: base - 3,
			Limit: 10,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{all[3]})
	})
}

// A window that excludes most of the index must still return a full limit
// of matches.
//
// Correctness here comes from the pass loop, which counts what was emitted
// rather than what was collected, so it keeps running passes until the
// limit is met. Spending a cursor's budget only on entries that became
// candidates is an efficiency property on top of that -- it saves passes --
// and is deliberately not what this test pins.
func TestLimitReturnsAFullLimitDespiteANarrowWindow(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// 100 events, only the oldest 10 inside the window.
	var all []*nip01.Event
	for i := 0; i < 100; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("skip %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{1},
		Until: base - 90,
		Limit: 5,
	}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), all[90:95])
}

// Same for candidates the index matches but filter.Match then rejects: the
// query still has to come back with a full limit.
func TestLimitReturnsAFullLimitDespiteNonMatchingCandidates(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// Alternating tags; the filter wants only one of them, but both share
	// the kind index the scan walks.
	var all []*nip01.Event
	var keep []*nip01.Event
	for i := 0; i < 60; i++ {
		tag := "keep"
		if i%2 == 1 {
			tag = "drop"
		}
		ev := signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("match %d", i), []string{"t", tag})
		all = append(all, ev)
		if tag == "keep" {
			keep = append(keep, ev)
		}
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{1},
		Tags:  map[string][]string{"t": {"keep"}},
		Limit: 10,
	}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), keep[:10])
}

// A multi-cursor filter offers every cursor the whole remaining budget, so
// it collects more candidates than it delivers. Those extra candidates must
// not be treated as delivered: a later filter in the same REQ still has to
// see them. This is why candidate dedup is scan-local and delivery dedup is
// query-wide.
//
// The fixture makes the two filters contend deliberately: filter one spans
// both kinds but the newest events are all kind A, so its kind-B candidates
// are collected and dropped -- and those are exactly what filter two wants.
func TestOverCollectedCandidatesStayVisibleToLaterFilters(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	kindA, kindB := regularKinds[0], regularKinds[1]

	var aEvents, bEvents, all []*nip01.Event
	for i := 0; i < 10; i++ {
		a := signEventAt(t, probeKeyA, kindA, base-uint64(i), fmt.Sprintf("a %d", i))
		aEvents = append(aEvents, a)
		all = append(all, a)
	}
	for i := 0; i < 10; i++ {
		b := signEventAt(t, probeKeyA, kindB, base-100-uint64(i), fmt.Sprintf("b %d", i))
		bEvents = append(bEvents, b)
		all = append(all, b)
	}
	insertInOrder(t, store, all, newestFirst)

	fg := nip01.NewSubscriptionFilterGroup()
	// Spans both kinds; every event it delivers is kind A, so its kind-B
	// candidates are collected and then dropped.
	fg.Add(&nip01.SubscriptionFilter{Kinds: []int{kindA, kindB}, Limit: 3})
	// Wants precisely those dropped kind-B candidates.
	fg.Add(&nip01.SubscriptionFilter{Kinds: []int{kindB}, Limit: 3})

	q := newQuery(t, store, fg)
	got := readEventsCollecting(t, q, false)

	seen := map[string]bool{}
	for _, pe := range got {
		seen[pe.EventID] = true
	}
	for i := 0; i < 3; i++ {
		if !seen[aEvents[i].ID] {
			t.Errorf("filter one's event %d (kind A) is missing", i)
		}
		if !seen[bEvents[i].ID] {
			t.Errorf("filter two's event %d (kind B) is missing -- it was collected as a "+
				"candidate by filter one and then hidden", i)
		}
	}
	if len(got) != 6 {
		t.Errorf("got %d events, want 6 (3 per filter)", len(got))
	}
}

// Two filters over disjoint kinds each get their own limit.
func TestTwoFiltersEachGetTheirLimit(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	kindA, kindB := regularKinds[0], regularKinds[1]
	var aEvents, bEvents, all []*nip01.Event
	for i := 0; i < 30; i++ {
		a := signEventAt(t, probeKeyA, kindA, base-uint64(i), fmt.Sprintf("a %d", i))
		b := signEventAt(t, probeKeyA, kindB, base-uint64(i), fmt.Sprintf("b %d", i))
		aEvents = append(aEvents, a)
		bEvents = append(bEvents, b)
		all = append(all, a, b)
	}
	insertInOrder(t, store, all, newestFirst)

	fg := nip01.NewSubscriptionFilterGroup()
	fg.Add(&nip01.SubscriptionFilter{Kinds: []int{kindA}, Limit: 5})
	fg.Add(&nip01.SubscriptionFilter{Kinds: []int{kindB}, Limit: 5})

	q := newQuery(t, store, fg)
	got := readEventsCollecting(t, q, false)
	if len(got) != 10 {
		t.Fatalf("got %d events, want 10 (5 per filter)", len(got))
	}

	seen := map[string]bool{}
	for _, pe := range got {
		seen[pe.EventID] = true
	}
	for i := 0; i < 5; i++ {
		if !seen[aEvents[i].ID] {
			t.Errorf("filter A's event %d is missing", i)
		}
		if !seen[bEvents[i].ID] {
			t.Errorf("filter B's event %d is missing", i)
		}
	}
}

// Overlapping filters must not deliver the same event twice.
func TestOverlappingFiltersDoNotDuplicate(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 20; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("dup %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	fg := nip01.NewSubscriptionFilterGroup()
	fg.Add(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 5})
	fg.Add(&nip01.SubscriptionFilter{Authors: []string{all[0].PubKey}, Limit: 5})

	q := newQuery(t, store, fg)
	got := readEventsCollecting(t, q, false)

	seen := map[string]int{}
	for _, pe := range got {
		seen[pe.EventID]++
		if seen[pe.EventID] > 1 {
			t.Fatalf("event %s delivered %d times", pe.EventID[:8], seen[pe.EventID])
		}
	}
}

// NIP-16: ephemeral events are not returned for historical requests, so a
// limited query over a mix of kinds still has to return a full limit of
// non-ephemeral ones.
func TestEphemeralEventsAreNotReturnedForHistoricalQueries(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var regular []*nip01.Event
	var all []*nip01.Event
	for i := 0; i < 20; i++ {
		e := signEventAt(t, probeKeyA, 20001, base-uint64(i), fmt.Sprintf("ephemeral %d", i))
		r := signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("regular %d", i))
		regular = append(regular, r)
		all = append(all, e, r)
	}
	insertInOrder(t, store, all, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{1, 20001},
		Limit: 5,
	}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), regular[:5])
}
