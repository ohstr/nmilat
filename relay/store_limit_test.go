package relay

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// NIP-01: "it is assumed that the events returned in the initial query will
// be the last n events ordered by the created_at". These tests assert which
// events come back and in what order — asserting only how many is what let
// the relay return the oldest N unnoticed.
//
// The fixtures deliberately decouple insertion order from created_at order,
// because that is the only condition under which the bug shows: the query
// indexes are keyed by evsid (arrival sequence), so a walk backwards through
// them is reverse *insertion* order, not reverse time order.

const (
	probeKeyA = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	probeKeyB = "1bce23dcf1fc98de24c28cdac68effe22c4981c518a95fdf6b5df3b7ac013a7d"
)

// signEventAt builds and signs an event with an explicit key, timestamp and
// content, so tests can control author, recency and identity independently.
func signEventAt(t testing.TB, privKey string, kind int, createdAt uint64, content string, tags ...[]string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{
		CreatedAt: createdAt,
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

type insertOrder string

const (
	// newestFirst is the issue's own repro: the newest event is inserted
	// first, so evsid order is the exact reverse of created_at order.
	newestFirst insertOrder = "newest-first"
	oldestFirst insertOrder = "oldest-first"
	shuffled    insertOrder = "shuffled"
)

// insertInOrder inserts events (given newest-first) in the requested
// arrival order. The returned slice stays newest-first regardless, so
// callers can index it to name the expected result.
func insertInOrder(t testing.TB, store *EventStore, newestFirstEvents []*nip01.Event, order insertOrder) {
	t.Helper()

	toInsert := make([]*nip01.Event, len(newestFirstEvents))
	copy(toInsert, newestFirstEvents)

	switch order {
	case newestFirst:
		// already in arrival order
	case oldestFirst:
		for i, j := 0, len(toInsert)-1; i < j; i, j = i+1, j-1 {
			toInsert[i], toInsert[j] = toInsert[j], toInsert[i]
		}
	case shuffled:
		r := rand.New(rand.NewSource(20260924))
		r.Shuffle(len(toInsert), func(i, j int) {
			toInsert[i], toInsert[j] = toInsert[j], toInsert[i]
		})
	default:
		t.Fatalf("unknown insert order %q", order)
	}

	// One event per insert task, so arrival order is exactly this order.
	for _, ev := range toInsert {
		InsertTestEvents(t, store, []*nip01.Event{ev})
	}
}

// probeEvents builds n events of one kind/author/tag whose created_at
// strictly decreases with index, so index 0 is the newest.
func probeEvents(t testing.TB, n int) []*nip01.Event {
	t.Helper()
	base := uint64(time.Now().Unix())
	events := make([]*nip01.Event, n)
	for i := 0; i < n; i++ {
		events[i] = signEventAt(t, probeKeyA, 1, base-uint64(i),
			fmt.Sprintf("limit-probe %d", i), []string{"t", "probe"})
	}
	return events
}

// assertIDsInOrder checks identity and sequence together, printing both
// sides with timestamps because a bare count tells you nothing about which
// end of the range you got.
func assertIDsInOrder(t testing.TB, got []*PotentialEvent, want []*nip01.Event) {
	t.Helper()

	if len(got) != len(want) {
		t.Errorf("got %d events, want %d", len(got), len(want))
	}

	describeGot := func() string {
		s := ""
		for _, pe := range got {
			s += fmt.Sprintf("\n  %s created_at=%d", pe.EventID[:8], pe.CreatedAt)
		}
		return s
	}
	describeWant := func() string {
		s := ""
		for _, ev := range want {
			s += fmt.Sprintf("\n  %s created_at=%d %q", ev.ID[:8], ev.CreatedAt, ev.Content)
		}
		return s
	}

	for i := range want {
		if i >= len(got) {
			break
		}
		if got[i].EventID != want[i].ID {
			t.Errorf("delivery position %d: got %s (created_at=%d), want %s (created_at=%d, %q)\ngot: %s\nwant:%s",
				i, got[i].EventID[:8], got[i].CreatedAt,
				want[i].ID[:8], want[i].CreatedAt, want[i].Content,
				describeGot(), describeWant())
			return
		}
	}
}

func filterGroup(f *nip01.SubscriptionFilter) *nip01.SubscriptionFilterGroup {
	fg := nip01.NewSubscriptionFilterGroup()
	fg.Add(f)
	return fg
}

// indexShapes returns one filter per index newStoreScan can select, all
// matching the same probe fixture.
func indexShapes(t testing.TB, events []*nip01.Event) map[string]func(limit int) *nip01.SubscriptionFilter {
	t.Helper()

	author := events[0].PubKey
	ids := make([]string, len(events))
	for i, ev := range events {
		ids[i] = ev.ID
	}

	return map[string]func(int) *nip01.SubscriptionFilter{
		"createdAt": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{Limit: limit}
		},
		"kind": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{Kinds: []int{1}, Limit: limit}
		},
		"pubkey": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{Authors: []string{author}, Limit: limit}
		},
		"kindPubkey": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{Kinds: []int{1}, Authors: []string{author}, Limit: limit}
		},
		"tag": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{Tags: map[string][]string{"t": {"probe"}}, Limit: limit}
		},
		"id": func(limit int) *nip01.SubscriptionFilter {
			return &nip01.SubscriptionFilter{IDs: ids, Limit: limit}
		},
	}
}

// TestLimitReturnsNewest is the issue's repro, generalized over every index
// and every relationship between arrival order and time order.
func TestLimitReturnsNewest(t *testing.T) {
	const total = 10

	for _, order := range []insertOrder{newestFirst, oldestFirst, shuffled} {
		for _, limit := range []int{1, 2, 3, total - 1, total, total + 1} {
			events := probeEvents(t, total)
			shapes := indexShapes(t, events)

			for _, shape := range []string{"createdAt", "kind", "pubkey", "kindPubkey", "tag", "id"} {
				name := fmt.Sprintf("%s/%s/limit-%d", shape, order, limit)
				t.Run(name, func(t *testing.T) {
					store := newStore(t)
					insertInOrder(t, store, events, order)

					q := newQuery(t, store, filterGroup(shapes[shape](limit)))
					got := readEventsCollecting(t, q, false)

					want := events
					if limit < len(want) {
						want = want[:limit]
					}
					assertIDsInOrder(t, got, want)
				})
			}
		}
	}
}

// A limit of 0 means "no limit" on the wire; every event must come back,
// newest first.
func TestLimitZeroReturnsEverythingNewestFirst(t *testing.T) {
	const total = 10
	events := probeEvents(t, total)

	store := newStore(t)
	insertInOrder(t, store, events, newestFirst)

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), events)
}

// TestLimitMultiCursorReturnsGlobalNewest covers the second cause: the
// per-cursor budget. Each case puts the newest events somewhere different
// relative to cursor order.
func TestLimitMultiCursorReturnsGlobalNewest(t *testing.T) {
	base := uint64(time.Now().Unix())

	// newestInLastCursor builds events across `kinds` kinds where the
	// newest `limit` events all belong to the kind whose cursor is created
	// last.
	t.Run("newest all in the last cursor", func(t *testing.T) {
		store := newStore(t)

		var newestFirstAll []*nip01.Event
		// kind 5 holds the newest, kinds 1..4 hold older events.
		for i := 0; i < 10; i++ {
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, 5, base-uint64(i), fmt.Sprintf("fresh %d", i)))
		}
		for i := 0; i < 40; i++ {
			kind := 1 + i%4
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, kind, base-100-uint64(i), fmt.Sprintf("stale %d", i)))
		}
		insertInOrder(t, store, newestFirstAll, newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1, 2, 3, 4, 5},
			Limit: 5,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), newestFirstAll[:5])
	})

	t.Run("newest spread one per cursor", func(t *testing.T) {
		store := newStore(t)

		var newestFirstAll []*nip01.Event
		// The five newest events are one per kind, interleaved.
		for i := 0; i < 5; i++ {
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, 1+i, base-uint64(i), fmt.Sprintf("fresh kind %d", 1+i)))
		}
		for i := 0; i < 40; i++ {
			kind := 1 + i%5
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, kind, base-100-uint64(i), fmt.Sprintf("stale %d", i)))
		}
		insertInOrder(t, store, newestFirstAll, newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1, 2, 3, 4, 5},
			Limit: 5,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), newestFirstAll[:5])
	})

	// Six cursors with a small limit is the regime where the old
	// ceil(limit/n)*refill arithmetic could not hand the whole budget to
	// cursor 0, so it fails differently from the cases above.
	t.Run("six cursors small limit", func(t *testing.T) {
		store := newStore(t)

		var newestFirstAll []*nip01.Event
		for i := 0; i < 6; i++ {
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, 1+i, base-uint64(i), fmt.Sprintf("fresh kind %d", 1+i)))
		}
		for i := 0; i < 60; i++ {
			kind := 1 + i%6
			newestFirstAll = append(newestFirstAll,
				signEventAt(t, probeKeyA, kind, base-100-uint64(i), fmt.Sprintf("stale %d", i)))
		}
		insertInOrder(t, store, newestFirstAll, newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1, 2, 3, 4, 5, 6},
			Limit: 3,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), newestFirstAll[:3])
	})

	t.Run("multiple authors", func(t *testing.T) {
		store := newStore(t)

		a := signEventAt(t, probeKeyA, 1, base, "author A newest")
		b := signEventAt(t, probeKeyB, 1, base-1, "author B second")
		var rest []*nip01.Event
		for i := 0; i < 20; i++ {
			key := probeKeyA
			if i%2 == 1 {
				key = probeKeyB
			}
			rest = append(rest, signEventAt(t, key, 1, base-100-uint64(i), fmt.Sprintf("stale %d", i)))
		}
		all := append([]*nip01.Event{a, b}, rest...)
		insertInOrder(t, store, all, newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Authors: []string{a.PubKey, b.PubKey},
			Limit:   2,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), []*nip01.Event{a, b})
	})

	t.Run("multiple tag values", func(t *testing.T) {
		// Cursor order for tags comes from ranging a map, so it varies per
		// run. Repeat to catch an implementation that depends on it.
		for attempt := 0; attempt < 20; attempt++ {
			store := newStore(t)

			var all []*nip01.Event
			for i := 0; i < 5; i++ {
				all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i),
					fmt.Sprintf("fresh %d", i), []string{"t", fmt.Sprintf("v%d", i)}))
			}
			for i := 0; i < 25; i++ {
				all = append(all, signEventAt(t, probeKeyA, 1, base-100-uint64(i),
					fmt.Sprintf("stale %d", i), []string{"t", fmt.Sprintf("v%d", i%5)}))
			}
			insertInOrder(t, store, all, newestFirst)

			q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
				Tags:  map[string][]string{"t": {"v0", "v1", "v2", "v3", "v4"}},
				Limit: 3,
			}))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:3])
			if t.Failed() {
				t.Fatalf("failed on attempt %d", attempt)
			}
		}
	})

	t.Run("one cursor holds everything newest", func(t *testing.T) {
		store := newStore(t)

		var all []*nip01.Event
		for i := 0; i < 10; i++ {
			all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("fresh %d", i)))
		}
		// Kind 2 exists but is entirely older.
		for i := 0; i < 10; i++ {
			all = append(all, signEventAt(t, probeKeyA, 2, base-100-uint64(i), fmt.Sprintf("stale %d", i)))
		}
		insertInOrder(t, store, all, newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1, 2},
			Limit: 4,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:4])
	})

	t.Run("one cursor empty", func(t *testing.T) {
		store := newStore(t)

		var all []*nip01.Event
		for i := 0; i < 6; i++ {
			all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("fresh %d", i)))
		}
		insertInOrder(t, store, all, newestFirst)

		// Kind 7 matches nothing.
		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{1, 7},
			Limit: 3,
		}))
		assertIDsInOrder(t, readEventsCollecting(t, q, false), all[:3])
	})

	t.Run("no cursor matches", func(t *testing.T) {
		store := newStore(t)
		insertInOrder(t, store, probeEvents(t, 5), newestFirst)

		q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
			Kinds: []int{42},
			Limit: 3,
		}))
		if got := readEventsCollecting(t, q, false); len(got) != 0 {
			t.Errorf("got %d events for a filter matching nothing, want 0", len(got))
		}
	})
}
