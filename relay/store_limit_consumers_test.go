package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// CountEvents (NIP-45) and QueryNip77Items (NIP-77) run the same bounded
// scan a REQ does, so they inherit whatever that path does with a limit.
//
// FindEvents (POST /query's only caller, handler_query.go) used to be a
// fourth, unlisted consumer of that same scan with no test of its own --
// it called scan.fetch's fetchUntilEmpty parameter with `true` instead of
// every other caller's `false`, silently scanning to exhaustion regardless
// of the filter's own Limit. /query's own response-shape tests
// (handler_query_test.go) never exercised a filter with more matching
// events than the requested limit, so nothing caught it.

func TestFindEventsRespectsLimit(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 40; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("find %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	cases := []struct {
		limit int
		want  int
	}{
		{1, 1},
		{5, 5},
		{40, 40},
		{100, 40},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("limit_%d", tc.limit), func(t *testing.T) {
			got, err := store.FindEvents(context.Background(), &nip01.SubscriptionFilter{
				Kinds: []int{1},
				Limit: tc.limit,
			})
			if err != nil {
				t.Fatalf("FindEvents: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d events, want %d", len(got), tc.want)
			}
		})
	}
}

// They must be the newest N, not an arbitrary N -- the same "oldest N
// unnoticed" risk store_limit_test.go's fixtures target for the other
// consumers.
func TestFindEventsLimitReturnsNewestNotArbitrary(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 20; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("newest %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	got, err := store.FindEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{1},
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("FindEvents: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5", len(got))
	}
	want := map[uint64]bool{}
	for _, ev := range all[:5] {
		want[ev.CreatedAt] = true
	}
	for _, pe := range got {
		if !want[pe.CreatedAt] {
			t.Errorf("got created_at=%d, want one of the 5 newest timestamps", pe.CreatedAt)
		}
	}
}

// TestFindEventsBeforeIDResumesPastSameTimestampTieWithoutDuplicationOrLoss
// is NIP-CW's composite cursor, exercised the way buzz-acp's own
// query_raw_all actually uses it: page by Limit, and on a full page, cursor
// the next request with Until=last page entry's CreatedAt,
// BeforeID=that entry's id. Until alone ("created_at <= Until") cannot
// disambiguate a same-second tie -- it re-matches the boundary event(s) on
// every subsequent page, which never advances and never terminates (bounded
// only by query_raw_all's own 10,000-event safety cap in production). This
// asserts both that it terminates and that every event is returned exactly
// once across the full walk.
func TestFindEventsBeforeIDResumesPastSameTimestampTieWithoutDuplicationOrLoss(t *testing.T) {
	store := newStore(t)
	tied := uint64(time.Now().Unix())

	const total = 11
	const pageLimit = 3
	var all []*nip01.Event
	for i := 0; i < total; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, tied, fmt.Sprintf("tied %d", i)))
	}
	insertInOrder(t, store, all, shuffled)

	filter := &nip01.SubscriptionFilter{Kinds: []int{1}, Limit: pageLimit}
	seen := map[string]int{}
	const maxPages = total/pageLimit + 2 // generous; a real bug here loops far longer than this
	pages := 0

	for {
		pages++
		if pages > maxPages {
			t.Fatalf("exceeded %d pages without terminating -- before_id is not advancing the cursor", maxPages)
		}
		page, err := store.FindEvents(context.Background(), filter)
		if err != nil {
			t.Fatalf("FindEvents (page %d): %v", pages, err)
		}
		for _, pe := range page {
			seen[pe.EventID]++
		}
		if len(page) < pageLimit {
			break
		}
		last := page[len(page)-1]
		filter.Until = last.CreatedAt
		filter.BeforeID = last.EventID
	}

	if len(seen) != total {
		t.Errorf("got %d unique events across %d pages, want %d", len(seen), pages, total)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("event %s returned %d times, want exactly once", id, count)
		}
	}
}

func TestCountEventsRespectsLimit(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 40; i++ {
		all = append(all, signEventAt(t, probeKeyA, regularKinds[i%4], base-uint64(i),
			fmt.Sprintf("count %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	cases := []struct {
		limit int
		want  int64
	}{
		{1, 1},
		{5, 5},
		{40, 40},
		{100, 40},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("limit_%d", tc.limit), func(t *testing.T) {
			got, err := store.CountEvents(context.Background(), filterGroup(&nip01.SubscriptionFilter{
				Kinds: regularKinds[:4],
				Limit: tc.limit,
			}))
			if err != nil {
				t.Fatalf("CountEvents: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// A count must not include candidates that were collected and then dropped
// by the filter's own Match.
func TestCountEventsIgnoresNonMatchingCandidates(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var all []*nip01.Event
	for i := 0; i < 20; i++ {
		tag := "keep"
		if i%2 == 1 {
			tag = "drop"
		}
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i),
			fmt.Sprintf("count %d", i), []string{"t", tag}))
	}
	insertInOrder(t, store, all, newestFirst)

	got, err := store.CountEvents(context.Background(), filterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{1},
		Tags:  map[string][]string{"t": {"keep"}},
		Limit: 100,
	}))
	if err != nil {
		t.Fatalf("CountEvents: %v", err)
	}
	if got != 10 {
		t.Errorf("got %d, want 10", got)
	}
}

// nip77.New documents that it needs items sorted by (Timestamp, ID).
// processNegOpen reverses this output to get ascending order, so the
// descending order here has to be total, not merely by timestamp.
func TestQueryNip77ItemsAreTotallyOrdered(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// Deliberate same-second ties: ordering by timestamp alone leaves
	// their relative order undefined.
	var all []*nip01.Event
	for i := 0; i < 12; i++ {
		all = append(all, signEventAt(t, probeKeyA, 1, base-uint64(i/3), fmt.Sprintf("tie %d", i)))
	}
	insertInOrder(t, store, all, newestFirst)

	items, err := store.QueryNip77Items(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{1},
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("QueryNip77Items: %v", err)
	}
	if len(items) != len(all) {
		t.Fatalf("got %d items, want %d", len(items), len(all))
	}

	for i := 1; i < len(items); i++ {
		if items[i-1].Compare(items[i]) <= 0 {
			t.Fatalf("items %d and %d are not in strictly descending (timestamp, id) order: "+
				"(%d, %x) then (%d, %x)",
				i-1, i,
				items[i-1].Timestamp, items[i-1].ID[:4],
				items[i].Timestamp, items[i].ID[:4])
		}
	}
}

func TestQueryNip77ItemsRespectsLimit(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	events := make([]*nip01.Event, 0, 20)
	for i := 0; i < 20; i++ {
		events = append(events, signEventAt(t, probeKeyA, 1, base-uint64(i), fmt.Sprintf("n77 %d", i)))
	}
	insertInOrder(t, store, events, newestFirst)

	items, err := store.QueryNip77Items(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{1},
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("QueryNip77Items: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("got %d items, want 5", len(items))
	}
	// They must be the newest five, not an arbitrary five.
	for i, item := range items {
		if item.Timestamp != events[i].CreatedAt {
			t.Errorf("item %d has timestamp %d, want %d", i, item.Timestamp, events[i].CreatedAt)
		}
	}
}
