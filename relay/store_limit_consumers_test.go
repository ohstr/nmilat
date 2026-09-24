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
