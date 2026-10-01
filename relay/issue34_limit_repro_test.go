package relay

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// Repro for issue #34: a REQ carrying `limit` must return the N most recent
// matching events (NIP-01), but the bounded scan truncates in index order --
// which for every index except created_at is insertion order (evsid), not
// created_at order.
//
// indexKind's key is kind||evsid with created_at only as the value, so
// storeCursor.Collect walking c.Prev() from maxKey yields the most recently
// *inserted* rows. The eventQueue heap then sorts whatever survived by
// created_at, so the ordering of the result looks right while the truncation
// has already dropped the wrong end.
//
// TestIssue34 inserts newest-first, making insertion order the exact reverse
// of created_at order, which is what exposes the truncation end.
// TestIssue34InsertionOrderDependence pins that this is order-dependent, not a
// plain reversal, and that the created_at index is unaffected -- both of which
// the fix has to account for.

// probeQuery runs one filter through the same bounded path a REQ uses
// (subscription.go calls Fetch with keepOpen=false) and returns the probe
// indexes it produced, in delivery order.
func probeQuery(t *testing.T, store *EventStore, idToProbe map[string]int, kinds []int, limit int) []int {
	t.Helper()

	g := nip01.NewSubscriptionFilterGroup()
	g.Add(&nip01.SubscriptionFilter{Kinds: kinds, Limit: limit})

	q, err := NewStoreQuery(store, g)
	if err != nil {
		t.Fatalf("NewStoreQuery: %v", err)
	}

	out := make(chan *PotentialEvent)
	var wg sync.WaitGroup
	var got []int
	done := make(chan struct{})
	go func() {
		defer close(done)
		for pv := range out {
			if probe, ok := idToProbe[pv.EventID]; ok {
				got = append(got, probe)
			} else {
				t.Errorf("unknown event id %q in results", pv.EventID)
			}
			wg.Done()
		}
	}()

	if err := q.Fetch(context.Background(), out, &wg, false); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	wg.Wait()
	close(out)
	<-done

	return got
}

// seedProbes builds `probes` kind-1 events where probe 0 is the newest and
// probe probes-1 the oldest, then inserts them one at a time so evsid order is
// deterministic. newestFirst picks the insertion order.
func seedProbes(t *testing.T, store *EventStore, probes int, newestFirst bool) map[string]int {
	t.Helper()

	base := uint64(time.Now().Unix())
	events := make([]*nip01.Event, probes)
	idToProbe := make(map[string]int, probes)

	for i := 0; i < probes; i++ {
		ev := &nip01.Event{
			PubKey:    publicKey,
			CreatedAt: base - uint64(i),
			Kind:      1,
			Tags:      [][]string{},
			Content:   fmt.Sprintf("limit-probe %d", i),
		}
		if err := ev.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
			t.Fatalf("sign probe %d: %v", i, err)
		}
		events[i] = ev
		idToProbe[ev.ID] = i
	}

	for i := 0; i < probes; i++ {
		ev := events[i]
		if !newestFirst {
			ev = events[probes-1-i]
		}
		InsertTestEvents(t, store, []*nip01.Event{ev})
	}

	return idToProbe
}

func TestIssue34FilterLimitReturnsNewestEvents(t *testing.T) {
	store := newStore(t)
	idToProbe := seedProbes(t, store, 10, true)

	// Effectively unlimited: ordering itself is fine, newest-first.
	if got := probeQuery(t, store, idToProbe, []int{1}, 50); !equalInts(got, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
		t.Errorf("limit 50: got probes %v, want 0..9 newest-first", got)
	}

	// The report: limit 3 returns probes 7, 8, 9 -- the three oldest.
	if got := probeQuery(t, store, idToProbe, []int{1}, 3); !equalInts(got, []int{0, 1, 2}) {
		t.Errorf("limit 3: got probes %v, want [0 1 2] (the three newest)", got)
	}
}

func TestIssue34InsertionOrderDependence(t *testing.T) {
	// Same ten events, inserted oldest-first so insertion order now agrees
	// with created_at order. If truncation were simply picking the oldest
	// end, this would still fail; it passes, which is what identifies evsid
	// order as the truncation key.
	t.Run("kind index, inserted oldest-first", func(t *testing.T) {
		store := newStore(t)
		idToProbe := seedProbes(t, store, 10, false)

		if got := probeQuery(t, store, idToProbe, []int{1}, 3); !equalInts(got, []int{0, 1, 2}) {
			t.Errorf("limit 3: got probes %v, want [0 1 2] (the three newest)", got)
		}
	})

	// The created_at index is keyed by timestamp, so its cursor truncates on
	// the right key even with adversarial insertion order. A fix must not
	// regress this path.
	t.Run("created_at index, inserted newest-first", func(t *testing.T) {
		store := newStore(t)
		idToProbe := seedProbes(t, store, 10, true)

		if got := probeQuery(t, store, idToProbe, nil, 3); !equalInts(got, []int{0, 1, 2}) {
			t.Errorf("limit 3: got probes %v, want [0 1 2] (the three newest)", got)
		}
	})
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
