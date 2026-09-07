package relay

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

func readSubscriptionEvents(t *testing.T, events <-chan *PotentialEvent, eose <-chan bool, errors <-chan error, wg *sync.WaitGroup, expected int) {
	var counter int
	for {
		select {
		case <-events:
			counter++
			wg.Done()

		case <-eose:
			t.Logf("eose received counter=%v", counter)
			if counter != expected {
				t.Fatalf("got more events than expected, want=%d got=%d", expected, counter)
			}
			return

		case err := <-errors:
			t.Fatal(err)

		case <-time.After(time.Second * 30):
			t.Fatalf("timeout/1 counter=%d", counter)
		}
	}
}

func TestSubscriptionProcess(t *testing.T) {

	tests := createStoreCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			filters := nip01.NewSubscriptionFilterGroup()

			test.init(t, store)
			test.setupFilters(filters)

			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sub, events, errors, eose := NewSubscription("sub-xxxxxxxx", CreateQueryWithFilters(t, store, filters))
			go sub.Start(ctx, &wg)

			readSubscriptionEvents(t, events, eose, errors, &wg, test.expected)

			test.onEOSE(t, store)

			if test.expectedPostEOSE == 0 {
				select {
				case ev := <-events:
					t.Fatalf("unexpected packet, got=%T", ev)

				case err := <-errors:
					t.Fatal(err)

				case <-time.After(time.Second * 1):
					return
				}

			} else {
				var counter int
				for i := 0; i < test.expectedPostEOSE; i++ {
					select {
					case <-events:
						counter++

					case err := <-errors:
						t.Fatal(err)

					case <-time.After(time.Second * 1):
						t.Fatalf("timeout/2 counter=%d", counter)
					}
				}
			}

			select {
			case ev := <-events:
				t.Fatalf("got more events than expected, got=%+v", ev)

			case err := <-errors:
				t.Fatal(err)

			case <-time.After(time.Second * 1):
				t.Logf("completed")
				return
			}

		})
	}
}

// TestSubscriptionCombinedKindBurstDoesNotStarveFreshEvent exercises the
// fairness fix through the real mechanism that produced the original bug:
// Subscription's buffered, backpressured outgoing channel (eventBufferCapacity),
// not just storeScan's own ordering in isolation. A consumer that only ever
// reads up to that buffer's own capacity (i.e. never faster than the
// subscription's own backpressure threshold) must still observe a fresh
// event on a quiet kind well within that budget, even with a 200-event
// burst on a different kind sharing the same combined-kind filter.
//
// Both the burst and the fresh event are inserted only after EOSE, once the
// subscription is already in its live/continuous polling phase: the
// initial pre-EOSE fetch always uses the bounded (!fetchUntilEmpty) path,
// which this fix deliberately leaves untouched (see
// TestStoreFetchBoundedCombinedKindRespectsLimitExactly) -- the production
// bug, and the fix, are both specifically about the live tail.
func TestSubscriptionCombinedKindBurstDoesNotStarveFreshEvent(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1, 7}, Limit: 500})

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub, events, errCh, eose := NewSubscription("sub-fairness", newQuery(t, store, filters))
	go sub.Start(ctx, &wg)

	select {
	case <-eose:
	case err := <-errCh:
		t.Fatalf("subscription error before EOSE: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("EOSE never arrived")
	}

	// Now that the subscription is live-polling (50ms ticks), a burst on
	// kind 1 lands alongside a single fresh kind-7 event -- the production
	// scenario of an ongoing kind-39100 flood while a kind-39101 pointer is
	// freshly published. Inserted in one InsertTestEvents call (one batch,
	// one bbolt transaction): two separate calls could straddle a 50ms tick
	// and split delivery across two ticks, which would make the burst
	// appear to "win" for reasons that have nothing to do with this fix.
	base := uint64(time.Now().Unix())
	burst := make([]*nip01.Event, 0, 201)
	for i := 0; i < 200; i++ {
		burst = append(burst, CreateEventWithTimestamp(t, 1, base+uint64(i)))
	}
	fresh := CreateEventWithTimestamp(t, 7, base+1000)
	InsertTestEvents(t, store, append(burst, fresh))

	// Pre-fix, handleEvents fully drained cursor 0 (kind 1's whole 200-event
	// burst) through this same channel before cursor 1 (kind 7) ever ran --
	// a consumer bounded to eventBufferCapacity-ish reads would never reach
	// the fresh event at all within that budget.
	const readBudget = eventBufferCapacity + 5
	found := false
	for i := 0; i < readBudget && !found; i++ {
		select {
		case ev := <-events:
			wg.Done()
			if ev.EventID == fresh.ID {
				found = true
			}
		case err := <-errCh:
			t.Fatalf("subscription error: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for delivery %d/%d", i, readBudget)
		}
	}
	if !found {
		t.Fatalf("fresh kind-7 event was not observed within the first %d deliveries (still starved behind the kind-1 burst)", readBudget)
	}
}

func BenchmarkSubscription(b *testing.B) {

	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(b *testing.B) {

			for i := 0; i < b.N; i++ {

				filters := nip01.NewSubscriptionFilterGroup()
				filters.Add(test.SubscriptionFilter)

				query, err := NewStoreQuery(store, filters)
				if err != nil {
					b.Fatal(err)
				}

				var wg sync.WaitGroup
				ctx, cancel := context.WithCancel(context.Background())

				sub, events, errors, eose := NewSubscription("sub-xxxxxxxx", query)
				go sub.Start(ctx, &wg)

				var counter int
			loop:
				for {
					select {
					case <-events:
						counter++
						wg.Done()

					case <-eose:
						break loop

					case err := <-errors:
						b.Fatal(err)
					}
				}

				wg.Wait()
				cancel()

				if counter != test.Expected {
					b.Fatalf("unexpected counter, want=%d got=%d", test.Expected, counter)
				}

			}

		})

	}

}
