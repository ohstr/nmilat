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

// TestSubscriptionBackpressureDelaysButNeverLosesEvents reproduces the
// no-timeout blocking-send mechanism behind the delivery stall fixed in
// PR #19: storeScan.handleEvents' send into a subscription's outgoing
// channel (eventBufferCapacity, 55 slots) has no timeout, and
// Subscription.Start's poll loop calls Fetch synchronously on every tick --
// so once the channel is full, the next poll tick blocks inside Fetch until
// the consumer drains it, stalling delivery of any new matching event.
// (Needs 55+ backlogged events to trigger directly; see
// TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection for the
// more realistic small-burst trigger one layer downstream.)
//
// Can't be shown by just reading from the stalled subscription's own
// channel and expecting a timeout -- it's a full FIFO buffer, so any read
// just returns an already-queued filler event regardless of whether the
// fresh one is stuck behind it. Instead this mirrors the report's own
// methodology: compares the stalled subscription against a brand-new
// "retry" subscription opened after the same event is published. The retry
// sees it promptly; the stalled one is then confirmed to eventually
// deliver everything, including the fresh event, exactly once.
func TestSubscriptionBackpressureDelaysButNeverLosesEvents(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 500})

	// The "stalled" subscription: opened first (while the store is still
	// empty, so its own EOSE arrives immediately), its outgoing channel is
	// then deliberately never drained until the very end of this test --
	// simulating a slow/blocked downstream consumer.
	var stalledWG sync.WaitGroup
	stalledCtx, stalledCancel := context.WithCancel(context.Background())
	defer stalledCancel()
	stalledSub, stalledEvents, stalledErrs, stalledEOSE := NewSubscription("sub-stalled", newQuery(t, store, filters))
	go stalledSub.Start(stalledCtx, &stalledWG)
	select {
	case <-stalledEOSE:
	case err := <-stalledErrs:
		t.Fatalf("stalled subscription error before EOSE: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("stalled subscription: EOSE never arrived")
	}

	// Fill its outgoing channel to capacity and let it settle -- it has
	// nowhere else to put these, so within a handful of 50ms ticks they
	// should all be sitting there, unread.
	base := uint64(time.Now().Unix())
	filler := make([]*nip01.Event, 0, eventBufferCapacity)
	for i := 0; i < eventBufferCapacity; i++ {
		filler = append(filler, CreateEventWithTimestamp(t, 1, base+uint64(i)))
	}
	InsertTestEvents(t, store, filler)
	time.Sleep(300 * time.Millisecond)
	if n := len(stalledEvents); n != eventBufferCapacity {
		t.Fatalf("setup: stalled subscription's outgoing channel has %d buffered events, want exactly %d (full)", n, eventBufferCapacity)
	}

	// Publish the event under test while the stalled subscription's
	// buffer is still full and undrained.
	fresh := CreateEventWithTimestamp(t, 1, base+uint64(eventBufferCapacity)+1000)
	InsertTestEvents(t, store, []*nip01.Event{fresh})

	// A brand-new subscription opened after fresh was published, nothing
	// backlogged. Its own initial fetch finds 56 matching events (one more
	// than eventBufferCapacity), so events and EOSE must be read from the
	// same select or it'd hit the same full-buffer deadlock as above.
	var freshWG sync.WaitGroup
	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()
	freshSub, freshEvents, freshErrs, freshEOSE := NewSubscription("sub-fresh-retry", newQuery(t, store, filters))
	go freshSub.Start(freshCtx, &freshWG)

	foundOnFreshSub := false
	for i := 0; i < eventBufferCapacity+10 && !foundOnFreshSub; i++ {
		select {
		case ev := <-freshEvents:
			freshWG.Done()
			if ev.EventID == fresh.ID {
				foundOnFreshSub = true
			}
		case <-freshEOSE:
			// keep looping: the fresh event may legitimately arrive as
			// part of the initial fetch, before or after EOSE
		case err := <-freshErrs:
			t.Fatalf("fresh subscription error: %v", err)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("fresh subscription: timed out waiting for the fresh event")
		}
	}
	if !foundOnFreshSub {
		t.Fatal("fresh subscription never observed the newly-published event")
	}

	// Finally, confirm nothing is actually lost on the stalled side
	// either: draining it now delivers every event, including fresh,
	// exactly once.
	seen := make(map[string]int)
	total := eventBufferCapacity + 1
	deadline := time.After(2 * time.Second)
	for len(seen) < total {
		select {
		case ev := <-stalledEvents:
			seen[ev.EventID]++
			stalledWG.Done()
		case err := <-stalledErrs:
			t.Fatalf("stalled subscription error while draining: %v", err)
		case <-deadline:
			t.Fatalf("timed out draining stalled subscription: got %d/%d distinct events", len(seen), total)
		}
	}
	if seen[fresh.ID] != 1 {
		t.Fatalf("fresh event delivered %d times via the stalled subscription, want exactly 1", seen[fresh.ID])
	}
	for _, ev := range filler {
		if seen[ev.ID] != 1 {
			t.Fatalf("filler event %s delivered %d times, want exactly 1", ev.ID, seen[ev.ID])
		}
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
