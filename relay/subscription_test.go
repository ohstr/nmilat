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
