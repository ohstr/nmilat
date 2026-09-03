package relay

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"

	bolt "go.etcd.io/bbolt"
)

type KindTable struct {
	kind   int
	target int
}

func appendStoreFromKindTable(t testing.TB, store *EventStore, table []KindTable) {

	kinds := []int{}
	for _, k := range table {
		for i := 0; i < k.target; i++ {
			kinds = append(kinds, k.kind)
		}
	}
	InsertTestEvents(t, store, CreateEventsFromKinds(t, kinds, 10000))
}

type StoreTestCase struct {
	name             string
	init             func(*testing.T, *EventStore)
	onEOSE           func(*testing.T, *EventStore)
	setupFilters     func(filter *nip01.SubscriptionFilterGroup)
	expected         int
	expectedPostEOSE int
}

func createStoreCases() []StoreTestCase {

	initStore := func(t *testing.T, store *EventStore) {
		kinds := []int{1, 1, 1, 1, 2, 2, 2, 4, 4, 1099}
		events := CreateEventsFromKinds(t, kinds, 0)
		InsertTestEvents(t, store, events)
	}

	initStore_2 := func(t *testing.T, store *EventStore) {
		tb := []KindTable{
			{1, 500},
			{2, 200},
			{4, 100},
			{6, 20},
		}
		appendStoreFromKindTable(t, store, tb)
	}

	initStore_3 := func(t *testing.T, store *EventStore) {
		tb := []KindTable{
			{1, 500},
			{0, 2},
			{3, 2},
		}
		appendStoreFromKindTable(t, store, tb)
	}

	onEOSE := func(t *testing.T, store *EventStore) {
		kinds := []int{1, 1, 1, 1, 2, 2, 2, 4, 4, 1099}
		InsertTestEvents(t, store, CreateEventsFromKinds(t, kinds, len(kinds)*2))
	}

	tests := []StoreTestCase{
		{
			"case_0",
			initStore_2, func(*testing.T, *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{99},
					Limit: 500,
				})
			},
			0,
			0,
		},
		{
			"case_1",
			initStore_2, func(*testing.T, *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 500,
				})
			},
			500,
			0,
		},
		{
			"case_2",
			initStore_2, func(*testing.T, *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 100,
				})
			},
			100,
			0,
		},
		{
			"case_3",
			initStore_2, func(*testing.T, *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 1000,
				})
			},
			500,
			0,
		},
		{
			"case_4",
			initStore_2, func(*testing.T, *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{6},
					Limit: 20,
				})
			},
			20,
			0,
		},

		{
			"case_duo_0",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 1,
				})
			},
			1,
			4,
		},
		{
			"case_duo_0_bis",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 2, 4, 1099}, // 4, 3, 2, 1 => cLimit=3 =>
					Limit: 10,
				})
			},
			10,
			10,
		},
		{
			"case_duo_1",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 2, 4}, // 4, 3, 2 //
					Limit: 3,
				})
			},
			3,
			9,
		},

		{
			"case_duo_2",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 4,
				})
			},
			4,
			4,
		},
		{
			"case_duo_2_bis",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 2,
				})
			},
			2,
			4,
		},
		{
			"case_duo_3",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{2, 4},
					Limit: 5,
				})
			},
			5,
			5,
		},
		{
			"case_duo_4",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{6},
					Limit: 0,
				})
			},
			0,
			0,
		},
		{
			"case_duo_5",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{7},
					Limit: 10,
				})
			},
			0,
			0,
		},
		{
			"case_duo_6",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: nil,
					Limit: 1, // 0 is ignored as the min is 1
				})
			},
			1,
			10,
		},
		{
			"case_duo_7",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 2, 4}, // 4, 3, 2
					Limit: 1,
				})
			},
			1,
			9, // 14
		},
		{
			"case_duo_8",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: nil,
					Limit: 1,
				})
			},
			1,
			10,
		},

		{
			"case_double_1",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 2}, // 4, 3 // 2, 2 => 4 | 7
					Limit: 4,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{4}, // 2 => 1 | 2
					Limit: 1,
				})
			},
			5,
			9,
		},
		{
			"case_double_2",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 2}, // 4, 3 // 2, 2 => 4 | 7
					Limit: 4,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{7},
					Limit: 10,
				})
			},
			4,
			7,
		},
		{
			"case_double_3",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{8, 9},
					Limit: 4,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1},
					Limit: 10,
				})
			},
			4,
			4,
		},
		{
			"case_double_4",
			initStore, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{8, 9},
					Limit: 4,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{6},
					Limit: 10,
				})
			},
			0,
			0,
		},
		{
			"case_bulk_1",
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 30; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-2000+int64(i))))
				}
				InsertTestEvents(t, store, events)

				initStore(t, store)
			},
			onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 6, 8, 9},
					Limit: 16,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{20},
					Limit: 100,
				})
			},
			16,
			4,
		},
		{
			"case_bulk_2",
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 10; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-2000+int64(i))))
				}
				for i := 0; i < 20; i++ {
					events = append(events, CreateEventWithTimestamp(t, 2, uint64(int64(time.Now().Unix())-3000+int64(i))))
				}
				for i := 0; i < 30; i++ {
					events = append(events, CreateEventWithTimestamp(t, 4, uint64(int64(time.Now().Unix())-4000+int64(i))))
				}
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 10; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-1000+int64(i))))
				}
				InsertTestEvents(t, store, events)
			},
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{1, 4},
					Limit: 5,
				})
				filter.Add(&nip01.SubscriptionFilter{
					Kinds: []int{2},
					Limit: 20,
				})
			},
			25,
			10,
		},
		{
			"case_tags_1",
			func(t *testing.T, store *EventStore) {
				events := CreateEventsFromKinds(t, []int{1, 1}, -2000,
					[]string{"e", "test"},
				)
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds:   []int{1},
					Tags:    make(map[string][]string),
					Authors: []string{publicKey},
					Limit:   10,
				}
				f.Tags["e"] = []string{"test"}
				filter.Add(f)
			},
			2,
			0,
		},
		{
			"case_tags_2",
			func(t *testing.T, store *EventStore) {
				events := CreateEventsFromKinds(t, []int{1, 1}, -2000,
					[]string{"e", "test"},
				)
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds: []int{1},
					Tags:  make(map[string][]string),
					Limit: 10,
				}
				f.Tags["e"] = []string{"wrong"}
				filter.Add(f)
			},
			0,
			0,
		},

		{
			"case_tags_3",
			func(t *testing.T, store *EventStore) {
				events := CreateEventsFromKinds(t, []int{1, 1}, -2000,
					[]string{"e", "test"},
				)
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds:   []int{1},
					Tags:    make(map[string][]string),
					Authors: []string{"0c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"},
					Limit:   10,
				}
				filter.Add(f)
			},
			0,
			0,
		},

		{
			"case_tags_4",
			func(t *testing.T, store *EventStore) {
				events := CreateEventsFromKinds(t, []int{1, 1}, -2000,
					[]string{"e", "test"},
				)
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds:   []int{1},
					Tags:    make(map[string][]string),
					Authors: []string{"0c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"},
					Limit:   10,
				}
				f.Tags["e"] = []string{"wrong"}
				filter.Add(f)
			},
			0,
			0,
		},

		{
			"case_tags_5",
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 10; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-2000+int64(i)), []string{"h", strconv.FormatInt(int64(i+1), 10)}))
				}
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds: []int{1},
					Tags:  make(map[string][]string),
				}
				f.Tags["h"] = []string{"1"}
				filter.Add(f)
			},
			0,
			0,
		},

		{
			"case_created_1",
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 30; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-10000+int64(i)), []string{"e", "test"}))
				}

				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {
				events := []*nip01.Event{}
				for i := 0; i < 15; i++ {
					events = append(events, CreateEventWithTimestamp(t, 1, uint64(int64(time.Now().Unix())-5000+int64(i)), []string{"e", "test"}))
				}
				InsertTestEvents(t, store, events)
			},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds: []int{1},
					Tags:  make(map[string][]string),
					Since: uint64(time.Now().Unix()) - 40000,
					Limit: 10,
				}
				f.Tags["e"] = []string{"test"}
				filter.Add(f)
			},
			10,
			15,
		},

		{
			"case_created_2",
			func(t *testing.T, store *EventStore) {
				events := CreateEventsFromKinds(t, []int{1, 1}, -10000,
					[]string{"e", "test"},
				)
				InsertTestEvents(t, store, events)
			},
			func(t *testing.T, store *EventStore) {},
			func(filter *nip01.SubscriptionFilterGroup) {
				f := &nip01.SubscriptionFilter{
					Kinds: []int{1},
					Tags:  make(map[string][]string),
					Since: uint64(time.Now().Unix()) + 100,
					Limit: 10,
				}
				f.Tags["e"] = []string{"test"}
				filter.Add(f)
			},
			0,
			0,
		},
		{
			"case_kindAuthor_1",
			initStore_3, onEOSE,
			func(filter *nip01.SubscriptionFilterGroup) {
				filter.Add(&nip01.SubscriptionFilter{
					Kinds:   []int{0, 3},
					Authors: []string{publicKey},
					Limit:   100,
				})
			},
			2,
			0,
		},
	}

	return tests
}

func readEvents(t testing.TB, query *StoreQuery, fetchUntilEmpty bool) int {

	var counter int

	events := make(chan *PotentialEvent)
	wg := sync.WaitGroup{}

	go func() {
		for range events {
			counter++
			wg.Done()
		}
	}()

	err := query.Fetch(context.Background(), events, &wg, fetchUntilEmpty)
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait()

	return counter
}

func TestStoreIndexableTags(t *testing.T) {

	tests := []struct {
		event           *nip01.Event
		expectedEntries int
	}{
		{
			CreateEvent(t, 1,
				[]string{"e", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e", "http://"},
			),
			1,
		},
		{
			CreateEvent(t, 1,
				[]string{"test", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e", "wss://"},
			),
			0,
		},
		{
			CreateEvent(t, 1,
				[]string{"e", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"},
				[]string{"test", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"},
				[]string{"p", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e", "http://"},
			),
			2,
		},
		{
			CreateEvent(t, 1,
				[]string{"test", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"},
				[]string{"p", "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e", "http://"},
				[]string{"d", "10"},
			),
			2,
		},
	}

	for ti, test := range tests {
		t.Run(fmt.Sprintf("tags%d", ti), func(t *testing.T) {
			entries, err := prepareIndexableTags(test.event.Tags, defaultMaxIndexableTags)

			if len(entries) != test.expectedEntries || err != nil {
				t.Fatalf("failed, want=%d got=%d", test.expectedEntries, len(entries))
			}

		})
	}
}

func TestStoreInsert(t *testing.T) {

	tests := []struct {
		name          string
		insertFunc    func(t testing.TB, store *EventStore)
		expectedCount int
	}{
		{"classic", func(t testing.TB, store *EventStore) {
			InsertTestEvents(t, store, CreateEvents(t, 10, 1))
		}, 10},

		{"duplicated", func(t testing.TB, store *EventStore) {
			events := CreateEvents(t, 1, 1)
			for _, event := range []*nip01.Event{events[0], events[0]} {
				task := NewEventInsertTask([]*nip01.Event{event})
				store.Execute(context.Background(), task)

				select {
				case <-task.Completed():
				case err := <-task.Errors():
					if errors.Is(err, ErrEventDuplicated) {
						t.Logf("%v", err)
					} else {
						t.Fatalf("failed to insert event, error=%v", err)
					}
				}
			}
		}, 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			test.insertFunc(t, store)

			events, err := store.FetchAll()
			if err != nil {
				t.Fatalf("failed to fetch events, error= %v", err)
			}

			if len(events) != test.expectedCount {
				t.Fatalf("event count mismatch. got %d expected %d", len(events), test.expectedCount)
			}

		})
	}

}

func TestStoreReplaceable(t *testing.T) {

	tests := []struct {
		name       string
		insertFunc func(t testing.TB, store *EventStore) *nip01.Event
	}{
		{"replaceable", func(t testing.TB, store *EventStore) *nip01.Event {
			events := CreateEvents(t, 1000, 15_001)

			InsertTestEvents(t, store, events)
			return events[len(events)-1]
		}},

		{"param", func(t testing.TB, store *EventStore) *nip01.Event {
			events := CreateEvents(t, 1000, 35_001, []string{"d", "test"})

			InsertTestEvents(t, store, events)
			return events[len(events)-1]
		}},

		{"diffTimestamp", func(t testing.TB, store *EventStore) *nip01.Event {
			now := uint64(time.Now().Unix())
			ev1 := CreateEventWithTimestamp(t, 0, now)
			ev1.Content = "old"
			if err := ev1.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			ev2 := CreateEventWithTimestamp(t, 0, now+10)
			ev2.Content = "new"
			if err := ev2.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			events := []*nip01.Event{ev1, ev2}
			InsertTestEvents(t, store, events)
			return ev2
		}},

		{"lowerID", func(t testing.TB, store *EventStore) *nip01.Event {
			events := []*nip01.Event{}
			now := uint64(time.Now().Unix())
			ev1 := CreateEventWithTimestamp(t, 0, now)
			ev1.Content = "a"
			if err := ev1.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			ev2 := CreateEventWithTimestamp(t, 0, now)
			ev2.Content = "b"
			if err := ev2.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			events = append(events, ev1, ev2)
			InsertTestEvents(t, store, events)

			if ev1.ID < ev2.ID {
				return ev1
			}
			return ev2
		}},

		{"higherID", func(t testing.TB, store *EventStore) *nip01.Event {
			now := uint64(time.Now().Unix())
			ev1 := CreateEventWithTimestamp(t, 0, now)
			ev1.Content = "a"
			if err := ev1.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			ev2 := CreateEventWithTimestamp(t, 0, now)
			ev2.Content = "b"
			if err := ev2.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"); err != nil {
				t.Fatal(err)
			}

			events := []*nip01.Event{ev1, ev2}
			InsertTestEvents(t, store, events)

			if ev1.ID < ev2.ID {
				return ev1
			}
			return ev2
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			insertedEvent := test.insertFunc(t, store)

			events, err := store.FetchAll()
			if err != nil {
				t.Fatalf("failed to fetch events, error= %v", err)
			}

			if len(events) != 1 {
				t.Fatalf("event count mismatch. got %d expected %d", len(events), 1)
			}

			if insertedEvent.ID != events[0].ID {
				t.Fatalf("unexpected event")
			}

		})
	}

}

func TestStoreDeletionRequest(t *testing.T) {

	tests := []struct {
		name     string
		setup    func() ([]*nip01.Event, *nip01.Event)
		expected int
	}{
		{
			"all events",
			func() ([]*nip01.Event, *nip01.Event) {
				events := CreateEvents(t, 100, 1)

				var tagsEvents [][]string
				for _, ev := range events {
					tagsEvents = append(tagsEvents, []string{"e", ev.ID})
				}
				tagsEvents = append(tagsEvents, []string{"k", "1"})

				delEvent := CreateEvent(t, 5, tagsEvents...)

				return events, delEvent
			},
			1,
		},
		{
			"subset of events",
			func() ([]*nip01.Event, *nip01.Event) {
				events := CreateEvents(t, 100, 1)

				var tagsEvents [][]string
				for _, ev := range events[:20] {
					tagsEvents = append(tagsEvents, []string{"e", ev.ID})
				}
				tagsEvents = append(tagsEvents, []string{"k", "1"})

				delEvent := CreateEvent(t, 5, tagsEvents...)

				return events, delEvent
			},
			81,
		},
		{
			"replaceable",
			func() ([]*nip01.Event, *nip01.Event) {
				events := CreateEventsFromKinds(t, []int{15_001, 15_001, 15_002, 15_002, 15_002, 15_002, 15_003}, -10_000)

				delEvent := CreateEventWithTimestamp(t, 5, uint64(time.Now().Unix()+100),
					[]string{"a", fmt.Sprintf("%d:%s:", 15_001, publicKey)},
					[]string{"a", fmt.Sprintf("%d:%s:", 15_003, publicKey)},
				)
				return events, delEvent
			},
			2,
		},
		{
			"param",
			func() ([]*nip01.Event, *nip01.Event) {
				events := CreateEvents(t, 10, 35_001, []string{"d", "test_1"})
				events = append(events, CreateEvents(t, 10, 35_002, []string{"d", "test_2"})...)
				events = append(events, CreateEvents(t, 10, 35_003, []string{"d", "test_3"})...)

				// CreateEvents timestamps events off a shared, monotonically increasing
				// counter (baseTime+offset), so the offset can already exceed a fixed
				// "now+100" margin once enough events have been created earlier in the
				// suite. Base the deletion request's timestamp on the actual max
				// CreatedAt among the events it targets instead, so the "a" tags'
				// Until bound is always safely after them regardless of prior state.
				var maxCreatedAt uint64
				for _, ev := range events {
					if ev.CreatedAt > maxCreatedAt {
						maxCreatedAt = ev.CreatedAt
					}
				}

				delEvent := CreateEventWithTimestamp(t, 5, maxCreatedAt+100,
					[]string{"a", fmt.Sprintf("%d:%s:%s", 35_001, publicKey, "test_1")},
					[]string{"a", fmt.Sprintf("%d:%s:%s", 35_003, publicKey, "test_3")},
				)

				return events, delEvent
			},
			2,
		},
		{
			"del of del",
			func() ([]*nip01.Event, *nip01.Event) {
				events := CreateEvents(t, 3, 5)
				delEvent := CreateEvent(t, 5,
					[]string{"e", events[0].ID},
					[]string{"e", events[1].ID},
					[]string{"a", fmt.Sprintf("%d:%s:%s", 5, publicKey, "")},
					[]string{"k", "5"},
				)

				return events, delEvent
			},
			4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newStore(t)
			defer store.Close()

			events, delEvent := test.setup()
			InsertTestEvents(t, store, events)

			err := store.InsertEvents(context.Background(), []*nip01.Event{delEvent})
			if err != nil {
				t.Fatal(err)
			}

			remainingEvents, err := store.FetchAll()
			if err != nil {
				t.Fatal(err)
			}

			if len(remainingEvents) != test.expected {
				t.Fatalf("mismatched remaining events got=%d want=%d", len(remainingEvents), test.expected)
			}

		})
	}

}

func TestStoreFetchAll(t *testing.T) {

	events := CreateEvents(t, 10, 1)
	store := newStoreWithEvents(t, events)

	if data, err := store.FetchAll(); err != nil {
		t.Fatalf("failed to fetch all events. error=%v", err)
	} else if len(data) != len(events) {
		t.Fatalf("event count mismatch: expected=%d, got=%d.", len(events), len(data))
	}
}

func TestStoreScan(t *testing.T) {

	tests := createStoreCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			filters := nip01.NewSubscriptionFilterGroup()

			test.init(t, store)
			test.setupFilters(filters)

			var counter int
			for _, filter := range filters.GetAll() {

				scan, err := newStoreScan(store, filter, make(map[uint64]bool))
				if err != nil {
					t.Fatal(err)
				}

				potEvents := make(chan *PotentialEvent)
				wgScan := &sync.WaitGroup{}

				go func() {
					for range potEvents {
						counter++
						wgScan.Done()
					}
				}()

				err = scan.Scan(context.Background(), potEvents, wgScan, false)
				if err != nil {
					t.Fatal(err)
				}

				wgScan.Wait()
				close(potEvents)

			}

			if test.expected != counter {
				t.Fatalf("unexpected counter, want=%d got=%d", test.expected, counter)
			}

		})
	}
}

func TestStoreFetch(t *testing.T) {

	tests := createStoreCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			filters := nip01.NewSubscriptionFilterGroup()

			test.init(t, store)
			test.setupFilters(filters)

			query := newQuery(t, store, filters)

			counter := readEvents(t, query, false)

			if counter != test.expected {
				t.Fatalf("unexpected counter, want=%d got=%d", test.expected, counter)
			}

		})
	}

}

func TestStoreDoubleFetch(t *testing.T) {

	tests := createStoreCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			filters := nip01.NewSubscriptionFilterGroup()

			test.init(t, store)
			test.setupFilters(filters)

			query, err := NewStoreQuery(store, filters)
			if err != nil {
				t.Fatal(err)
			}

			counter := readEvents(t, query, false)

			if counter != test.expected {
				t.Fatalf("unexpected eose counter, want=%d got=%d", test.expected, counter)
			}

			t.Logf("eose.events=%d", counter)

			/////////////////////

			test.onEOSE(t, store)

			counter = readEvents(t, query, true)

			if counter != test.expectedPostEOSE {
				t.Fatalf("unexpected counter, want=%d got=%d", test.expectedPostEOSE, counter)
			}

		})
	}

}

func TestStoreFetchCases(b *testing.T) {

	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(t *testing.T) {

			filters := nip01.NewSubscriptionFilterGroup()
			filters.Add(test.SubscriptionFilter)

			query, err := NewStoreQuery(store, filters)
			if err != nil {
				b.Fatal(err)
			}

			counter := readEvents(t, query, false)

			if counter != test.Expected {
				b.Fatalf("unexpected counter, want=%v got=%v", test.Expected, counter)
			}

		})
	}
}

func TestStoreScanCases(b *testing.T) {

	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(t *testing.T) {

			scan, err := newStoreScan(store, test.SubscriptionFilter, make(map[uint64]bool))
			if err != nil {
				t.Fatal(err)
			}

			potEvents := make(chan *PotentialEvent)
			wg := &sync.WaitGroup{}
			var counter int
			go func() {
				for range potEvents {
					counter++
					wg.Done()
				}
			}()

			err = scan.Scan(context.Background(), potEvents, wg, false)
			if err != nil {
				t.Fatal(err)
			}

			wg.Wait()
			close(potEvents)

			if test.Expected != counter {
				t.Fatalf("unexpected counter, want=%d got=%d", test.Expected, counter)
			}

		})
	}
}

// TestStoreInsertConcurrentNoRace hammers InsertEvents from many goroutines
// at once, the exact shape handleTasks' per-batch timer (relay/store.go)
// has to stay race-free under: multiple handleTasks workers pulling from
// the same taskQueue, each racing to arm/stop/nil its own timer and flush
// its own batch into a shared bolt db. Run with -race in CI.
func TestStoreInsertConcurrentNoRace(t *testing.T) {
	store := newStore(t)

	const writers = 50
	const perWriter = 20

	events := CreateEvents(t, writers*perWriter, 1)

	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(batch []*nip01.Event) {
			defer wg.Done()
			for _, ev := range batch {
				if err := store.InsertEvents(context.Background(), []*nip01.Event{ev}); err != nil {
					errCh <- err
					return
				}
			}
		}(events[w*perWriter : (w+1)*perWriter])
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent insert failed: %v", err)
	}

	all, err := store.FetchAll()
	if err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}
	if len(all) != writers*perWriter {
		t.Fatalf("expected %d events, got %d", writers*perWriter, len(all))
	}
}

// BenchmarkStoreInsert measures the real write-to-relay path: each event
// goes through InsertEvents -> the taskQueue -> the async batching worker
// -> a bolt transaction, same as a live EVENT message would.
func BenchmarkStoreInsert(b *testing.B) {
	store := OpenBenchStore(b)
	defer store.Close()

	// Pre-generate and sign every event before starting the timer so the
	// benchmark measures store/bolt cost, not event construction or signing.
	events := CreateEvents(b, b.N, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.InsertEvents(context.Background(), []*nip01.Event{events[i]}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStoreInsertConcurrent measures write throughput when many
// callers submit at once, the shape a live relay actually sees (multiple
// client connections publishing concurrently): the batching worker fills
// up toward BatchSize instead of idling until the BatchInterval ticker
// fires, so this is expected to run far faster per-op than the strictly
// sequential BenchmarkStoreInsert.
func BenchmarkStoreInsertConcurrent(b *testing.B) {
	store := OpenBenchStore(b)
	defer store.Close()

	events := CreateEvents(b, b.N, 1)
	var next atomic.Int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := next.Add(1) - 1
			if err := store.InsertEvents(context.Background(), []*nip01.Event{events[i]}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkStoreInsertBatch submits all b.N events in a single InsertEvents
// call -- one task, one bolt transaction -- to measure the raw storage
// ceiling with the BatchInterval ticker's per-round-trip wait paid once
// instead of once per event. This is the number a client that batches its
// own writes (or a bulk import) would actually see.
func BenchmarkStoreInsertBatch(b *testing.B) {
	store := OpenBenchStore(b)
	defer store.Close()

	events := CreateEvents(b, b.N, 1)

	b.ResetTimer()
	if err := store.InsertEvents(context.Background(), events); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkStoreFetch(b *testing.B) {
	store := OpenBenchStore(b)
	defer store.Close()
	tests := CreateTestCases()

	for _, test := range tests {
		b.Run(test.Name, func(t *testing.B) {
			for i := 0; i < t.N; i++ {

				filters := nip01.NewSubscriptionFilterGroup()
				filters.Add(test.SubscriptionFilter)

				query, err := NewStoreQuery(store, filters)
				if err != nil {
					b.Fatal(err)
				}

				counter := readEvents(t, query, false)

				if counter != test.Expected {
					b.Fatalf("unexpected counter, want=%v got=%v", test.Expected, counter)
				}

			}

		})
	}
}

func BenchmarkStoreScan(b *testing.B) {
	store := OpenBenchStore(b)
	defer store.Close()

	tests := CreateTestCases()

	for _, test := range tests {
		b.Run(test.Name, func(t *testing.B) {
			for i := 0; i < t.N; i++ {

				scan, err := newStoreScan(store, test.SubscriptionFilter, make(map[uint64]bool))
				if err != nil {
					t.Fatal(err)
				}

				potEvents := make(chan *PotentialEvent)
				wg := &sync.WaitGroup{}

				var counter int
				go func() {
					for range potEvents {
						counter++
						wg.Done()
					}
				}()

				err = scan.Scan(context.Background(), potEvents, wg, false)
				if err != nil {
					t.Fatal(err)
				}

				wg.Wait()
				close(potEvents)

				if test.Expected != counter {
					t.Fatalf("unexpected counter, want=%d got=%d", test.Expected, counter)
				}

			}

		})
	}
}

func BenchmarkStoreCursor(b *testing.B) {

	store := OpenBenchStore(b)
	defer store.Close()

	tests := []struct {
		name   string
		filter *nip01.SubscriptionFilter
	}{
		{
			"case_1",
			&nip01.SubscriptionFilter{
				Kinds: []int{0, 1, 3, 7},
				Limit: 500_000,
			},
		},
		{
			"case_2",
			&nip01.SubscriptionFilter{
				Kinds: []int{},
				Limit: 500_000,
			},
		},
	}

	for _, test := range tests {
		filter := test.filter
		b.Run(test.name, func(t *testing.B) {
			for i := 0; i < t.N; i++ {

				ss, err := newStoreScan(store, filter, make(map[uint64]bool))
				if err != nil {
					t.Fatal(err)
				}

				resumeKeys := make(map[int][]byte, len(ss.cursors))
				limit := int(math.Ceil(float64(ss.filter.Limit) / float64(len(ss.cursors))))
				// for ci := range ss.cursors {
				// 	ss.cursors[ci].firstCollect = true
				// }

				var totalCollected int

				_ = store.db.View(func(tx *bolt.Tx) error {
					for {
						for ci, cursor := range ss.cursors {

							var cursorLimit = limit
							if ss.filter.Limit-totalCollected < cursorLimit {
								cursorLimit = ss.filter.Limit - totalCollected
							}

							resumeKeys[ci], _, _ = cursor.Collect(context.Background(), tx, ss.scanContext, resumeKeys[ci], cursorLimit, false)
							totalCollected += ss.queueEvents.Len()
							ss.queueEvents.Clear()
							// for ss.queueEvents.Len() > 0 {
							// 	ss.queueEvents.PopEvent()
							// }
						}
						if totalCollected == filter.Limit {
							break
						}
					}

					// log.Debug().Msgf("totalCollected=%d", totalCollected)

					return nil
				})

			}

		})
	}
}

func TestStoreSimpleCursor(b *testing.T) {

	store := OpenBenchStore(b)
	defer store.Close()

	tests := []struct {
		name   string
		filter *nip01.SubscriptionFilter
	}{
		{
			"case_1",
			&nip01.SubscriptionFilter{
				Kinds: []int{},
				Limit: 1_000,
			},
		},
		{
			"case_2",
			&nip01.SubscriptionFilter{
				Kinds: []int{},
				Limit: 1_000,
			},
		},
	}

	for _, test := range tests {
		filter := test.filter
		b.Run(test.name, func(t *testing.T) {
			// for i := 0; i < t.N; i++ {

			ss, err := newStoreScan(store, filter, make(map[uint64]bool))
			if err != nil {
				t.Fatal(err)
			}

			_ = store.db.View(func(tx *bolt.Tx) error {
			loop:
				for _, cursor := range ss.cursors {

					c := tx.Bucket(ss.index).Cursor()

					c.Seek(cursor.maxKey)

					for k, v := c.Prev(); k != nil; k, _ = c.Prev() {
						completed, err := cursor.match(ss.scanContext, k, v)

						if completed || err != nil {
							break
						}

						if ss.queueEvents.Len() >= filter.Limit {
							break loop
						}
					}
				}

				potEvents := make(chan *PotentialEvent)
				wg := sync.WaitGroup{}

				go func() {
					for range potEvents {
						wg.Done()
					}
				}()

				sent, _ := ss.handleEvents(context.Background(), potEvents, tx, &wg, false)
				b.Logf("sent=%d", sent)

				wg.Wait()
				close(potEvents)

				return nil
			})

			// }

		})
	}
}

func TestStoreUnsortedEvents(t *testing.T) {

	knownEvents_p := CreateEventsFromKinds(t, []int{1, 1}, 20_000)
	knownEvents_n := CreateEventsFromKinds(t, []int{1, 1}, -10_000)

	tests := []struct {
		name       string
		filter     *nip01.SubscriptionFilter
		events_1   []*nip01.Event
		expected_1 int
		events_2   []*nip01.Event
		expected_2 int
	}{
		{
			"index_default_p",
			&nip01.SubscriptionFilter{
				Limit: 1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, 20_000), 7,
		},
		{
			"index_default_n",
			&nip01.SubscriptionFilter{
				Limit: 1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, -10_000), 7,
		},

		{
			"index_kind_p",
			&nip01.SubscriptionFilter{
				Kinds: []int{1},
				Limit: 1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, 20_000), 7,
		},

		{
			"index_kind_n",
			&nip01.SubscriptionFilter{
				Kinds: []int{1},
				Limit: 1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, -10_000), 7,
		},

		{
			"index_pubkey_p",
			&nip01.SubscriptionFilter{
				Authors: []string{publicKey},
				Limit:   1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, 20_000), 7,
		},

		{
			"index_pubkey_n",
			&nip01.SubscriptionFilter{
				Authors: []string{publicKey},
				Limit:   1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, -10_000), 7,
		},

		{
			"index_kind_pubkey_p",
			&nip01.SubscriptionFilter{
				Kinds:   []int{1},
				Authors: []string{publicKey},
				Limit:   1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, 20_000), 7,
		},

		{
			"index_kind_pubkey_n",
			&nip01.SubscriptionFilter{
				Kinds:   []int{1},
				Authors: []string{publicKey},
				Limit:   1,
			},
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), 1,
			CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, -10_000), 7,
		},

		{
			"index_id_p",
			&nip01.SubscriptionFilter{
				IDs:   []string{knownEvents_p[0].ID, knownEvents_p[1].ID},
				Limit: 1,
			},
			append(CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), knownEvents_p[0]), 1,
			append(CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, 20_000), knownEvents_p[1]), 1,
		},

		{
			"index_id_n",
			&nip01.SubscriptionFilter{
				IDs:   []string{knownEvents_n[0].ID, knownEvents_n[1].ID},
				Limit: 1,
			},
			append(CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1}, 10_000), knownEvents_n[0]), 1,
			append(CreateEventsFromKinds(t, []int{1, 1, 1, 1, 1, 1, 1}, -10_000), knownEvents_n[1]), 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			store := newStore(t)
			defer store.Close()

			InsertTestEvents(t, store, test.events_1)

			// scan #1
			scan, err := newStoreScan(store, test.filter, make(map[uint64]bool))
			if err != nil {
				t.Fatal(err)
			}

			potEvents := make(chan *PotentialEvent)
			wg := &sync.WaitGroup{}

			var counter int
			go func() {
				for range potEvents {
					counter++
					wg.Done()
				}
			}()

			err = scan.Scan(context.Background(), potEvents, wg, false)
			if err != nil {
				t.Fatal(err)
			}

			wg.Wait()
			close(potEvents)

			if counter != test.expected_1 {
				t.Fatalf("unexpected scan#1.counter  got=%d want=%d", counter, test.expected_1)
			}

			//////////////////////////////////////////////////////////////////////////////////////////
			// scan #2
			//////////////////////////////////////////////////////////////////////////////////////////

			InsertTestEvents(t, store, test.events_2)

			potEvents = make(chan *PotentialEvent)
			wg = &sync.WaitGroup{}

			counter = 0
			go func() {
				for range potEvents {
					counter++
					wg.Done()
				}
			}()

			err = scan.Scan(context.Background(), potEvents, wg, true)
			if err != nil {
				t.Fatal(err)
			}

			wg.Wait()
			close(potEvents)

			if counter != test.expected_2 {
				t.Fatalf("unexpected scan#2.counter  got=%d want=%d", counter, test.expected_2)
			}
		})
	}

}
