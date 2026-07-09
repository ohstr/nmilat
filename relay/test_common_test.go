package relay

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
)

const publicKey = "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e"

func newQuery(t testing.TB, store *EventStore, filters *nip01.SubscriptionFilterGroup) *StoreQuery {
	q, err := NewStoreQuery(store, filters)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func CreateEvent(t testing.TB, kind int, tags ...[]string) *nip01.Event {
	return CreateEventWithTimestamp(t, kind, uint64(time.Now().Unix()), tags...)
}

func CreateEventWithTimestamp(t testing.TB, kind int, created_at uint64, tags ...[]string) *nip01.Event {
	ev := &nip01.Event{
		PubKey:    "3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e",
		CreatedAt: created_at,
		Kind:      kind,
		Tags:      tags,
		Content:   "test content",
	}
	privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return ev
}

var eventCounter int64

func CreateEvents(t testing.TB, count int, kind int, tags ...[]string) []*nip01.Event {
	var events []*nip01.Event
	baseTime := uint64(time.Now().Unix())
	for i := 0; i < count; i++ {
		offset := atomic.AddInt64(&eventCounter, 1)
		ev := CreateEventWithTimestamp(t, kind, baseTime+uint64(offset), tags...)
		ev.Content = fmt.Sprintf("content %d %d", i, offset)
		// We need to re-sign because content changed
		privKey := "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
		if err := ev.Sign(privKey); err != nil {
			t.Fatalf("failed to sign event: %v", err)
		}
		events = append(events, ev)
	}
	return events
}

func CreateEventsFromKinds(t testing.TB, kinds []int, IDOffset int, tags ...[]string) []*nip01.Event {
	var events []*nip01.Event
	for i, k := range kinds {
		ev := CreateEvent(t, k, tags...)
		ev.Content = fmt.Sprintf("content %d %d", i, IDOffset)
		ev.Sign("0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c")
		events = append(events, ev)
	}
	return events
}

func createSampleEvent(t testing.TB, kind int, tags ...[]string) *nip01.Event {
	return CreateEvent(t, kind, tags...)
}

func createLowerIDEvent(t testing.TB, kind int) *nip01.Event {
	events := CreateEvents(t, 1, kind)
	return events[0]
}

func newStore(t testing.TB) *EventStore {
	f, err := os.CreateTemp("", "test.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Cleanup
	t.Cleanup(func() {
		os.Remove(f.Name())
	})

	store, err := NewEventStore(f.Name(), &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		store.Close()
	})

	return store
}

func newStoreWithEvents(t testing.TB, events []*nip01.Event) *EventStore {
	store := newStore(t)
	InsertTestEvents(t, store, events)
	return store
}

func InsertTestEvents(t testing.TB, store *EventStore, events []*nip01.Event) {
	task := NewEventInsertTask(events)
	store.Execute(context.Background(), task)
	select {
	case <-task.Completed():
	case err := <-task.Errors():
		if !errors.Is(err, ErrEventDuplicated) {
			t.Fatalf("failed to insert events: %v", err)
		}
	}
}

func OpenBenchStore(b testing.TB) *EventStore {
	return newStore(b)
}

func CreateFilter(kinds []int, limit int) *nip01.SubscriptionFilterGroup {
	g := nip01.NewSubscriptionFilterGroup()
	// If kinds is empty, use nil to indicate "all kinds" (standard nostr filter behavior)
	// although nip01.SubscriptionFilter doesn't strict enforce this,
	// Match() logic: if sf.Kinds != nil ...
	// If we pass []int{}, it is != nil but matches nothing.
	// So we must pass nil.
	if len(kinds) == 0 {
		kinds = nil
	}

	g.Add(&nip01.SubscriptionFilter{
		Kinds: kinds,
		Limit: limit,
	})
	return g
}

func CreateQueryWithFilters(t testing.TB, store *EventStore, filters *nip01.SubscriptionFilterGroup) *StoreQuery {
	q, err := NewStoreQuery(store, filters)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// WS and Scan Helpers

func createWS(t testing.TB, store *EventStore) *websocket.Conn {
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	handler := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)))
	srv := httptest.NewServer(handler)
	t.Cleanup(func() { srv.Close() })

	u := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

type ScanTestCase struct {
	Name               string
	SubscriptionFilter *nip01.SubscriptionFilter
	Expected           int
}

func CreateTestCases() []ScanTestCase {
	return []ScanTestCase{
		{
			Name: "Filter Kind 1",
			SubscriptionFilter: &nip01.SubscriptionFilter{
				Kinds: []int{1},
				Limit: 10,
			},
			Expected: 0, // Depends on events in store?
			// The tests init store with their own events or standard set?
			// TestPacketRequest uses OpenBenchStore which is empty, then CreateTestCases.
			// Wait, OpenBenchStore calls newStore (empty).
			// But packet_test.go uses `processPacketCase`.
			// processPacketCase initializes session with store.
			// Does it insert events?
			// packet_test.go:88: store := OpenBenchStore(b).
			// It does NOT insert events.
			// So Expected should be 0?
			// Unless test inserts events?
			// Logic in processPacketCase doesn't insert.
			// So default validation.
			// Maybe CreateTestCases was intended for BENCHMARK where we might prefill?
			// Or maybe OpenBenchStore loads a database?
			// My implementation of OpenBenchStore creates TEMP DB (empty).
			// So Expected=0.
		},
	}
}
