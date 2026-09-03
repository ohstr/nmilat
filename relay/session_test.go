package relay

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

func TestSessionRequest(t *testing.T) {

	events := CreateEvents(t, 10, 1)
	store := newStoreWithEvents(t, events)
	conn := createWS(t, store)

	req := wire.NewRequestPacket("xxxx", CreateFilter([]int{}, 100))

	if err := conn.WriteJSON(req); err != nil {
		t.Fatalf("failed to send REQ payload")
	}

	for i := 0; i < len(events); i++ {
		var payload wire.ClientPayload
		if err := conn.ReadJSON(&payload); err != nil {
			t.Fatal(err)
		}

		t.Logf("paylaod=%T", payload.SubscriptionResponse)
	}

}

func processRequestCases(b testing.TB, store *EventStore, test ScanTestCase) {

	conn := createWS(b, store)
	defer func() { _ = conn.Close() }()

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(test.SubscriptionFilter)

	rp := wire.NewRequestPacket("sub-xxx", filters)
	err := conn.WriteJSON(rp)
	if err != nil {
		b.Fatalf("failed to write, err=%v", err)
	}

	var counter int
	for {
		var payload wire.ClientPayload
		if err := conn.ReadJSON(&payload); err != nil {
			b.Fatal(err)
		}
		if _, ok := payload.SubscriptionResponse.(*wire.EOSESubscriptionResponse); ok {
			break
		}
		counter++
	}

	if counter != test.Expected {
		b.Fatalf("unexpected counter got=%d want=%d", counter, test.Expected)
	}

}

func TestSessionRequestCases(b *testing.T) {
	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(b *testing.T) {
			processRequestCases(b, store, test)
		})
	}
}

func BenchmarkSessionRequest(b *testing.B) {
	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				processRequestCases(b, store, test)
			}
		})

	}
}
