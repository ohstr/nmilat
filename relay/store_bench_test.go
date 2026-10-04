package relay

import (
	"context"
	"sync"
	"testing"
)

// BenchmarkDeliverREQ measures the cost of scanning and delivering a REQ's
// matching events the way handlers.go's StandardRequestHandler actually
// does today: each *PotentialEvent off the subscription channel is replied
// to directly, using the bytes collectBatch already captured at scan time
// (PotentialEvent.Bytes) -- no second store read per event.
func BenchmarkDeliverREQ(b *testing.B) {
	benchmarkDeliverREQ(b, func(_ *EventStore, pe *PotentialEvent) []byte {
		return pe.Bytes
	})
}

// BenchmarkDeliverREQLegacyPerEventStoreRead benchmarks the same scan path,
// but reproduces the per-event cost this change retires: a fresh
// store.FindEventBytes call -- its own bolt read transaction -- for every
// delivered event, discarding the bytes collectBatch already loaded. Kept
// as a permanent before/after comparison; run both together with
// `go test -bench=BenchmarkDeliverREQ -benchmem ./relay/...` (or `just
// bench`). See docs/relay-scan-transaction-blocks-under-load.md.
func BenchmarkDeliverREQLegacyPerEventStoreRead(b *testing.B) {
	benchmarkDeliverREQ(b, func(store *EventStore, pe *PotentialEvent) []byte {
		bytes, err := store.FindEventBytes(pe.Evsid)
		if err != nil {
			b.Fatalf("FindEventBytes: %v", err)
		}
		return bytes
	})
}

func benchmarkDeliverREQ(b *testing.B, deliver func(store *EventStore, pe *PotentialEvent) []byte) {
	const eventCount = 200

	store := OpenBenchStore(b)
	InsertTestEvents(b, store, CreateEvents(b, eventCount, 1))

	filters := CreateFilter([]int{1}, eventCount)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		query, err := NewStoreQuery(store, filters)
		if err != nil {
			b.Fatal(err)
		}

		out := make(chan *PotentialEvent)
		var wg sync.WaitGroup
		var delivered int

		go func() {
			for pe := range out {
				_ = deliver(store, pe)
				delivered++
				wg.Done()
			}
		}()

		if err := query.Fetch(context.Background(), out, &wg, false); err != nil {
			b.Fatal(err)
		}
		wg.Wait()
		close(out)

		if delivered != eventCount {
			b.Fatalf("delivered %d events, want %d", delivered, eventCount)
		}
	}
}
