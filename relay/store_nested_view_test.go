package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// A query planned inside a caller's read transaction must not open a second
// one: once a writer waits to grow the file, the second read lock queues
// behind it and the writer waits for the first, forever. findEvents under
// QueryEvents' View did exactly that for a filter on two tag names.
func TestQueryInsideReadTxSurvivesAGrowingWrite(t *testing.T) {
	store := newStore(t)
	now := uint64(time.Now().Unix())
	ev := signEventAt(t, probeKeyA, 1, now, "x", []string{"t", "x"}, []string{"h", "g"})
	InsertTestEvents(t, store, []*nip01.Event{ev})

	filter := &nip01.SubscriptionFilter{Tags: map[string][]string{"t": {"x"}, "h": {"g"}}, BeforeID: ev.ID}
	done := make(chan error, 1)
	go func() {
		done <- store.db.View(func(tx *bolt.Tx) error {
			// A write big enough to remap the file, started while this
			// read transaction holds the mmap lock: it waits for it.
			writer := make(chan error, 1)
			go func() {
				writer <- store.db.Update(func(wtx *bolt.Tx) error {
					b, err := wtx.CreateBucketIfNotExists([]byte("nested-view-test"))
					if err != nil {
						return err
					}
					return b.Put([]byte("k"), make([]byte, 64<<20))
				})
			}()
			time.Sleep(300 * time.Millisecond)

			_, err := store.findEvents(context.Background(), tx, filter)
			select {
			case werr := <-writer:
				t.Errorf("writer finished inside the read: %v", werr)
			default:
			}
			return err
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("query inside a read transaction deadlocked against a growing write")
	}
}
