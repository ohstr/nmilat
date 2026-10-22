package relay

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	bolt "go.etcd.io/bbolt"
)

const (
	zapReceiverA = "000000000000000000000000000000000000000000000000000000000000000a"
	zapReceiverB = "000000000000000000000000000000000000000000000000000000000000000b"
	zapReceiverC = "000000000000000000000000000000000000000000000000000000000000000c"
)

// putRawEvents stores events in the events bucket only, as if they predate
// the zap index, and returns the next free evsid.
func putRawEvents(t *testing.T, store *EventStore, first uint64, events ...*nip01.Event) uint64 {
	t.Helper()
	err := store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexEvents)
		for _, ev := range events {
			raw, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			if err := b.Put(itob(first), raw); err != nil {
				return err
			}
			first++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return first
}

// rawZap builds a valid receipt from a fixed sender and LNURL server.
func rawZap(t testing.TB, kind int, receiver, msats string, createdAt uint64) *nip01.Event {
	t.Helper()
	amount, err := strconv.ParseInt(msats, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return zapReceipt(t, zapSpec{
		Kind: kind, Sender: newTestKey(t, 1), Provider: newTestKey(t, 2),
		Recipient: receiver, Amount: amount, CreatedAt: createdAt,
	})
}

func topZapped(t *testing.T, store *EventStore) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, coin := range Coins() {
		ranked, err := store.TopZapped(context.Background(), 0, uint64(time.Now().Unix()+3600), coin, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, z := range ranked {
			out[z.Pubkey] += z.Total
		}
	}
	return out
}

func TestRebuildZapIndex_ReplacesStaleIndexAtomically(t *testing.T) {
	store := newStore(t)
	putRawEvents(t, store, 1,
		rawZap(t, 9735, zapReceiverA, "1000", 100),
		rawZap(t, 9521, zapReceiverB, "2000", 200),
		&nip01.Event{Kind: 1, CreatedAt: 150},
	)
	// A stale entry only the old index holds.
	if err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexZaps)
		if err != nil {
			return err
		}
		return putZap(b, rawZap(t, 9735, zapReceiverC, "9999", 50), 99)
	}); err != nil {
		t.Fatal(err)
	}
	if got := topZapped(t, store); got[zapReceiverC] != 9999 {
		t.Fatalf("stale entry missing before rebuild: %v", got)
	}

	var lastScanned int
	indexed, err := store.RebuildZapIndex(context.Background(), func(scanned, _ int) { lastScanned = scanned })
	if err != nil {
		t.Fatal(err)
	}
	if indexed != 2 || lastScanned != 3 {
		t.Fatalf("indexed=%d scanned=%d, want 2 and 3", indexed, lastScanned)
	}

	got := topZapped(t, store)
	want := map[string]uint64{zapReceiverA: 1000, zapReceiverB: 2000}
	if len(got) != len(want) || got[zapReceiverA] != 1000 || got[zapReceiverB] != 2000 {
		t.Fatalf("top zapped = %v, want %v", got, want)
	}

	if err := store.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(indexZaps) != nil {
			t.Error("old index bucket still present")
		}
		if buildingZapBucket(tx) != nil {
			t.Error("building pointer left set")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRebuildZapIndex_KeepsZapsStoredDuringRebuild(t *testing.T) {
	store := newStore(t)
	putRawEvents(t, store, 1, rawZap(t, 9735, zapReceiverA, "1000", 100))

	live := rawZap(t, 9735, zapReceiverB, "5000", uint64(time.Now().Unix()))
	inserted := false
	_, err := store.RebuildZapIndex(context.Background(), func(int, int) {
		if !inserted {
			inserted = true
			InsertTestEvents(t, store, []*nip01.Event{live})
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := topZapped(t, store); got[zapReceiverA] != 1000 || got[zapReceiverB] != 5000 {
		t.Fatalf("top zapped = %v, want both the scanned and the live zap", got)
	}
}

func TestRebuildZapIndex_RefusesConcurrentRebuild(t *testing.T) {
	store := newStore(t)
	putRawEvents(t, store, 1, rawZap(t, 9735, zapReceiverA, "1000", 100))

	var second error
	_, err := store.RebuildZapIndex(context.Background(), func(int, int) {
		if second == nil {
			_, second = store.RebuildZapIndex(context.Background(), nil)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(second, ErrZapRebuildInProgress) {
		t.Fatalf("second rebuild err = %v, want ErrZapRebuildInProgress", second)
	}
}

func TestRebuildZapIndex_CancelKeepsOldIndex(t *testing.T) {
	store := newStore(t)
	// More than one scan batch, so the rebuild checks ctx between them.
	events := make([]*nip01.Event, 0, 1500)
	for i := 0; i < 1500; i++ {
		events = append(events, &nip01.Event{Kind: 1, CreatedAt: uint64(i + 1)})
	}
	next := putRawEvents(t, store, 1, events...)
	putRawEvents(t, store, next, rawZap(t, 9735, zapReceiverA, "1000", 100))
	if _, err := store.ReindexZaps(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	_, err := store.RebuildZapIndex(ctx, func(int, int) { cancel() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := topZapped(t, store); got[zapReceiverA] != 1000 {
		t.Fatalf("old index lost after cancel: %v", got)
	}
	if err := store.db.View(func(tx *bolt.Tx) error {
		if buildingZapBucket(tx) != nil {
			t.Error("building pointer left set after cancel")
		}
		if tx.Bucket(append([]byte{9, 'g'}, itob(1)...)) != nil {
			t.Error("unfinished bucket left behind after cancel")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRebuildZapIndex_SurvivesReopen(t *testing.T) {
	path := t.TempDir() + "/zaps.db"
	open := func() *EventStore {
		store, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	store := open()
	putRawEvents(t, store, 1, rawZap(t, 9735, zapReceiverA, "1000", 100))
	if _, err := store.RebuildZapIndex(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	store.Close()

	store = open()
	defer store.Close()
	if got := topZapped(t, store); got[zapReceiverA] != 1000 {
		t.Fatalf("top zapped after reopen = %v", got)
	}
}
