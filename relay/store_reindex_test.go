package relay

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestReindexZaps(t *testing.T) {
	// Setup temporary DB
	tmpFile, err := os.CreateTemp("", "nmilat_test_*.db")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	store, err := NewEventStore(tmpFile.Name(), &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	// 1. Seed DB with events (some zaps, some not)
	ctx := context.Background()

	zapEvent := &nip01.Event{
		Kind:      9735,
		CreatedAt: uint64(time.Now().Unix()),
		Tags: [][]string{
			{"p", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"amount", "1000000"}, // 1000 sats
		},
		Content: "Zap!",
	}
	// generate ID and normalize
	// (skipping ID generation for brevity as IndexZap doesn't strictly require valid IDs if we manually insert,
	// but store.insert does. Let's just manually put into bucket to simulate existing data)

	// We need to use store.insert to ensure it's in indexEvents
	// But store.insert automatically calls IndexZap if we don't disable it.
	// We want to test ReindexZap, so ideally we insert WITHOUT indexing first?
	// Or we just checking if ReindexZaps works idempotently or fixes missing indexes.
	// But store.insert calls IndexZap.
	// Let's manually insert into indexEvents to simulate "old data not indexed"

	err = store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexEvents)

		// Event 1: Normal Note (Kind 1)
		ev1 := &nip01.Event{Kind: 1, Content: "Hello", CreatedAt: 100}
		ev1Bytes, _ := json.Marshal(ev1)
		_ = b.Put(itob(1), ev1Bytes)

		// Event 2: Zap (Kind 5521)
		ev2 := zapEvent
		ev2.Kind = 5521
		ev2.CreatedAt = 200
		ev2.Tags = [][]string{
			{"p", "0000000000000000000000000000000000000000000000000000000000000001"},
			{"description", `{"kind":5520,"tags":[["amount","1000000"]]}`},
		}
		ev2Bytes, _ := json.Marshal(ev2)
		_ = b.Put(itob(2), ev2Bytes)

		return nil
	})
	require.NoError(t, err)

	// 2. Clear indexZaps to ensure Reindex populates it. Ignore error if
	// bucket doesn't exist.
	_ = store.db.Update(func(tx *bolt.Tx) error {
		_ = tx.DeleteBucket(indexZaps)
		return nil
	})

	// 3. Run ReindexZaps
	count, err := store.ReindexZaps(ctx, func(c int) {
		t.Logf("Indexed: %d", c)
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count, "Should index exactly 1 zap")

	// 4. Verify Index
	stats, err := store.GetTopZapped(ctx, 0, uint64(time.Now().Unix()+1000), 10)
	require.NoError(t, err)

	require.Len(t, stats, 1)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001", stats[0].Pubkey)
	assert.Equal(t, uint64(1000000), stats[0].TotalMLoki)
}
