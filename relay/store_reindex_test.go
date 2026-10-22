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

	// Put events straight into the events bucket, as data stored before the
	// zap index existed.

	err = store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexEvents)

		// Event 1: Normal Note (Kind 1)
		ev1 := &nip01.Event{Kind: 1, Content: "Hello", CreatedAt: 100}
		ev1Bytes, _ := json.Marshal(ev1)
		_ = b.Put(itob(1), ev1Bytes)

		// Event 2: AltZap receipt (Kind 9521)
		ev2 := rawZap(t, 9521, "0000000000000000000000000000000000000000000000000000000000000001", "1000000", 200)
		ev2Bytes, _ := json.Marshal(ev2)
		_ = b.Put(itob(2), ev2Bytes)

		// Event 3: NIP-57 zap receipt (Kind 9735)
		ev3 := rawZap(t, 9735, "0000000000000000000000000000000000000000000000000000000000000002", "2000000", 300)
		ev3Bytes, _ := json.Marshal(ev3)
		_ = b.Put(itob(3), ev3Bytes)

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
	assert.Equal(t, 2, count, "Should index both the 9521 and the 9735 zap")

	// 4. Verify Index
	// The 9735 paid sats, the 9521 loki: each ranks only in its own coin.
	sats, err := store.TopZapped(ctx, 0, uint64(time.Now().Unix()+1000), CoinSats, 10)
	require.NoError(t, err)
	require.Len(t, sats, 1)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000002", sats[0].Pubkey)
	assert.Equal(t, uint64(2000000), sats[0].Total)
	loki, err := store.TopZapped(ctx, 0, uint64(time.Now().Unix()+1000), CoinLoki, 10)
	require.NoError(t, err)
	require.Len(t, loki, 1)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001", loki[0].Pubkey)
	assert.Equal(t, uint64(1000000), loki[0].Total)
}
