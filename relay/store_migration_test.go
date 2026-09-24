package relay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay/migrations"
	"github.com/ohstr/nmilat/testlogger"
)

// The v2 migration rewrites every query index so created_at leads the
// suffix. These tests build a store in the pre-v2 layout by hand, then
// assert that reopening it produces correct newest-first answers.

// writeOldLayoutIndexes replaces the query indexes with the pre-v2 key
// layout (prefix + evsid, no created_at) and rewinds the recorded migration
// version so the next open re-runs the rebuild.
func writeOldLayoutIndexes(t testing.TB, path string) {
	t.Helper()

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{indexID, indexPubkey, indexKind, indexTag, indexKindPubkey} {
			if err := tx.DeleteBucket(name); err != nil && err != bolt.ErrBucketNotFound {
				return err
			}
			if _, err := tx.CreateBucket(name); err != nil {
				return err
			}
		}

		events := tx.Bucket(indexEvents)
		if events == nil {
			return nil
		}

		return events.ForEach(func(k, v []byte) error {
			var ev nip01.Event
			if err := json.Unmarshal(v, &ev); err != nil {
				return err
			}
			evsidBytes := append([]byte(nil), k...)
			createdAt := itob(ev.CreatedAt)

			idBytes, err := hex.DecodeString(ev.ID)
			if err != nil {
				return err
			}
			pkBytes, err := hex.DecodeString(ev.PubKey)
			if err != nil {
				return err
			}
			kindBytes := itob(uint64(ev.Kind))

			puts := []struct {
				bucket []byte
				key    []byte
			}{
				{indexID, concatKey(idBytes, evsidBytes)},
				{indexPubkey, concatKey(pkBytes, evsidBytes)},
				{indexKind, concatKey(kindBytes, evsidBytes)},
				{indexKindPubkey, concatKey(kindBytes, pkBytes, evsidBytes)},
			}
			for _, p := range puts {
				if err := tx.Bucket(p.bucket).Put(p.key, createdAt); err != nil {
					return err
				}
			}

			// Pre-v2 tag entries were a bare name+value with no length
			// prefix and no created_at in the suffix.
			for _, tagSet := range ev.Tags {
				if len(tagSet) < 2 || len(tagSet[0]) != 1 {
					continue
				}
				legacy := []byte(tagSet[0] + tagSet[1])
				if err := tx.Bucket(indexTag).Put(concatKey(legacy, evsidBytes), createdAt); err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("write old layout: %v", err)
	}

	// Rewind to version 1 so v2 runs again on the next open.
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(migrations.MIGRATIONS_BUCKET)
		if err != nil {
			return err
		}
		return b.Put(migrations.VERSION_KEY, itob(1))
	}); err != nil {
		t.Fatalf("rewind version: %v", err)
	}
}

func reopenStore(t testing.TB, path string) *EventStore {
	t.Helper()
	store, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func migrationVersion(t testing.TB, path string) uint64 {
	t.Helper()
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var version uint64
	if err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(migrations.MIGRATIONS_BUCKET)
		if b == nil {
			return nil
		}
		v := b.Get(migrations.VERSION_KEY)
		if len(v) == 8 {
			version = btoi(v)
		}
		return nil
	}); err != nil {
		t.Fatalf("read version: %v", err)
	}
	return version
}

// seedStoreForMigration writes probe events newest-first (so evsid order is
// the reverse of time order), then rewrites the indexes in the old layout
// and returns the path plus the events, newest first.
func seedStoreForMigration(t testing.TB) (string, []*nip01.Event) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "migration-test.db")
	store, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	events := probeEvents(t, 10)
	insertInOrder(t, store, events, newestFirst)
	store.Close()

	writeOldLayoutIndexes(t, path)
	return path, events
}

func TestMigrationV2RebuildsIndexesForNewestFirstQueries(t *testing.T) {
	path, events := seedStoreForMigration(t)

	store := reopenStore(t, path)

	shapes := indexShapes(t, events)
	for _, shape := range []string{"createdAt", "kind", "pubkey", "kindPubkey", "tag", "id"} {
		t.Run(shape, func(t *testing.T) {
			q := newQuery(t, store, filterGroup(shapes[shape](3)))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), events[:3])
		})
	}
}

func TestMigrationV2ProducesTheCurrentKeyLayout(t *testing.T) {
	path, events := seedStoreForMigration(t)
	store := reopenStore(t, path)

	const tagValueLen = len("probe")
	for _, idx := range queryIndexes {
		keys := bucketKeys(t, store, idx.bucket)
		if len(keys) != len(events) {
			t.Errorf("%s index: got %d keys, want %d", idx.name, len(keys), len(events))
			continue
		}
		want := idx.keyLen(tagValueLen)
		for _, k := range keys {
			if len(k) != want {
				t.Errorf("%s index: key is %d bytes, want %d", idx.name, len(k), want)
				break
			}
		}
	}
}

func TestMigrationV2IsIdempotent(t *testing.T) {
	path, events := seedStoreForMigration(t)

	store := reopenStore(t, path)
	first := bucketKeys(t, store, indexKind)
	store.Close()

	if got := migrationVersion(t, path); got != 2 {
		t.Fatalf("migration version = %d, want 2", got)
	}

	// Reopening runs no migration, and must not disturb the indexes.
	store = reopenStore(t, path)
	second := bucketKeys(t, store, indexKind)

	if len(first) != len(second) || len(second) != len(events) {
		t.Fatalf("kind index: %d keys before reopen, %d after, want %d", len(first), len(second), len(events))
	}
	for i := range first {
		if string(first[i]) != string(second[i]) {
			t.Fatalf("kind index key %d changed across a reopen", i)
		}
	}
}

// An interrupted rebuild leaves the version behind, so the next open starts
// over and still converges.
func TestMigrationV2RecoversFromAnInterruptedRun(t *testing.T) {
	path, events := seedStoreForMigration(t)

	// Run the rebuild directly with a failing IndexEvent to simulate a
	// crash part-way through, then let the store open normally.
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	var seen int
	m := &migrations.RebuildTimeOrderedIndexes{
		EventsBucket:   indexEvents,
		RebuildBuckets: [][]byte{indexID, indexPubkey, indexKind, indexTag, indexKindPubkey},
		BatchSize:      2,
		IndexEvent: func(tx *bolt.Tx, evsid uint64, raw []byte) error {
			seen++
			if seen > 4 {
				return fmt.Errorf("simulated crash")
			}
			var ev nip01.Event
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			keys, err := indexKeysFor(&ev, evsid, defaultMaxIndexableTags)
			if err != nil {
				return err
			}
			return putEventIndexes(tx, keys)
		},
	}
	if err := m.Up(db); err == nil {
		t.Fatal("expected the simulated crash to fail the rebuild")
	}
	_ = db.Close()

	if got := migrationVersion(t, path); got != 1 {
		t.Fatalf("version = %d after a failed rebuild, want 1 so it re-runs", got)
	}

	store := reopenStore(t, path)
	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{1}, Limit: 3}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), events[:3])
}

// Batching must actually span more than one write transaction, or the
// migration would hold an entire store's rebuild in memory.
func TestMigrationV2WritesInSeveralTransactions(t *testing.T) {
	path, _ := seedStoreForMigration(t)

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var batches int
	var lastTxID int
	m := &migrations.RebuildTimeOrderedIndexes{
		EventsBucket:   indexEvents,
		RebuildBuckets: [][]byte{indexID, indexPubkey, indexKind, indexTag, indexKindPubkey},
		BatchSize:      1,
		IndexEvent: func(tx *bolt.Tx, evsid uint64, raw []byte) error {
			if tx.ID() != lastTxID {
				batches++
				lastTxID = tx.ID()
			}
			var ev nip01.Event
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			keys, err := indexKeysFor(&ev, evsid, defaultMaxIndexableTags)
			if err != nil {
				return err
			}
			return putEventIndexes(tx, keys)
		},
	}
	if err := m.Up(db); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if batches < 2 {
		t.Errorf("rebuild used %d write transactions, want more than one with BatchSize 1", batches)
	}
}

// A store that has never held an event has nothing to rebuild, and the
// index buckets do not exist yet when migrations run.
func TestMigrationV2OnAnEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")

	store := reopenStore(t, path)
	if got := countBucket(t, store, indexEvents); got != 0 {
		t.Fatalf("events bucket: got %d entries, want 0", got)
	}
	store.Close()

	if got := migrationVersion(t, path); got != 2 {
		t.Errorf("migration version = %d, want 2", got)
	}
}

// Indexes the migration does not rebuild must come through untouched.
func TestMigrationV2LeavesOtherIndexesAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "untouched.db")
	store, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	events := probeEvents(t, 5)
	insertInOrder(t, store, events, newestFirst)
	before := bucketKeys(t, store, indexCreatedAt)
	store.Close()

	writeOldLayoutIndexes(t, path)
	store = reopenStore(t, path)

	after := bucketKeys(t, store, indexCreatedAt)
	if len(before) != len(after) {
		t.Fatalf("createdAt index: %d keys before, %d after", len(before), len(after))
	}
	for i := range before {
		if string(before[i]) != string(after[i]) {
			t.Errorf("createdAt index key %d changed across the migration", i)
		}
	}
}
