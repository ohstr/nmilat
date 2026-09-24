package migrations

import (
	"bytes"
	"fmt"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// RebuildTimeOrderedIndexes rewrites the query indexes after created_at
// moved ahead of evsid in their keys, so that walking a prefix backwards
// yields events newest-first.
//
// The rebuild is delete-and-refill rather than in place. For the
// fixed-width indexes the old and new key lengths differ, so an in-place
// pass could tell them apart -- but for the tag index it cannot: an old key
// of length M is "entry of length M-8" and a new one is "entry of length
// M-16", which are indistinguishable. Dropping the buckets also reclaims
// the old pages instead of leaving them behind.
//
// Everything the migration needs from the relay package is injected, since
// this package cannot import it: bucket ids, and an IndexEvent function
// that writes one event's index entries using the very same code the live
// insert path runs, so the two cannot drift.
type RebuildTimeOrderedIndexes struct {
	// EventsBucket holds evsid -> serialized event; it is the source of
	// truth the indexes are rebuilt from and is never modified.
	EventsBucket []byte
	// RebuildBuckets are emptied and refilled.
	RebuildBuckets [][]byte
	// IndexEvent writes every index entry for one stored event.
	IndexEvent func(tx *bolt.Tx, evsid uint64, raw []byte) error
	// BatchSize is how many events are re-indexed per write transaction.
	BatchSize int
	// Progress, if set, is called with the running total.
	Progress func(count int)
}

func (m *RebuildTimeOrderedIndexes) Version() uint64 { return 2 }

func (m *RebuildTimeOrderedIndexes) Description() string {
	return "Rebuild the query indexes with created_at ahead of evsid so limited queries return the newest events"
}

// Down is a no-op: the rebuild is forward-only. An older binary reading a
// store at this version mis-parses every index key, so a downgrade needs a
// copy of the file taken before the upgrade, not a reverse migration.
func (m *RebuildTimeOrderedIndexes) Down(db *bolt.DB) error { return nil }

func (m *RebuildTimeOrderedIndexes) Up(db *bolt.DB) error {
	if m.IndexEvent == nil {
		return fmt.Errorf("rebuild indexes: IndexEvent is required")
	}
	batchSize := m.BatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}

	// A store that has never held an event has no indexes to rebuild. The
	// relay creates these buckets after migrations run, so on a fresh file
	// they do not exist yet.
	empty, err := m.sourceIsEmpty(db)
	if err != nil {
		return err
	}
	if empty {
		return nil
	}

	if err := m.resetBuckets(db); err != nil {
		return err
	}

	var (
		lastKey []byte
		total   int
	)
	for {
		batch, err := m.readBatch(db, lastKey, batchSize)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}

		if err := db.Update(func(tx *bolt.Tx) error {
			for _, e := range batch {
				if err := m.IndexEvent(tx, e.evsid, e.raw); err != nil {
					return fmt.Errorf("rebuild indexes: evsid %d: %w", e.evsid, err)
				}
			}
			return nil
		}); err != nil {
			return err
		}

		total += len(batch)
		if m.Progress != nil {
			m.Progress(total)
		}

		lastKey = batch[len(batch)-1].key
		if len(batch) < batchSize {
			break
		}
	}

	return nil
}

func (m *RebuildTimeOrderedIndexes) sourceIsEmpty(db *bolt.DB) (bool, error) {
	empty := true
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(m.EventsBucket)
		if b == nil {
			return nil
		}
		k, _ := b.Cursor().First()
		empty = k == nil
		return nil
	})
	return empty, err
}

// resetBuckets empties every index being rebuilt, in one transaction. It is
// idempotent, so an interrupted run simply starts over.
func (m *RebuildTimeOrderedIndexes) resetBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, name := range m.RebuildBuckets {
			if err := tx.DeleteBucket(name); err != nil && err != bolterrors.ErrBucketNotFound {
				return fmt.Errorf("rebuild indexes: drop bucket %v: %w", name, err)
			}
			if _, err := tx.CreateBucket(name); err != nil {
				return fmt.Errorf("rebuild indexes: create bucket %v: %w", name, err)
			}
		}
		return nil
	})
}

type storedEvent struct {
	key   []byte
	evsid uint64
	raw   []byte
}

// readBatch reads up to n events from the events bucket, resuming after
// lastKey. Reads and writes are kept in separate transactions so no single
// transaction has to hold the whole rebuild.
func (m *RebuildTimeOrderedIndexes) readBatch(db *bolt.DB, lastKey []byte, n int) ([]storedEvent, error) {
	var batch []storedEvent

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(m.EventsBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()

		var k, v []byte
		if lastKey == nil {
			k, v = c.First()
		} else {
			k, v = c.Seek(lastKey)
			if k != nil && bytes.Equal(k, lastKey) {
				k, v = c.Next()
			}
		}

		for ; k != nil && len(batch) < n; k, v = c.Next() {
			if len(k) != 8 {
				continue
			}
			batch = append(batch, storedEvent{
				key:   append([]byte(nil), k...),
				evsid: beUint64(k),
				raw:   append([]byte(nil), v...),
			})
		}
		return nil
	})

	return batch, err
}

func beUint64(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}
