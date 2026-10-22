package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// The zap index lives in a bucket named by zapMeta's "active" key, or
// indexZaps when unset. RebuildZapIndex builds a new generation beside it
// and swaps the pointer in one transaction, so readers never see it empty.
var (
	zapMeta        = []byte{9, 'm'}
	zapActiveKey   = []byte("active")
	zapBuildingKey = []byte("building")
	zapGenKey      = []byte("gen")
	// coinsKey marks an index (zap or social) rebuilt since zaps record their
	// coin; without it, entries may lack one and the index is rebuilt once.
	coinsKey = []byte("coins")
)

// ErrZapRebuildInProgress is returned by RebuildZapIndex while another
// rebuild is running.
var ErrZapRebuildInProgress = errors.New("zap index rebuild already in progress")

// activeZapBucket returns the name of the bucket readers use.
func activeZapBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(zapMeta); m != nil {
		if v := m.Get(zapActiveKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return indexZaps
}

// buildingZapBucket returns the name of the bucket a rebuild is filling, or
// nil when none is running.
func buildingZapBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(zapMeta); m != nil {
		if v := m.Get(zapBuildingKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return nil
}

// ClearZapIndex empties the active zap index without touching the stored
// events. RebuildZapIndex is the way to refresh it without an empty window.
func (s *EventStore) ClearZapIndex(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		name := activeZapBucket(tx)
		if err := tx.DeleteBucket(name); err != nil && err != bolterrors.ErrBucketNotFound {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(name)
		return err
	})
}

// ReindexZaps scans every stored event into the active zap index in place.
// It returns the number of zaps indexed.
func (s *EventStore) ReindexZaps(ctx context.Context, progressCb func(count int)) (int, error) {
	_, indexed, err := s.scanZapsInto(ctx, activeZapBucket, func(_, indexed int) {
		if progressCb != nil {
			progressCb(indexed)
		}
	})
	return indexed, err
}

// RebuildZapIndex rebuilds the zap index into a new bucket and makes it the
// active one atomically once complete, so top-zapped queries keep answering
// from the old index throughout. Zaps stored meanwhile land in both.
// progress, if set, is called after each batch with the number of events
// scanned and zaps indexed so far. Cancelling ctx discards the new bucket.
func (s *EventStore) RebuildZapIndex(ctx context.Context, progress func(scanned, indexed int)) (int, error) {
	if !s.zapRebuilding.CompareAndSwap(false, true) {
		return 0, ErrZapRebuildInProgress
	}
	defer s.zapRebuilding.Store(false)

	var next []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		m, err := tx.CreateBucketIfNotExists(zapMeta)
		if err != nil {
			return err
		}
		// A rebuild interrupted by a crash leaves its bucket behind.
		if stale := m.Get(zapBuildingKey); stale != nil {
			if err := tx.DeleteBucket(stale); err != nil && err != bolterrors.ErrBucketNotFound {
				return err
			}
		}
		var gen uint64
		if v := m.Get(zapGenKey); len(v) == 8 {
			gen = binary.BigEndian.Uint64(v)
		}
		gen++
		next = append([]byte{9, 'g'}, itob(gen)...)
		if _, err := tx.CreateBucket(next); err != nil {
			return err
		}
		if err := m.Put(zapGenKey, itob(gen)); err != nil {
			return err
		}
		return m.Put(zapBuildingKey, next)
	})
	if err != nil {
		return 0, err
	}

	_, indexed, err := s.scanZapsInto(ctx, func(*bolt.Tx) []byte { return next }, progress)
	if err != nil {
		if dropErr := s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.DeleteBucket(next); err != nil && err != bolterrors.ErrBucketNotFound {
				return err
			}
			return tx.Bucket(zapMeta).Delete(zapBuildingKey)
		}); dropErr != nil {
			s.logger.Warn().Err(dropErr).Msg("failed to discard an unfinished zap index rebuild")
		}
		return indexed, err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		old := activeZapBucket(tx)
		m := tx.Bucket(zapMeta)
		if err := m.Put(zapActiveKey, next); err != nil {
			return err
		}
		if err := m.Delete(zapBuildingKey); err != nil {
			return err
		}
		if err := m.Put(coinsKey, []byte{1}); err != nil {
			return err
		}
		if err := tx.DeleteBucket(old); err != nil && err != bolterrors.ErrBucketNotFound {
			return err
		}
		return nil
	})
	return indexed, err
}

// ZapIndexRebuilding reports whether RebuildZapIndex is running.
func (s *EventStore) ZapIndexRebuilding() bool { return s.zapRebuilding.Load() }

// scanZapsInto walks every stored event in batches, indexing zap receipts
// into the bucket target names. It returns events scanned and zaps indexed.
func (s *EventStore) scanZapsInto(ctx context.Context, target func(*bolt.Tx) []byte, progress func(scanned, indexed int)) (int, int, error) {
	return s.scanEventsInto(ctx, isZapKind, func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) error {
		b, err := tx.CreateBucketIfNotExists(target(tx))
		if err != nil {
			return err
		}
		return putZap(b, ev, evsid)
	}, progress)
}

// scanEventsInto walks every stored event in batches, calling apply in a
// write transaction for each one whose kind matches. It returns events
// scanned and applied.
func (s *EventStore) scanEventsInto(ctx context.Context, match func(kind int) bool, apply func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) error, progress func(scanned, indexed int)) (int, int, error) {
	const batchSize = 1000 // events per read transaction
	scanned, indexed := 0, 0
	var lastKey []byte

	for {
		var matched []*nip01.Event
		var evsids []uint64
		var newLastKey []byte
		inBatch := 0

		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(indexEvents).Cursor()
			var k, v []byte
			if lastKey == nil {
				k, v = c.First()
			} else {
				k, v = c.Seek(lastKey)
				if k != nil && bytes.Equal(k, lastKey) {
					k, v = c.Next()
				}
			}
			for ; inBatch < batchSize && k != nil; k, v = c.Next() {
				inBatch++
				newLastKey = append(newLastKey[:0], k...)

				var event nip01.Event
				if err := json.Unmarshal(v, &event); err != nil {
					s.logger.Warn().Err(err).Uint64("evsid", binary.BigEndian.Uint64(k)).Msg("reindex: failed to unmarshal event")
					continue
				}
				if match(event.Kind) {
					matched = append(matched, &event)
					evsids = append(evsids, binary.BigEndian.Uint64(k))
				}
			}
			return nil
		})
		if err != nil {
			return scanned, indexed, err
		}
		scanned += inBatch

		if len(matched) > 0 {
			err := s.db.Update(func(tx *bolt.Tx) error {
				for i, event := range matched {
					if err := apply(tx, event, evsids[i]); err != nil {
						return err
					}
					indexed++
				}
				return nil
			})
			if err != nil {
				return scanned, indexed, err
			}
		}
		if progress != nil {
			progress(scanned, indexed)
		}

		if inBatch < batchSize {
			return scanned, indexed, nil
		}
		lastKey = newLastKey

		select {
		case <-ctx.Done():
			return scanned, indexed, ctx.Err()
		default:
		}
	}
}
