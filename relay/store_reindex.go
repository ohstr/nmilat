package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// ClearZapIndex deletes and recreates the zap index bucket, discarding all
// indexed zap-receipt data without touching the underlying stored events.
// Pair with ReindexZaps to rebuild the index from scratch.
func (s *EventStore) ClearZapIndex(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(indexZaps); err != nil && err != bolterrors.ErrBucketNotFound {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(indexZaps)
		return err
	})
}

// ReindexZaps iterates over all events and populates the indexZaps bucket.
// It returns the count of indexed zaps and any error encountered.
func (s *EventStore) ReindexZaps(ctx context.Context, progressCb func(count int)) (int, error) {
	count := 0
	batchSize := 1000 // Process 1000 events per read transaction
	var lastKey []byte

	for {
		// 1. Read Batch (View Transaction)
		var zapsToIndex []*nip01.Event
		var zapEvsids []uint64
		var newLastKey []byte
		itemsScanned := 0

		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(indexEvents).Cursor()
			var k, v []byte

			if lastKey == nil {
				k, v = c.First()
			} else {
				k, v = c.Seek(lastKey)
				if k != nil && bytes.Equal(k, lastKey) {
					k, v = c.Next() // Resume from next
				}
			}

			// Scan batch
			for i := 0; i < batchSize && k != nil; i++ {
				itemsScanned++
				newLastKey = append([]byte(nil), k...) // Copy key for next iteration

				// Unmarshal to check kind
				var event nip01.Event
				if err := json.Unmarshal(v, &event); err == nil {
					if event.Kind == 5521 {
						zapsToIndex = append(zapsToIndex, &event)
						zapEvsids = append(zapEvsids, binary.BigEndian.Uint64(k))
					}
				} else {
					s.logger.Warn().Err(err).Uint64("evsid", binary.BigEndian.Uint64(k)).Msg("reindex: failed to unmarshal event")
				}

				k, v = c.Next()
			}
			return nil
		})

		if err != nil {
			return count, err
		}

		// 2. Write Batch (Update Transaction)
		if len(zapsToIndex) > 0 {
			err := s.db.Update(func(tx *bolt.Tx) error {
				// Ensure bucket exists once (or every time, cheap check)
				if _, err := tx.CreateBucketIfNotExists(indexZaps); err != nil {
					return err
				}

				for i, event := range zapsToIndex {
					if err := s.IndexZap(tx, event, zapEvsids[i]); err != nil {
						return err
					}
					count++
				}
				return nil
			})
			if err != nil {
				return count, err
			}

			if progressCb != nil {
				progressCb(count)
			}
		}

		// 3. Loop Control
		if itemsScanned < batchSize {
			break // End of database reached
		}
		lastKey = newLastKey

		select {
		case <-ctx.Done():
			return count, ctx.Err()
		default:
		}
	}

	return count, nil
}
