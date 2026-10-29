package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip09"
	bolt "go.etcd.io/bbolt"
)

// deletionsIndexedKey marks a store whose deletion requests are all indexed.
// Versions before #209's fix stored a kind 5 with no indexes, so it was never
// served and the duplicate check missed it: every republish stored a copy.
var deletionsIndexedKey = []byte("deletions-indexed")

// reindexBatch is how many stored events one reindex transaction reads.
var reindexBatch = 1000

// indexStoredDeletions indexes every deletion request a version before #209's
// fix stored without indexes, and drops the extra copies of each one so it is
// stored once. It runs once per store, before the workers start, and is
// idempotent: an indexed request with no other copy is left as it is.
func (s *EventStore) indexStoredDeletions() error {
	done := false
	if err := s.db.View(func(tx *bolt.Tx) error {
		done = metaValue(tx, storeMeta, deletionsIndexedKey) != nil
		return nil
	}); err != nil || done {
		return err
	}

	var indexed, dropped int
	for after := uint64(0); ; {
		rows, last, err := s.storedDeletions(after)
		if err != nil {
			return err
		}
		if err := s.db.Update(func(tx *bolt.Tx) error {
			for _, r := range rows {
				i, d, err := s.indexStoredDeletion(tx, r.evsid, r.ev)
				if err != nil {
					return fmt.Errorf("index deletion request %s: %w", r.ev.ID, err)
				}
				indexed, dropped = indexed+i, dropped+d
			}
			if last == 0 {
				m, err := tx.CreateBucketIfNotExists(storeMeta)
				if err != nil {
					return err
				}
				return m.Put(deletionsIndexedKey, []byte{1})
			}
			return nil
		}); err != nil {
			return err
		}
		if last == 0 {
			break
		}
		after = last
	}
	if indexed+dropped > 0 {
		s.logger.Info().Int("indexed", indexed).Int("dropped_copies", dropped).Msg("indexed stored deletion requests")
	}
	return nil
}

type storedDeletion struct {
	evsid uint64
	ev    *nip01.Event
}

// storedDeletions reads the deletion requests among the reindexBatch events
// after evsid after. last is the last evsid read, 0 once the bucket is done.
func (s *EventStore) storedDeletions(after uint64) (rows []storedDeletion, last uint64, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(indexEvents).Cursor()
		n := 0
		for k, v := c.Seek(itob(after + 1)); k != nil; k, v = c.Next() {
			if len(k) != 8 {
				continue
			}
			if n == reindexBatch {
				return nil
			}
			n++
			last = btoi(k)
			var head struct {
				Kind int `json:"kind"`
			}
			if json.Unmarshal(v, &head) != nil || !nip09.IsDeletionKind(head.Kind) {
				continue
			}
			var ev nip01.Event
			if json.Unmarshal(v, &ev) != nil {
				continue // undecodable, as the index rebuild skips it
			}
			rows = append(rows, storedDeletion{evsid: last, ev: &ev})
		}
		last = 0
		return nil
	})
	return rows, last, err
}

// indexStoredDeletion indexes one stored deletion request, or drops it when
// another copy of the same event is indexed, so exactly one copy stays.
func (s *EventStore) indexStoredDeletion(tx *bolt.Tx, evsid uint64, ev *nip01.Event) (indexed, dropped int, err error) {
	keys, err := indexKeysFor(ev, evsid, s.limitation.MaxIndexableTags)
	if err != nil {
		return 0, 0, nil // unindexable, as the index rebuild skips it
	}
	ids := tx.Bucket(indexID)
	own := ids.Get(keys.id) != nil
	idBytes, _ := hex.DecodeString(ev.ID)
	other := false
	c := ids.Cursor()
	for k, _ := c.Seek(idBytes); k != nil && bytes.HasPrefix(k, idBytes); k, _ = c.Next() {
		if !bytes.Equal(k, keys.id) {
			other = true
			break
		}
	}
	switch {
	case other:
		if err := tx.Bucket(indexEvents).Delete(keys.evsid); err != nil {
			return 0, 0, err
		}
		if own {
			if err := delEventIndexes(tx, keys); err != nil {
				return 0, 0, err
			}
			if err := countDelete(tx, keys); err != nil {
				return 0, 0, err
			}
		}
		return 0, 1, nil
	case own:
		return 0, 0, nil
	default:
		return 1, 0, s.insertIndexes(tx, ev, evsid)
	}
}
