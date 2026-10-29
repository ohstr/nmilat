package relay

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// indexCounters keeps exact counts so they're O(1) to read: stored events
// per kind ('k' + kind(8) -> n) and distinct authors ("authors" -> n). They
// change in the same transaction as the indexes they mirror. Only indexed
// events count.
//
// A store from before counters is backfilled in chunks, each in its own
// write transaction, so writes never wait long. A watermark ("kinds-mark",
// "authors-mark") is the last index key counted; a live write updates a
// counter only for keys at or before it, the backfill gets the rest. The
// "-done" keys mark a finished backfill.
var (
	indexCounters = []byte{18}

	ctrAuthors     = []byte("authors")
	ctrKindsMark   = []byte("kinds-mark")
	ctrKindsDone   = []byte("kinds-done")
	ctrAuthorsMark = []byte("authors-mark")
	ctrAuthorsDone = []byte("authors-done")
)

// countersChunk is how many index keys (or authors) one backfill
// transaction covers.
var countersChunk = 20_000

func kindCounterKey(kind []byte) []byte { return append([]byte{'k'}, kind...) }

func addCounter(b *bolt.Bucket, key []byte, delta int64) error {
	var n int64
	if v := b.Get(key); len(v) == 8 {
		n = int64(binary.BigEndian.Uint64(v))
	}
	n += delta
	if n <= 0 {
		return b.Delete(key)
	}
	return b.Put(key, itob(uint64(n)))
}

// counted reports whether a live write at key is already reflected in the
// counters: the backfill is done, or has passed key.
func counted(c *bolt.Bucket, done, mark, key []byte) bool {
	if c.Get(done) != nil {
		return true
	}
	m := c.Get(mark)
	return m != nil && bytes.Compare(key, m) <= 0
}

// hasPrefixKey reports whether b holds any key starting with prefix.
func hasPrefixKey(b *bolt.Bucket, prefix []byte) bool {
	k, _ := b.Cursor().Seek(prefix)
	return k != nil && bytes.HasPrefix(k, prefix)
}

// countInsert records an event about to be indexed under k.
func countInsert(tx *bolt.Tx, k *indexKeys) error {
	return countEvent(tx, k, 1)
}

// countDelete records an event whose index keys k were just removed.
func countDelete(tx *bolt.Tx, k *indexKeys) error {
	return countEvent(tx, k, -1)
}

func countEvent(tx *bolt.Tx, k *indexKeys, delta int64) error {
	c := tx.Bucket(indexCounters)
	if c == nil {
		return nil
	}
	if counted(c, ctrKindsDone, ctrKindsMark, k.kind) {
		if err := addCounter(c, kindCounterKey(k.kind[:8]), delta); err != nil {
			return err
		}
	}
	pubkey := k.pubkey[:32]
	if counted(c, ctrAuthorsDone, ctrAuthorsMark, pubkey) && !hasPrefixKey(tx.Bucket(indexPubkey), pubkey) {
		// Before an insert: the author's first event. After a delete: their last.
		return addCounter(c, ctrAuthors, delta)
	}
	return nil
}

// Counts are a store's exact totals of indexed events.
type Counts struct {
	Events  uint64
	Authors uint64
	// Kinds maps a kind to its stored events.
	Kinds map[int]uint64
	// Ready is false while a store from before counters is being backfilled;
	// the numbers are then partial.
	Ready bool
}

// Kind returns the stored events of kind.
func (c Counts) Kind(kind int) uint64 { return c.Kinds[kind] }

// Counts reads the counters. Cost is one read per kind in use.
func (s *EventStore) Counts() Counts {
	out := Counts{Kinds: map[int]uint64{}}
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(indexCounters)
		if c == nil {
			return nil
		}
		out.Ready = c.Get(ctrKindsDone) != nil && c.Get(ctrAuthorsDone) != nil
		if v := c.Get(ctrAuthors); len(v) == 8 {
			out.Authors = btoi(v)
		}
		cur := c.Cursor()
		for k, v := cur.Seek([]byte{'k'}); k != nil && k[0] == 'k'; k, v = cur.Next() {
			if len(k) != 9 || len(v) != 8 {
				continue
			}
			n := btoi(v)
			out.Kinds[int(btoi(k[1:]))] = n
			out.Events += n
		}
		return nil
	})
	return out
}

// CountFromCounters answers filters that name only kinds, or nothing, from
// the counters. ok is false when any filter needs a scan or the counters
// are still being backfilled.
func (s *EventStore) CountFromCounters(filters *nip01.SubscriptionFilterGroup) (n int64, ok bool) {
	all := filters.GetAll()
	if len(all) == 0 {
		return 0, false
	}
	kinds := map[int]bool{}
	every := false
	for _, f := range all {
		if len(f.IDs) > 0 || len(f.Authors) > 0 || len(f.Tags) > 0 || f.Since > 0 || f.Until > 0 ||
			f.Limit > 0 || f.Search != "" || f.Cache != nil || f.BeforeID != "" {
			return 0, false
		}
		if len(f.Kinds) == 0 {
			every = true
		}
		for _, k := range f.Kinds {
			kinds[k] = true
		}
	}
	c := s.Counts()
	if !c.Ready {
		return 0, false
	}
	if every {
		return int64(c.Events), true
	}
	for k := range kinds {
		n += int64(c.Kind(k))
	}
	return n, true
}

// backfillCounters counts a store's existing events, in the background.
func (s *EventStore) backfillCounters() {
	done := false
	_ = s.db.Update(func(tx *bolt.Tx) error {
		c, err := tx.CreateBucketIfNotExists(indexCounters)
		if err != nil {
			return err
		}
		if c.Get(ctrKindsDone) != nil && c.Get(ctrAuthorsDone) != nil {
			done = true
			return nil
		}
		// Nothing indexed yet: counting starts complete.
		if k, _ := tx.Bucket(indexKind).Cursor().First(); k == nil {
			done = true
			if err := c.Put(ctrKindsDone, []byte{1}); err != nil {
				return err
			}
			return c.Put(ctrAuthorsDone, []byte{1})
		}
		return nil
	})
	if done {
		return
	}
	s.workersWg.Add(1)
	go func() {
		defer s.workersWg.Done()
		s.logger.Info().Msg("counting stored events")
		for _, step := range []func(tx *bolt.Tx) (bool, error){countKindsChunk, countAuthorsChunk} {
			for {
				select {
				case <-s.closeCh:
					return
				default:
				}
				var finished bool
				if err := s.db.Update(func(tx *bolt.Tx) error {
					var err error
					finished, err = step(tx)
					return err
				}); err != nil {
					if !errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
						s.logger.Error().Err(err).Msg("failed to count stored events")
					}
					return
				}
				if finished {
					break
				}
			}
		}
		s.logger.Info().Msg("stored events counted")
	}()
}

// countKindsChunk counts the next chunk of indexKind keys.
func countKindsChunk(tx *bolt.Tx) (bool, error) {
	c := tx.Bucket(indexCounters)
	if c.Get(ctrKindsDone) != nil {
		return true, nil
	}
	cur := tx.Bucket(indexKind).Cursor()
	var k []byte
	if mark := c.Get(ctrKindsMark); mark != nil {
		if k, _ = cur.Seek(mark); k != nil && bytes.Equal(k, mark) {
			k, _ = cur.Next()
		}
	} else {
		k, _ = cur.First()
	}
	pending := map[string]int64{}
	var last []byte
	for n := 0; k != nil && n < countersChunk; n++ {
		if len(k) >= 8 {
			pending[string(k[:8])]++
		}
		last = k
		k, _ = cur.Next()
	}
	for kind, n := range pending {
		if err := addCounter(c, kindCounterKey([]byte(kind)), n); err != nil {
			return false, err
		}
	}
	if last != nil {
		if err := c.Put(ctrKindsMark, bytes.Clone(last)); err != nil {
			return false, err
		}
	}
	if k == nil {
		return true, c.Put(ctrKindsDone, []byte{1})
	}
	return false, nil
}

// countAuthorsChunk counts the next chunk of distinct pubkeys, skipping
// from one to the next with a seek.
func countAuthorsChunk(tx *bolt.Tx) (bool, error) {
	c := tx.Bucket(indexCounters)
	if c.Get(ctrAuthorsDone) != nil {
		return true, nil
	}
	cur := tx.Bucket(indexPubkey).Cursor()
	var k []byte
	if mark := c.Get(ctrAuthorsMark); mark != nil {
		k, _ = cur.Seek(concatKey(mark, maxSuffixBytes))
	} else {
		k, _ = cur.First()
	}
	var last []byte
	n := int64(0)
	for ; k != nil && n < int64(countersChunk); n++ {
		if len(k) < 32 {
			k, _ = cur.Next()
			continue
		}
		last = bytes.Clone(k[:32])
		k, _ = cur.Seek(concatKey(last, maxSuffixBytes))
	}
	if err := addCounter(c, ctrAuthors, n); err != nil {
		return false, err
	}
	if last != nil {
		if err := c.Put(ctrAuthorsMark, last); err != nil {
			return false, err
		}
	}
	if k == nil {
		return true, c.Put(ctrAuthorsDone, []byte{1})
	}
	return false, nil
}
