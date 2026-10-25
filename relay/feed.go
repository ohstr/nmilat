package relay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"sync/atomic"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// storeMeta holds store-wide state: the last event this version wrote
// ("seq"), and the feeds.
var (
	storeMeta = []byte{19}
	seqKey    = []byte("seq")
	feedsKey  = []byte("feeds")

	feedDefKey   = []byte("def")
	feedWKey     = []byte("w")
	feedDirty    = []byte("d")
	feedDirtySeq = []byte("ds")
	feedDirtyN   = []byte("dn")
)

// ErrUnknownFeed is returned for a feed that was never registered.
var ErrUnknownFeed = errors.New("unknown feed")

// A Feed lets a consumer outside the store — a search engine, the profile
// checks — follow the stored events of some kinds durably: it reads the
// events after its watermark, applies them, then acknowledges, so nothing
// is lost to a full queue, a restart or the consumer being off.
//
// Besides new events, a feed queues the authors to look at again: with
// Deletes, whenever an event of its kinds is deleted; with Scores,
// whenever a profile's score changes. The consumer re-reads such an
// author's current state, so the order it handles them in doesn't matter.
//
// A feed's definition is kept in the store, so its queue keeps filling
// while its consumer isn't running.
type Feed struct {
	Name    string `json:"name"`
	Kinds   []int  `json:"kinds"`
	Deletes bool   `json:"deletes,omitempty"`
	Scores  bool   `json:"scores,omitempty"`
}

func (f Feed) takes(kind int) bool {
	for _, k := range f.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

type feedSet struct{ feeds []Feed }

// WithEventStoreFeeds registers feeds when the store opens.
func WithEventStoreFeeds(feeds ...Feed) EventStoreOption {
	return func(cfg *EventStoreConfig) {
		cfg.Feeds = append(cfg.Feeds, feeds...)
	}
}

// writtenSeq returns the last event sequence this version of the store
// wrote; stamped is false for a store from before it was recorded.
func (s *EventStore) writtenSeq(tx *bolt.Tx) (uint64, bool) {
	v := metaValue(tx, storeMeta, seqKey)
	if len(v) != 8 {
		return 0, false
	}
	return btoi(v), true
}

func (s *EventStore) stampSeq(tx *bolt.Tx, seq uint64) error {
	b, err := tx.CreateBucketIfNotExists(storeMeta)
	if err != nil {
		return err
	}
	return b.Put(seqKey, itob(seq))
}

// openFeeds loads the feeds kept in the store and registers new ones.
func (s *EventStore) openFeeds(register []Feed) error {
	s.feeds = &atomic.Pointer[feedSet]{}
	s.feeds.Store(&feedSet{})
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, f := range register {
			if err := putFeedDef(tx, f); err != nil {
				return err
			}
		}
		s.feeds.Store(&feedSet{feeds: loadFeeds(tx)})
		return nil
	})
}

// EnsureFeed registers a feed, or updates its definition.
func (s *EventStore) EnsureFeed(f Feed) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := putFeedDef(tx, f); err != nil {
			return err
		}
		feeds := loadFeeds(tx)
		tx.OnCommit(func() { s.feeds.Store(&feedSet{feeds: feeds}) })
		return nil
	})
}

// DropFeed forgets a feed: its watermark and queue.
func (s *EventStore) DropFeed(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		fb := feedsBucket(tx)
		if fb == nil || fb.Bucket([]byte(name)) == nil {
			return ErrUnknownFeed
		}
		if err := fb.DeleteBucket([]byte(name)); err != nil {
			return err
		}
		feeds := loadFeeds(tx)
		tx.OnCommit(func() { s.feeds.Store(&feedSet{feeds: feeds}) })
		return nil
	})
}

func putFeedDef(tx *bolt.Tx, f Feed) error {
	m, err := tx.CreateBucketIfNotExists(storeMeta)
	if err != nil {
		return err
	}
	fb, err := m.CreateBucketIfNotExists(feedsKey)
	if err != nil {
		return err
	}
	b, err := fb.CreateBucketIfNotExists([]byte(f.Name))
	if err != nil {
		return err
	}
	v, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return b.Put(feedDefKey, v)
}

func feedsBucket(tx *bolt.Tx) *bolt.Bucket {
	m := tx.Bucket(storeMeta)
	if m == nil {
		return nil
	}
	return m.Bucket(feedsKey)
}

func feedBucket(tx *bolt.Tx, name string) *bolt.Bucket {
	fb := feedsBucket(tx)
	if fb == nil {
		return nil
	}
	return fb.Bucket([]byte(name))
}

func loadFeeds(tx *bolt.Tx) []Feed {
	fb := feedsBucket(tx)
	if fb == nil {
		return nil
	}
	var out []Feed
	_ = fb.ForEach(func(k, v []byte) error {
		if v != nil {
			return nil
		}
		var f Feed
		if raw := fb.Bucket(k).Get(feedDefKey); raw != nil && json.Unmarshal(raw, &f) == nil {
			out = append(out, f)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// feedsDeleted queues a deleted event's author on the feeds that follow
// deletes of its kind.
func (s *EventStore) feedsDeleted(tx *bolt.Tx, ev *nip01.Event) error {
	for _, f := range s.feeds.Load().feeds {
		if f.Deletes && f.takes(ev.Kind) {
			if err := queueFeed(tx, f.Name, ev.PubKey); err != nil {
				return err
			}
		}
	}
	return nil
}

// feedsRescored queues a profile whose score changed on the feeds that
// follow scores.
func (s *EventStore) feedsRescored(tx *bolt.Tx, pubkey string) error {
	for _, f := range s.feeds.Load().feeds {
		if f.Scores {
			if err := queueFeed(tx, f.Name, pubkey); err != nil {
				return err
			}
		}
	}
	return nil
}

func queueFeed(tx *bolt.Tx, name, pubkey string) error {
	b := feedBucket(tx, name)
	if b == nil {
		return nil
	}
	d, err := b.CreateBucketIfNotExists(feedDirty)
	if err != nil {
		return err
	}
	var seq uint64
	if v := b.Get(feedDirtySeq); len(v) == 8 {
		seq = btoi(v)
	}
	seq++
	if err := b.Put(feedDirtySeq, itob(seq)); err != nil {
		return err
	}
	if d.Get([]byte(pubkey)) == nil {
		if err := addCounter(b, feedDirtyN, 1); err != nil {
			return err
		}
	}
	return d.Put([]byte(pubkey), itob(seq))
}

// FeedBatch is what a feed has for its consumer: events stored after its
// watermark (Through is how far the batch read) and queued authors.
type FeedBatch struct {
	Events  []*nip01.Event
	Evsids  []uint64
	Through uint64
	Dirty   []string
	seqs    []uint64
}

// Upto returns the batch cut to its first n events and no queued authors,
// for a consumer that could take only that many.
func (b FeedBatch) Upto(n int) FeedBatch {
	if n >= len(b.Events) {
		return FeedBatch{Events: b.Events, Evsids: b.Evsids, Through: b.Through}
	}
	out := FeedBatch{Events: b.Events[:n], Evsids: b.Evsids[:n]}
	if n > 0 {
		out.Through = b.Evsids[n-1]
	} else if len(b.Evsids) > 0 {
		out.Through = b.Evsids[0] - 1
	}
	return out
}

// Empty reports whether the batch moves nothing.
func (b FeedBatch) Empty() bool { return len(b.Events) == 0 && len(b.Dirty) == 0 && b.Through == 0 }

// FeedChanges reads up to maxEvents events of the feed's kinds stored after
// its watermark, and up to maxDirty queued authors. It changes nothing;
// AckFeed records what the consumer applied.
func (s *EventStore) FeedChanges(name string, maxEvents, maxDirty int) (FeedBatch, error) {
	var out FeedBatch
	err := s.db.View(func(tx *bolt.Tx) error {
		b := feedBucket(tx, name)
		if b == nil {
			return ErrUnknownFeed
		}
		var f Feed
		_ = json.Unmarshal(b.Get(feedDefKey), &f)
		var w uint64
		if v := b.Get(feedWKey); len(v) == 8 {
			w = btoi(v)
		}
		c := tx.Bucket(indexEvents).Cursor()
		n := 0
		for k, v := c.Seek(itob(w + 1)); k != nil && n < scanBatch*5 && len(out.Events) < maxEvents; k, v = c.Next() {
			n++
			evsid := binary.BigEndian.Uint64(k)
			out.Through = evsid
			if kind, ok := peekKind(v); ok && !f.takes(kind) {
				continue
			}
			var ev nip01.Event
			if err := json.Unmarshal(v, &ev); err != nil || !f.takes(ev.Kind) {
				continue
			}
			out.Events = append(out.Events, &ev)
			out.Evsids = append(out.Evsids, evsid)
		}
		if d := b.Bucket(feedDirty); d != nil {
			dc := d.Cursor()
			for k, v := dc.First(); k != nil && len(out.Dirty) < maxDirty; k, v = dc.Next() {
				out.Dirty = append(out.Dirty, string(k))
				out.seqs = append(out.seqs, btoi(v))
			}
		}
		return nil
	})
	return out, err
}

// FeedCursor is how far a consumer has read past its watermark: the last
// event read, and the last queued author read.
type FeedCursor struct {
	After      uint64
	DirtyAfter string
}

// FeedChangesFrom is FeedChanges for a consumer with batches still in
// flight: it reads past from (or the watermark, when further), in read
// transactions of bounded length until maxEvents are found or the store
// ends, and queued authors after from.DirtyAfter only. It returns where
// the next read starts. A consumer that has acknowledged everything starts
// again from a zero FeedCursor, which reads queued authors from the start.
func (s *EventStore) FeedChangesFrom(name string, from FeedCursor, maxEvents, maxDirty int) (FeedBatch, FeedCursor, error) {
	var out FeedBatch
	next := from
	dirtyDone := false
	for {
		read := 0
		err := s.db.View(func(tx *bolt.Tx) error {
			b := feedBucket(tx, name)
			if b == nil {
				return ErrUnknownFeed
			}
			var f Feed
			_ = json.Unmarshal(b.Get(feedDefKey), &f)
			if v := b.Get(feedWKey); len(v) == 8 {
				next.After = max(next.After, btoi(v))
			}
			c := tx.Bucket(indexEvents).Cursor()
			for k, v := c.Seek(itob(next.After + 1)); k != nil && read < scanBatch*5 && len(out.Events) < maxEvents; k, v = c.Next() {
				read++
				evsid := binary.BigEndian.Uint64(k)
				next.After, out.Through = evsid, evsid
				if kind, ok := peekKind(v); ok && !f.takes(kind) {
					continue
				}
				var ev nip01.Event
				if err := json.Unmarshal(v, &ev); err != nil || !f.takes(ev.Kind) {
					continue
				}
				out.Events = append(out.Events, &ev)
				out.Evsids = append(out.Evsids, evsid)
			}
			if dirtyDone {
				return nil
			}
			dirtyDone = true
			if d := b.Bucket(feedDirty); d != nil {
				dc := d.Cursor()
				k, v := dc.First()
				if next.DirtyAfter != "" {
					k, v = dc.Seek([]byte(next.DirtyAfter))
					if k != nil && string(k) == next.DirtyAfter {
						k, v = dc.Next()
					}
				}
				for ; k != nil && len(out.Dirty) < maxDirty; k, v = dc.Next() {
					out.Dirty = append(out.Dirty, string(k))
					out.seqs = append(out.seqs, btoi(v))
					next.DirtyAfter = string(k)
				}
			}
			return nil
		})
		if err != nil {
			return FeedBatch{}, from, err
		}
		if read < scanBatch*5 || len(out.Events) >= maxEvents {
			return out, next, nil
		}
	}
}

// AckFeed records that the consumer applied a batch: the watermark moves to
// its Through, and each queued author leaves the queue unless queued again
// since the batch was read.
func (s *EventStore) AckFeed(name string, batch FeedBatch) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := feedBucket(tx, name)
		if b == nil {
			return ErrUnknownFeed
		}
		if v := b.Get(feedWKey); batch.Through > 0 && (len(v) != 8 || btoi(v) < batch.Through) {
			if err := b.Put(feedWKey, itob(batch.Through)); err != nil {
				return err
			}
		}
		d := b.Bucket(feedDirty)
		if d == nil {
			return nil
		}
		for i, pk := range batch.Dirty {
			if v := d.Get([]byte(pk)); len(v) == 8 && btoi(v) == batch.seqs[i] {
				if err := d.Delete([]byte(pk)); err != nil {
					return err
				}
				if err := addCounter(b, feedDirtyN, -1); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// FeedStatus is how far a feed's consumer is.
type FeedStatus struct {
	Name      string `json:"name"`
	Watermark uint64 `json:"watermark"`
	Head      uint64 `json:"head"`
	// Behind is events stored after the watermark, of any kind.
	Behind uint64 `json:"behind"`
	// Queued is authors waiting to be looked at again.
	Queued int64 `json:"queued"`
}

// FeedStatus reports a feed's progress.
func (s *EventStore) FeedStatus(name string) (FeedStatus, error) {
	st := FeedStatus{Name: name}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := feedBucket(tx, name)
		if b == nil {
			return ErrUnknownFeed
		}
		if v := b.Get(feedWKey); len(v) == 8 {
			st.Watermark = btoi(v)
		}
		if v := b.Get(feedDirtyN); len(v) == 8 {
			st.Queued = int64(btoi(v))
		}
		st.Head = tx.Bucket(indexEvents).Sequence()
		if st.Head > st.Watermark {
			st.Behind = st.Head - st.Watermark
		}
		return nil
	})
	return st, err
}

// SetFeedWatermark moves a feed's watermark: 0 has its consumer see every
// stored event again.
func (s *EventStore) SetFeedWatermark(name string, w uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := feedBucket(tx, name)
		if b == nil {
			return ErrUnknownFeed
		}
		return b.Put(feedWKey, itob(w))
	})
}

// Head returns the sequence of the last stored event.
func (s *EventStore) Head() uint64 {
	var h uint64
	_ = s.db.View(func(tx *bolt.Tx) error {
		h = tx.Bucket(indexEvents).Sequence()
		return nil
	})
	return h
}

// CommitSignal returns a channel closed at the next write that may have
// stored events.
func (s *EventStore) CommitSignal() <-chan struct{} { return s.commitSignal() }
