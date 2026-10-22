package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// DerivedIndexes selects the indexes a store keeps beyond the ones queries
// need. Each backs only an optional feature, so a store builds none of them
// unless asked.
type DerivedIndexes struct {
	// Zaps backs zap ranking and totals (ZapRanking, ZapTotals, TopZapped).
	Zaps bool
	// Social backs profile stats and social scores (GetProfileStats,
	// ComputeSocialScore).
	Social bool
}

// ErrIndexDisabled is returned when a derived index the call needs isn't
// enabled on this store (WithEventStoreIndexes).
var ErrIndexDisabled = errors.New("index not enabled on this store")

// IndexState describes one derived index.
type IndexState struct {
	// Enabled: writes maintain it and readers serve it.
	Enabled bool `json:"enabled"`
	// Current: it reflects every stored event.
	Current bool `json:"current"`
	// Rebuilding: a rebuild or clear is running.
	Rebuilding bool `json:"rebuilding"`
	// HasData: it holds entries, current or not.
	HasData bool `json:"has_data"`
	// Entries is zap receipts for the zap index, followed profiles for the
	// social one.
	Entries int64 `json:"entries"`
}

// socialRescoreKey marks a social rebuild whose scores aren't stored yet.
var socialRescoreKey = []byte("rescore")

// derivedIndex is one derived index's layout and switches.
type derivedIndex struct {
	name    string
	meta    []byte   // meta bucket: active, building, gen and markers
	def     []byte   // active bucket name before any rebuild
	markers [][]byte // meta keys that, all present, mean current
	extra   [][]byte // meta keys dropped along with the markers
	enabled bool
	// rebuilding guards rebuilds and clears against each other.
	rebuilding atomic.Bool
	// marked is set while a disabled index may still be marked current, so
	// the first write that skips it unmarks it.
	marked atomic.Bool
	// size reports whether an active bucket holds data, and how much.
	size func(b *bolt.Bucket) (bool, int64)
	// rebuild builds it from the stored events.
	rebuild func(ctx context.Context) (int, error)
}

func newDerivedIndexes(s *EventStore, ix DerivedIndexes) {
	s.zaps = &derivedIndex{
		name:    "zap",
		meta:    zapMeta,
		def:     indexZaps,
		markers: [][]byte{coinsKey},
		enabled: ix.Zaps,
		size: func(b *bolt.Bucket) (bool, int64) {
			k, _ := b.Cursor().First()
			return k != nil, int64(b.Stats().KeyN)
		},
		rebuild: func(ctx context.Context) (int, error) { return s.RebuildZapIndex(ctx, nil) },
	}
	s.social = &derivedIndex{
		name:    "social",
		meta:    socialMeta,
		def:     socialDefault,
		markers: [][]byte{socialBuiltAt, coinsKey},
		extra:   [][]byte{socialRescoreKey},
		enabled: ix.Social,
		size: func(gen *bolt.Bucket) (bool, int64) {
			has := false
			for _, sub := range [][]byte{subZapsRecd, subZapsSent, subFollowEdges, subFollowers, subFollowing} {
				if b := gen.Bucket(sub); b != nil {
					if k, _ := b.Cursor().First(); k != nil {
						has = true
						break
					}
				}
			}
			var n int64
			if b := gen.Bucket(subFollowers); b != nil {
				n = int64(b.Stats().KeyN)
			}
			return has, n
		},
		rebuild: func(ctx context.Context) (int, error) { return s.RebuildSocialIndex(ctx, nil) },
	}
}

func metaValue(tx *bolt.Tx, meta, key []byte) []byte {
	if m := tx.Bucket(meta); m != nil {
		if v := m.Get(key); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return nil
}

func (d *derivedIndex) active(tx *bolt.Tx) []byte {
	if v := metaValue(tx, d.meta, zapActiveKey); v != nil {
		return v
	}
	return d.def
}

func (d *derivedIndex) building(tx *bolt.Tx) []byte {
	return metaValue(tx, d.meta, zapBuildingKey)
}

func (d *derivedIndex) current(tx *bolt.Tx) bool {
	m := tx.Bucket(d.meta)
	if m == nil {
		return false
	}
	for _, k := range d.markers {
		if m.Get(k) == nil {
			return false
		}
	}
	return true
}

// hasMarks reports whether any marker or extra key is set.
func (d *derivedIndex) hasMarks(tx *bolt.Tx) bool {
	m := tx.Bucket(d.meta)
	if m == nil {
		return false
	}
	for _, k := range append(d.markers, d.extra...) {
		if m.Get(k) != nil {
			return true
		}
	}
	return false
}

// stamp marks the index current.
func (d *derivedIndex) stamp(tx *bolt.Tx) error {
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return err
	}
	for _, k := range d.markers {
		v := []byte{1}
		if bytes.Equal(k, socialBuiltAt) {
			v = itob(uint64(time.Now().Unix()))
		}
		if err := m.Put(k, v); err != nil {
			return err
		}
	}
	return nil
}

// unmark drops the markers, so the next open with the index enabled
// rebuilds it.
func (d *derivedIndex) unmark(tx *bolt.Tx) error {
	m := tx.Bucket(d.meta)
	if m == nil {
		return nil
	}
	for _, k := range append(d.markers, d.extra...) {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	tx.OnCommit(func() { d.marked.Store(false) })
	return nil
}

// skip is called, in place of an update, by a write the disabled index
// misses: its data stops being current.
func (d *derivedIndex) skip(tx *bolt.Tx) error {
	if !d.marked.Load() {
		return nil
	}
	return d.unmark(tx)
}

// dropBuilding deletes a rebuild's generation left behind by a crash.
func (d *derivedIndex) dropBuilding(tx *bolt.Tx) error {
	name := d.building(tx)
	if name == nil {
		return nil
	}
	if err := tx.DeleteBucket(name); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
		return err
	}
	return tx.Bucket(d.meta).Delete(zapBuildingKey)
}

// clear deletes the index's data and markers, keeping the meta bucket.
func (d *derivedIndex) clear(tx *bolt.Tx) error {
	if err := d.dropBuilding(tx); err != nil {
		return err
	}
	if err := tx.DeleteBucket(d.active(tx)); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
		return err
	}
	if m := tx.Bucket(d.meta); m != nil {
		if err := m.Delete(zapActiveKey); err != nil {
			return err
		}
	}
	return d.unmark(tx)
}

// clearIndex runs clear unless a rebuild holds the index.
func (s *EventStore) clearIndex(ctx context.Context, d *derivedIndex, busy error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !d.rebuilding.CompareAndSwap(false, true) {
		return busy
	}
	defer d.rebuilding.Store(false)
	return s.db.Update(d.clear)
}

func (s *EventStore) indexState(d *derivedIndex) IndexState {
	st := IndexState{Enabled: d.enabled, Rebuilding: d.rebuilding.Load()}
	_ = s.db.View(func(tx *bolt.Tx) error {
		st.Current = d.current(tx)
		if b := tx.Bucket(d.active(tx)); b != nil {
			st.HasData, st.Entries = d.size(b)
		}
		return nil
	})
	return st
}

// ZapIndexState reports the zap index's state.
func (s *EventStore) ZapIndexState() IndexState { return s.indexState(s.zaps) }

// SocialIndexState reports the social index's state.
func (s *EventStore) SocialIndexState() IndexState { return s.indexState(s.social) }

// backfillIndexes prepares the derived indexes on open: it drops a crashed
// rebuild's generation, and builds each enabled index that isn't current,
// once and in the background (an empty store is just marked current). A
// disabled index is left as is until a write skips it, so opening a store
// to read it changes nothing.
func (s *EventStore) backfillIndexes() {
	ixs := []*derivedIndex{s.social, s.zaps}
	needWrite := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		for _, d := range ixs {
			if d.building(tx) != nil || (d.enabled && !d.current(tx)) {
				needWrite = true
			}
			if !d.enabled {
				d.marked.Store(d.hasMarks(tx))
			}
		}
		return nil
	})
	if !needWrite {
		return
	}
	var rebuild []*derivedIndex
	err := s.db.Update(func(tx *bolt.Tx) error {
		rebuild = nil
		empty := true
		if b := tx.Bucket(indexEvents); b != nil {
			if k, _ := b.Cursor().First(); k != nil {
				empty = false
			}
		}
		for _, d := range ixs {
			if err := d.dropBuilding(tx); err != nil {
				return err
			}
			if !d.enabled || d.current(tx) {
				continue
			}
			if empty {
				if err := d.stamp(tx); err != nil {
					return err
				}
				continue
			}
			rebuild = append(rebuild, d)
		}
		return nil
	})
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to prepare the derived indexes")
		return
	}
	if len(rebuild) == 0 {
		return
	}
	s.workersWg.Add(1)
	go func() {
		defer s.workersWg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-s.closeCh:
				cancel()
			case <-ctx.Done():
			}
		}()
		for _, d := range rebuild {
			s.logger.Info().Str("index", d.name).Msg("building the index from stored events")
			n, err := d.rebuild(ctx)
			if !s.logRebuild(d.name, n, err) {
				return
			}
		}
	}()
}

// logRebuild logs a background rebuild's outcome; false when it didn't finish.
func (s *EventStore) logRebuild(index string, n int, err error) bool {
	switch {
	case errors.Is(err, context.Canceled):
		return false
	case err != nil:
		s.logger.Error().Err(err).Str("index", index).Msg("failed to build the index")
		return false
	}
	s.logger.Info().Str("index", index).Int("indexed", n).Msg("index built")
	return true
}

// TakeSocialRescore returns up to limit profiles still to rescore after a
// social rebuild, walking every stored profile (kind 0 author) once. It
// returns nil when no rescore is pending.
func (s *EventStore) TakeSocialRescore(limit int) []string {
	if !s.social.enabled || limit <= 0 {
		return nil
	}
	s.socialMu.Lock()
	defer s.socialMu.Unlock()
	var out []string
	done := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		if metaValue(tx, socialMeta, socialRescoreKey) == nil {
			s.rescoreAfter = nil
			return nil
		}
		b := tx.Bucket(indexKindPubkey)
		if b == nil {
			done = true
			return nil
		}
		kind0 := make([]byte, 8)
		seek := kind0
		if s.rescoreAfter != nil {
			seek = append(append(append([]byte(nil), kind0...), s.rescoreAfter...), bytes.Repeat([]byte{0xFF}, 16)...)
		}
		c := b.Cursor()
		k, _ := c.Seek(seek)
		var last []byte
		for ; k != nil && bytes.HasPrefix(k, kind0) && len(out) < limit; k, _ = c.Next() {
			if len(k) != profileKeyLen || bytes.Equal(k[8:40], last) {
				continue
			}
			last = append(last[:0], k[8:40]...)
			out = append(out, hex.EncodeToString(last))
		}
		done = k == nil || !bytes.HasPrefix(k, kind0)
		if last != nil {
			s.rescoreAfter = last
		}
		return nil
	})
	if done {
		s.rescoreAfter = nil
		if err := s.db.Update(func(tx *bolt.Tx) error {
			if m := tx.Bucket(socialMeta); m != nil {
				return m.Delete(socialRescoreKey)
			}
			return nil
		}); err != nil {
			s.logger.Warn().Err(err).Msg("failed to finish the social rescore")
		}
	}
	return out
}

// warnMissingIndexes warns when a session feature needs a derived index the
// store wasn't opened with: that feature then answers as if disabled.
func warnMissingIndexes(cfg *SessionConfig, store *EventStore, search bool) {
	if store == nil {
		return
	}
	if cfg.Zaps.Enabled && !store.zaps.enabled {
		cfg.Logger.Warn().Msg("zap ranking is enabled but the store's zap index is not (WithEventStoreIndexes): zap ranking stays unavailable")
	}
	if (cfg.EnableProfileStats || search) && !store.social.enabled {
		cfg.Logger.Warn().Msg("profile stats or search is enabled but the store's social index is not (WithEventStoreIndexes): stats are unavailable and social scores stay zero")
	}
}
