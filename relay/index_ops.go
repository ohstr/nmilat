package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
)

// Index actions, as IndexStatus.Action names them.
const (
	ActionRebuild = "rebuild"
	ActionResume  = "resume"
	ActionCatchUp = "catch_up"
	ActionRescore = "rescore"
	ActionReap    = "reap"
)

// Index states, as IndexStatus.State names them.
const (
	StateDisabled     = "disabled"
	StateEmpty        = "empty"
	StateReady        = "ready"
	StateBehind       = "behind"
	StateNeedsRebuild = "needs_rebuild"
)

// IndexStatus describes one derived index: what it holds, whether it is
// current, and what it needs next.
type IndexStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	// Running is the operation in progress, "" when idle.
	Running string `json:"running,omitempty"`
	// Action is what brings it current ("" when nothing), Reason why.
	Action  string `json:"action,omitempty"`
	Reason  string `json:"reason,omitempty"`
	HasData bool   `json:"has_data"`
	// Entries is exact: zap receipts for zaps, followed profiles for social.
	Entries int64 `json:"entries"`
	// Watermark is the last stored event a behind index reflects; Behind is
	// how many events were stored after it.
	Watermark  uint64      `json:"watermark,omitempty"`
	Behind     uint64      `json:"behind,omitempty"`
	Head       uint64      `json:"head"`
	Tombstones int64       `json:"tombstones,omitempty"`
	BuiltAt    int64       `json:"built_at,omitempty"`
	Build      *IndexBuild `json:"build,omitempty"`
	// Retired is how many old generations wait to be freed.
	Retired int `json:"retired,omitempty"`
}

// IndexBuild is a rebuild in progress, possibly paused by a restart.
type IndexBuild struct {
	Mark      uint64 `json:"mark"`
	Head      uint64 `json:"head"`
	Scanned   int64  `json:"scanned"`
	Indexed   int64  `json:"indexed"`
	StartedAt int64  `json:"started_at"`
}

// IndexProgress is reported while an operation runs.
type IndexProgress struct {
	Phase string `json:"phase"`
	// Done and Total are in the phase's own unit: events for a scan,
	// entries for tombstones, profiles for a rescore, keys for a reap.
	Done  int64 `json:"done"`
	Total int64 `json:"total"`
	// Applied counts events (or entries) the operation changed.
	Applied int64 `json:"applied"`
}

// IndexResult is what an operation did.
type IndexResult struct {
	Scanned       int64 `json:"scanned"`
	Applied       int64 `json:"applied"`
	EntriesBefore int64 `json:"entries_before"`
	EntriesAfter  int64 `json:"entries_after"`
}

// Batch bounds: an operation holds the writer for at most applyBudget or
// applyMax events per transaction, so ingest never waits long behind it.
// The budget counts from inside the transaction, not the wait for the
// writer, and each transaction makes progress however long that wait was.
var (
	scanBatch   = 1000
	applyMax    = 256
	applyBudget = 25 * time.Millisecond
	reapChunk   = 10_000
)

// IndexStatus reports a derived index's state.
func (s *EventStore) IndexStatus(name string) (IndexStatus, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexStatus{}, err
	}
	st := IndexStatus{Name: d.name, Enabled: d.enabled, Running: d.running.Load().(string)}
	err = s.db.View(func(tx *bolt.Tx) error {
		state, w := d.state(tx)
		man := d.manifest(tx)
		st.Head = tx.Bucket(indexEvents).Sequence()
		st.HasData = s.hasData(tx, d)
		st.Entries = d.entries(tx, d.active(tx))
		st.BuiltAt = man.BuiltAt
		st.Retired = len(man.Retired)
		if v := metaValue(tx, d.meta, keyTombN); len(v) == 8 {
			st.Tombstones = int64(btoi(v))
		}
		if b := man.Build; b != nil {
			st.Build = &IndexBuild{Mark: b.Mark, Head: b.Head, Scanned: b.Scanned, Indexed: b.Indexed, StartedAt: b.StartedAt}
		}
		if state == stFrozen {
			st.Watermark = w
			if st.Head > w {
				st.Behind = st.Head - w
			}
		}
		empty := true
		if k, _ := tx.Bucket(indexEvents).Cursor().First(); k != nil {
			empty = false
		}
		st.State, st.Action, st.Reason = reconcile(d, state, man, st, empty, s.rescorePending(tx, d))
		return nil
	})
	return st, err
}

// reconcile decides, from what an index records, its state and the one
// action that brings it current.
func reconcile(d *derivedIndex, state byte, man indexManifest, st IndexStatus, empty bool, rescore string) (string, string, string) {
	if !d.enabled {
		if st.Retired > 0 {
			return StateDisabled, ActionReap, fmt.Sprintf("%d old generation(s) to free", st.Retired)
		}
		return StateDisabled, "", ""
	}
	var stateName, action, reason string
	switch state {
	case stLive:
		stateName = StateReady
	case stFrozen:
		stateName = StateBehind
	case stDirty:
		stateName, action, reason = StateNeedsRebuild, ActionRebuild, man.Reason
	default:
		stateName = StateNeedsRebuild
		if empty {
			stateName = StateEmpty
		} else {
			action, reason = ActionRebuild, "never built"
		}
	}
	switch {
	case man.Build != nil:
		action = ActionResume
		reason = fmt.Sprintf("resuming the rebuild at event %d of %d", man.Build.Mark, man.Build.Head)
	case action != "":
	case (state == stLive || state == stFrozen) && man.Schema < indexSchema:
		stateName, action, reason = StateNeedsRebuild, ActionRebuild, fmt.Sprintf("layout %d → %d", man.Schema, indexSchema)
	case state == stFrozen:
		action = ActionCatchUp
		reason = fmt.Sprintf("%d event(s) stored since it was last current", st.Behind)
		if st.Tombstones > 0 {
			reason += fmt.Sprintf(", %d deleted", st.Tombstones)
		}
	case rescore != "":
		action, reason = ActionRescore, rescore
	case st.Retired > 0:
		action, reason = ActionReap, fmt.Sprintf("%d old generation(s) to free", st.Retired)
	}
	return stateName, action, reason
}

// RebuildIndex rebuilds an enabled index from every stored event into a new
// generation and swaps it in once complete; readers keep the old one until
// then. A rebuild interrupted by a restart or a cancelled ctx resumes where
// it stopped; AbortIndexBuild discards it instead.
func (s *EventStore) RebuildIndex(ctx context.Context, name string, progress func(IndexProgress)) (IndexResult, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexResult{}, err
	}
	if !d.enabled {
		return IndexResult{}, ErrIndexDisabled
	}
	if err := d.start(ActionRebuild); err != nil {
		return IndexResult{}, err
	}
	defer d.finish()

	var res IndexResult
	var build indexBuild
	err = s.db.Update(func(tx *bolt.Tx) error {
		man := d.manifest(tx)
		res.EntriesBefore = d.entries(tx, d.active(tx))
		if man.Build != nil && tx.Bucket(man.Build.Gen) != nil {
			build = *man.Build
			return nil
		}
		if man.Build != nil {
			man.Retired = append(man.Retired, man.Build.Gen)
		}
		gen, err := d.nextGen(tx, 'g')
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucket(gen); err != nil {
			return err
		}
		build = indexBuild{Gen: gen, Head: tx.Bucket(indexEvents).Sequence(), StartedAt: time.Now().Unix()}
		man.Build = &build
		if err := d.putManifest(tx, man); err != nil {
			return err
		}
		return tx.Bucket(d.meta).Put(zapBuildingKey, gen)
	})
	if err != nil {
		return res, err
	}

	scanned, applied, err := s.scanIndex(ctx, d, build.Mark, build.Scanned, func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) (bool, error) {
		delta, _, err := d.apply(s, tx, build.Gen, ev, evsid, true)
		if err != nil {
			return false, err
		}
		return true, d.addEntries(tx, build.Gen, delta)
	}, func(tx *bolt.Tx, mark uint64, scanned, applied int64) error {
		man := d.manifest(tx)
		if man.Build == nil {
			return fmt.Errorf("the rebuild was abandoned")
		}
		man.Build.Mark, man.Build.Scanned, man.Build.Indexed = mark, scanned, man.Build.Indexed+applied
		return d.putManifest(tx, man)
	}, func(pos uint64, applied int64) {
		if progress != nil {
			progress(IndexProgress{Phase: "scan", Done: int64(pos), Total: int64(max(build.Head, pos)), Applied: build.Indexed + applied})
		}
	})
	res.Scanned, res.Applied = scanned, build.Indexed+applied
	if err != nil {
		return res, err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		man := d.manifest(tx)
		if man.Build == nil || !bytes.Equal(man.Build.Gen, build.Gen) {
			return fmt.Errorf("the rebuild was abandoned")
		}
		old := d.active(tx)
		m := tx.Bucket(d.meta)
		if err := m.Put(zapActiveKey, build.Gen); err != nil {
			return err
		}
		if err := m.Delete(zapBuildingKey); err != nil {
			return err
		}
		if tx.Bucket(old) != nil {
			man.Retired = append(man.Retired, old)
		}
		if man.Tomb != nil {
			man.Retired = append(man.Retired, man.Tomb)
		}
		man.Build, man.Tomb, man.Reason = nil, nil, ""
		man.Schema, man.BuiltAt = indexSchema, time.Now().Unix()
		if err := d.putManifest(tx, man); err != nil {
			return err
		}
		for _, k := range [][]byte{keyTombN, keyTombB} {
			if err := m.Delete(k); err != nil {
				return err
			}
		}
		if d == s.social {
			if err := m.Put(socialRescoreKey, []byte("after a rebuild")); err != nil {
				return err
			}
			if err := m.Delete(socialRescoreAfter); err != nil {
				return err
			}
		}
		res.EntriesAfter = d.entries(tx, build.Gen)
		if err := d.stampKinds(tx); err != nil {
			return err
		}
		return d.setState(tx, stLive, 0)
	})
	return res, err
}

// AbortIndexBuild discards a paused or interrupted rebuild.
func (s *EventStore) AbortIndexBuild(name string) error {
	d, err := s.index(name)
	if err != nil {
		return err
	}
	if err := d.start("abort"); err != nil {
		return err
	}
	defer d.finish()
	return s.db.Update(func(tx *bolt.Tx) error {
		if d.manifest(tx).Build == nil {
			return ErrNothingToDo
		}
		return s.retireBuild(tx, d)
	})
}

// CatchUpIndex brings an enabled index that fell behind (it was off while
// events were stored) current: it removes what was deleted meanwhile, then
// applies the events stored after its watermark. It works in place, in
// bounded steps, and resumes after a restart from where it stopped.
func (s *EventStore) CatchUpIndex(ctx context.Context, name string, progress func(IndexProgress)) (IndexResult, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexResult{}, err
	}
	if !d.enabled {
		return IndexResult{}, ErrIndexDisabled
	}
	if err := d.start(ActionCatchUp); err != nil {
		return IndexResult{}, err
	}
	defer d.finish()

	var res IndexResult
	var from uint64
	var head, tombs int64
	err = s.db.View(func(tx *bolt.Tx) error {
		st, w := d.state(tx)
		if st != stFrozen {
			return ErrNothingToDo
		}
		from = w
		head = int64(tx.Bucket(indexEvents).Sequence())
		res.EntriesBefore = d.entries(tx, d.active(tx))
		if v := metaValue(tx, d.meta, keyTombN); len(v) == 8 {
			tombs = int64(btoi(v))
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	removed, err := s.applyTombstones(ctx, d, func(done int64) {
		if progress != nil {
			progress(IndexProgress{Phase: "deletes", Done: done, Total: tombs, Applied: done})
		}
	})
	res.Applied = removed
	if err != nil {
		return res, err
	}

	scanned, applied, err := s.scanIndex(ctx, d, from, 0, func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) (bool, error) {
		return true, s.applyLive(tx, d, ev, evsid, true, d.active(tx))
	}, func(tx *bolt.Tx, mark uint64, _, _ int64) error {
		if st, _ := d.state(tx); st != stFrozen {
			return fmt.Errorf("the index changed state during the catch-up")
		}
		return d.setState(tx, stFrozen, mark)
	}, func(pos uint64, applied int64) {
		if progress != nil {
			progress(IndexProgress{Phase: "scan", Done: int64(pos - from), Total: max(head-int64(from), int64(pos-from)), Applied: removed + applied})
		}
	})
	res.Scanned, res.Applied = scanned, removed+applied
	if err != nil {
		return res, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if st, _ := d.state(tx); st != stFrozen {
			return fmt.Errorf("the index changed state during the catch-up")
		}
		res.EntriesAfter = d.entries(tx, d.active(tx))
		if err := d.stampKinds(tx); err != nil {
			return err
		}
		return d.setState(tx, stLive, 0)
	})
	return res, err
}

// applyTombstones removes, in bounded steps, the events deleted while the
// index was off, then drops their bucket.
func (s *EventStore) applyTombstones(ctx context.Context, d *derivedIndex, progress func(done int64)) (int64, error) {
	var done int64
	for {
		finished := false
		err := s.indexTx(d, func(tx *bolt.Tx, start time.Time) error {
			man := d.manifest(tx)
			if man.Tomb == nil {
				finished = true
				return nil
			}
			b := tx.Bucket(man.Tomb)
			var keys [][]byte
			var vals [][]byte
			if b != nil {
				c := b.Cursor()
				for k, v := c.First(); k != nil && len(keys) < applyMax; k, v = c.Next() {
					keys = append(keys, append([]byte(nil), k...))
					vals = append(vals, append([]byte(nil), v...))
				}
			}
			if len(keys) == 0 {
				if b != nil {
					if err := tx.DeleteBucket(man.Tomb); err != nil {
						return err
					}
				}
				man.Tomb = nil
				m := tx.Bucket(d.meta)
				for _, k := range [][]byte{keyTombN, keyTombB} {
					if err := m.Delete(k); err != nil {
						return err
					}
				}
				finished = true
				return d.putManifest(tx, man)
			}
			var n, bytesGone int64
			for i, k := range keys {
				var ev nip01.Event
				if err := json.Unmarshal(vals[i], &ev); err == nil {
					if err := s.applyLive(tx, d, &ev, btoi(k), false, d.active(tx), d.building(tx)); err != nil {
						return err
					}
				}
				if err := b.Delete(k); err != nil {
					return err
				}
				n++
				bytesGone += int64(len(vals[i]))
				if time.Since(start) > applyBudget {
					break
				}
			}
			done += n
			m := tx.Bucket(d.meta)
			if err := addCounter(m, keyTombN, -n); err != nil {
				return err
			}
			return addCounter(m, keyTombB, -bytesGone)
		})
		if err != nil {
			return done, err
		}
		if progress != nil {
			progress(done)
		}
		if finished {
			return done, nil
		}
		if err := s.yield(ctx); err != nil {
			return done, err
		}
	}
}

// ClearIndex empties a disabled index: its data is retired at once (freed
// by ReapIndex) and it is rebuilt when next enabled. An enabled index is
// kept current instead, so clearing it is refused.
func (s *EventStore) ClearIndex(name string) (IndexResult, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexResult{}, err
	}
	if d.enabled {
		return IndexResult{}, ErrIndexEnabled
	}
	if err := d.start("clear"); err != nil {
		return IndexResult{}, err
	}
	defer d.finish()
	var res IndexResult
	err = s.db.Update(func(tx *bolt.Tx) error {
		man := d.manifest(tx)
		st, _ := d.state(tx)
		active := d.active(tx)
		res.EntriesBefore = d.entries(tx, active)
		if !s.hasData(tx, d) && man.Tomb == nil && man.Build == nil && st == stNone {
			return ErrNothingToDo
		}
		if tx.Bucket(active) != nil {
			man.Retired = append(man.Retired, active)
		}
		if man.Tomb != nil {
			man.Retired = append(man.Retired, man.Tomb)
		}
		if man.Build != nil {
			man.Retired = append(man.Retired, man.Build.Gen)
		}
		man.Build, man.Tomb, man.Reason, man.BuiltAt = nil, nil, "", 0
		fresh, err := d.nextGen(tx, 'g')
		if err != nil {
			return err
		}
		m := tx.Bucket(d.meta)
		if err := m.Put(zapActiveKey, fresh); err != nil {
			return err
		}
		for _, k := range [][]byte{zapBuildingKey, keyTombN, keyTombB, keyKinds, socialRescoreKey, socialRescoreAfter} {
			if err := m.Delete(k); err != nil {
				return err
			}
		}
		if err := d.putManifest(tx, man); err != nil {
			return err
		}
		return d.setState(tx, stNone, 0)
	})
	return res, err
}

// ReapIndex frees the generations an index no longer reads, a bounded
// chunk of keys per transaction.
func (s *EventStore) ReapIndex(ctx context.Context, name string, progress func(IndexProgress)) (IndexResult, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexResult{}, err
	}
	if err := d.start(ActionReap); err != nil {
		return IndexResult{}, err
	}
	defer d.finish()
	var res IndexResult
	for {
		var target []byte
		_ = s.db.View(func(tx *bolt.Tx) error {
			if r := d.manifest(tx).Retired; len(r) > 0 {
				target = r[0]
			}
			return nil
		})
		if target == nil {
			if res.Applied == 0 {
				return res, ErrNothingToDo
			}
			return res, nil
		}
		for {
			var gone int64
			empty := false
			err := s.indexTx(d, func(tx *bolt.Tx, start time.Time) error {
				b := tx.Bucket(target)
				if b == nil {
					empty = true
				} else {
					budget := reapChunk
					var err error
					empty, err = drainBucket(b, &budget, start)
					gone = int64(reapChunk - budget)
					if err != nil {
						return err
					}
				}
				if !empty {
					return nil
				}
				if b != nil {
					if err := tx.DeleteBucket(target); err != nil {
						return err
					}
				}
				man := d.manifest(tx)
				kept := man.Retired[:0]
				for _, r := range man.Retired {
					if !bytes.Equal(r, target) {
						kept = append(kept, r)
					}
				}
				man.Retired = kept
				if err := tx.Bucket(d.meta).Delete(entriesKey(target)); err != nil {
					return err
				}
				return d.putManifest(tx, man)
			})
			if err != nil {
				return res, err
			}
			res.Applied += gone
			if progress != nil {
				progress(IndexProgress{Phase: "free", Done: res.Applied, Applied: res.Applied})
			}
			if empty {
				break
			}
			if err := s.yield(ctx); err != nil {
				return res, err
			}
		}
	}
}

// drainBucket deletes keys from b, descending into nested buckets, until
// it is empty or the budget (keys, and applyBudget since start) runs out.
// It always takes one round of keys, so a late start still makes progress.
func drainBucket(b *bolt.Bucket, budget *int, start time.Time) (bool, error) {
	for first := true; *budget > 0 && (first || time.Since(start) < applyBudget); first = false {
		var keys, nested [][]byte
		c := b.Cursor()
		for k, v := c.First(); k != nil && len(keys)+len(nested) < *budget; k, v = c.Next() {
			if v == nil {
				nested = append(nested, append([]byte(nil), k...))
			} else {
				keys = append(keys, append([]byte(nil), k...))
			}
		}
		if len(keys)+len(nested) == 0 {
			return true, nil
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return false, err
			}
			*budget--
		}
		for _, k := range nested {
			empty, err := drainBucket(b.Bucket(k), budget, start)
			if err != nil || !empty {
				return false, err
			}
			if err := b.DeleteBucket(k); err != nil {
				return false, err
			}
		}
	}
	k, _ := b.Cursor().First()
	return k == nil, nil
}

// scanIndex applies the stored events after from that the index takes, in
// bounded write transactions. Each one re-reads its events, so one deleted
// since the read pass is skipped, and records its position through
// checkpoint, so a restart resumes from it. It returns the events scanned
// and applied.
func (s *EventStore) scanIndex(ctx context.Context, d *derivedIndex, from uint64, scanned int64,
	apply func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) (bool, error),
	checkpoint func(tx *bolt.Tx, mark uint64, scanned, applied int64) error,
	progress func(pos uint64, applied int64),
) (int64, int64, error) {
	var applied int64
	pos := from
	lastCheckpoint := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return scanned, applied, err
		}
		var matched []uint64
		var last uint64
		n := 0
		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(indexEvents).Cursor()
			for k, v := c.Seek(itob(pos + 1)); k != nil && n < scanBatch; k, v = c.Next() {
				n++
				last = binary.BigEndian.Uint64(k)
				if kind, ok := peekKind(v); !ok || d.matches(kind) {
					matched = append(matched, last)
				}
			}
			return nil
		})
		if err != nil {
			return scanned, applied, err
		}
		if n == 0 {
			if pos != from {
				err := s.db.Update(func(tx *bolt.Tx) error { return checkpoint(tx, pos, scanned, 0) })
				return scanned, applied, err
			}
			return scanned, applied, nil
		}
		// Write when there is something to apply, or at least every second
		// so a scan through other kinds still records its position.
		i := 0
		for i < len(matched) || time.Since(lastCheckpoint) >= time.Second {
			var got int64
			mark := last
			err := s.indexTx(d, func(tx *bolt.Tx, start time.Time) error {
				events := tx.Bucket(indexEvents)
				for first := i; i < len(matched) && got < int64(applyMax) && (i == first || time.Since(start) < applyBudget); {
					evsid := matched[i]
					i++
					raw := events.Get(itob(evsid))
					if raw == nil {
						continue
					}
					var ev nip01.Event
					if err := json.Unmarshal(raw, &ev); err != nil {
						s.logger.Warn().Err(err).Uint64("evsid", evsid).Msg("index scan: failed to unmarshal event")
						continue
					}
					if !d.matches(ev.Kind) {
						continue
					}
					ok, err := apply(tx, &ev, evsid)
					if err != nil {
						return err
					}
					if ok {
						got++
					}
				}
				if i > 0 && i < len(matched) {
					mark = matched[i-1]
				}
				return checkpoint(tx, mark, scanned+int64(n), got)
			})
			if err != nil {
				return scanned, applied, err
			}
			applied += got
			lastCheckpoint = time.Now()
			if progress != nil {
				progress(mark, applied)
			}
			if i == len(matched) {
				break
			}
			if err := s.yield(ctx); err != nil {
				return scanned, applied, err
			}
		}
		scanned += int64(n)
		pos = last
		if progress != nil {
			progress(pos, applied)
		}
		if err := s.yield(ctx); err != nil {
			return scanned, applied, err
		}
	}
}

// indexTx runs one bounded write transaction of an index operation. start
// is when fn got the writer, so waiting for it never counts against the
// budget, and the time it held the writer is reported.
func (s *EventStore) indexTx(d *derivedIndex, fn func(tx *bolt.Tx, start time.Time) error) error {
	var start time.Time
	err := s.db.Update(func(tx *bolt.Tx) error {
		start = time.Now()
		return fn(tx, start)
	})
	if !start.IsZero() {
		s.observer().IndexBatchCommitted(d.name, time.Since(start))
	}
	return err
}

// yield lets queued writes through between an operation's transactions.
func (s *EventStore) yield(ctx context.Context) error {
	if s.TaskQueueDepth() > 0 {
		t := time.NewTimer(min(s.batchInterval*2, 50*time.Millisecond))
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closeCh:
			return context.Canceled
		case <-t.C:
		}
	} else {
		runtime.Gosched()
	}
	select {
	case <-s.closeCh:
		return context.Canceled
	default:
	}
	return ctx.Err()
}

// peekKind reads a stored event's kind without decoding it. Inside a JSON
// string every quote is escaped, so the first `"kind":` is the field.
func peekKind(raw []byte) (int, bool) {
	i := bytes.Index(raw, []byte(`"kind":`))
	if i < 0 {
		return 0, false
	}
	rest := raw[i+7:]
	j := 0
	for j < len(rest) && (rest[j] == '-' || (rest[j] >= '0' && rest[j] <= '9')) {
		j++
	}
	k, err := strconv.Atoi(string(rest[:j]))
	return k, err == nil
}

// IndexMaintenance chooses who runs the derived indexes' operations.
type IndexMaintenance int

const (
	// MaintenanceAuto runs whatever IndexStatus asks for, in the
	// background, after open and whenever an operation finishes.
	MaintenanceAuto IndexMaintenance = iota
	// MaintenanceManual leaves it to the embedder (IndexStatus, then
	// RebuildIndex, CatchUpIndex, RescoreIndex or ReapIndex).
	MaintenanceManual
)

// RunIndexAction runs the action IndexStatus asks for on name.
func (s *EventStore) RunIndexAction(ctx context.Context, name, action string, progress func(IndexProgress)) (IndexResult, error) {
	switch action {
	case ActionRebuild, ActionResume:
		return s.RebuildIndex(ctx, name, progress)
	case ActionCatchUp:
		return s.CatchUpIndex(ctx, name, progress)
	case ActionRescore:
		return s.RescoreIndex(ctx, name, progress)
	case ActionReap:
		return s.ReapIndex(ctx, name, progress)
	}
	return IndexResult{}, ErrNothingToDo
}

// maintainIndexes is MaintenanceAuto's runner: it brings each index
// current, one operation at a time, until each needs nothing or fails.
func (s *EventStore) maintainIndexes() {
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
		for _, name := range []string{IndexSocial, IndexZaps} {
			for ctx.Err() == nil {
				st, err := s.IndexStatus(name)
				if err != nil || st.Action == "" {
					break
				}
				s.logger.Info().Str("index", name).Str("action", st.Action).Str("reason", st.Reason).Msg("index maintenance started")
				res, err := s.RunIndexAction(ctx, name, st.Action, nil)
				if err != nil {
					if ctx.Err() == nil {
						s.logger.Error().Err(err).Str("index", name).Str("action", st.Action).Msg("index maintenance failed")
					}
					break
				}
				s.logger.Info().Str("index", name).Str("action", st.Action).Int64("applied", res.Applied).Int64("entries", res.EntriesAfter).Msg("index maintenance finished")
			}
		}
	}()
}
