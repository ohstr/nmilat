package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	bolt "go.etcd.io/bbolt"
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

// Derived index names, as IndexStatus and the index operations take them.
const (
	IndexZaps   = "zaps"
	IndexSocial = "social"
)

var (
	// ErrIndexDisabled is returned when a derived index the call needs
	// isn't enabled on this store (WithEventStoreIndexes).
	ErrIndexDisabled = errors.New("index not enabled on this store")
	// ErrIndexEnabled is returned by ClearIndex on an enabled index: an
	// enabled index is kept current, so it is rebuilt, never emptied.
	ErrIndexEnabled = errors.New("index is enabled; rebuild it instead")
	// ErrIndexBusy is returned while another operation runs on the index.
	ErrIndexBusy = errors.New("another operation is running on this index")
	// ErrUnknownIndex is returned for a name that isn't a derived index.
	ErrUnknownIndex = errors.New("unknown index")
	// ErrNothingToDo is returned by an operation the index doesn't need.
	ErrNothingToDo = errors.New("nothing to do")
)

// indexSchema is the layout version a generation is written in. A
// generation built by an older version is rebuilt.
const indexSchema = 1

// Index states, as stored in a meta bucket's "st" key.
const (
	stNone   byte = iota // never built, or dropped
	stLive               // reflects every stored event
	stFrozen             // was live up to the watermark; catch-up brings it back
	stDirty              // can't be caught up; needs a rebuild
)

// Tombstones are bounded: past either cap the index is rebuilt instead.
var (
	maxTombstones     int64 = 100_000
	maxTombstoneBytes int64 = 64 << 20
)

// Meta keys every derived index keeps besides its generation pointers.
var (
	keyState    = []byte("st")       // state(1) + watermark(8)
	keyManifest = []byte("manifest") // indexManifest JSON
	keyKinds    = []byte("kinds")    // stored events of the index's kinds at its last write
	keyTombN    = []byte("tn")       // tombstones held
	keyTombB    = []byte("tb")       // their bytes
)

func entriesKey(gen []byte) []byte { return append([]byte("n:"), gen...) }

// indexManifest is what an index records about itself beyond its state.
type indexManifest struct {
	Schema  int    `json:"schema"`
	Reason  string `json:"reason,omitempty"`
	BuiltAt int64  `json:"built_at,omitempty"`
	// Build is a rebuild in progress: its generation fills from the stored
	// events up to Mark, and from live writes.
	Build *indexBuild `json:"build,omitempty"`
	// Tomb names the bucket of events deleted while the index was frozen.
	Tomb []byte `json:"tomb,omitempty"`
	// Retired are buckets no longer read, waiting for ReapIndex.
	Retired [][]byte `json:"retired,omitempty"`
}

type indexBuild struct {
	Gen       []byte `json:"gen"`
	Mark      uint64 `json:"mark"`
	Head      uint64 `json:"head"`
	Scanned   int64  `json:"scanned"`
	Indexed   int64  `json:"indexed"`
	StartedAt int64  `json:"started_at"`
}

// derivedIndex is one derived index's layout and switches.
type derivedIndex struct {
	name    string
	meta    []byte // meta bucket: pointers, state, manifest
	def     []byte // active bucket name before any rebuild
	prefix  byte   // first byte of its generation and tombstone buckets
	legacy  [][]byte
	kinds   []int
	enabled bool
	// running is the operation in progress ("" when idle).
	running atomic.Value
	// apply writes (or removes) one event in a generation and returns the
	// change in its entry count and the profiles it touched.
	apply func(s *EventStore, tx *bolt.Tx, gen []byte, ev *nip01.Event, evsid uint64, add bool) (int64, []string, error)
}

func newDerivedIndexes(s *EventStore, ix DerivedIndexes) {
	s.zaps = &derivedIndex{
		name:    IndexZaps,
		meta:    zapMeta,
		def:     indexZaps,
		prefix:  9,
		legacy:  [][]byte{coinsKey},
		kinds:   []int{9735, 9521},
		enabled: ix.Zaps,
		apply:   applyZap,
	}
	s.social = &derivedIndex{
		name:    IndexSocial,
		meta:    socialMeta,
		def:     socialDefault,
		prefix:  17,
		legacy:  [][]byte{socialBuiltAt, coinsKey},
		kinds:   []int{kindContacts, 9735, 9521},
		enabled: ix.Social,
		apply:   applySocialGen,
	}
	for _, d := range []*derivedIndex{s.zaps, s.social} {
		d.running.Store("")
	}
}

func (s *EventStore) index(name string) (*derivedIndex, error) {
	switch name {
	case IndexZaps:
		return s.zaps, nil
	case IndexSocial:
		return s.social, nil
	}
	return nil, ErrUnknownIndex
}

func (d *derivedIndex) matches(kind int) bool {
	for _, k := range d.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// start claims the index for op, or returns ErrIndexBusy.
func (d *derivedIndex) start(op string) error {
	if !d.running.CompareAndSwap("", op) {
		return ErrIndexBusy
	}
	return nil
}

func (d *derivedIndex) finish() { d.running.Store("") }

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

func (d *derivedIndex) state(tx *bolt.Tx) (byte, uint64) {
	v := metaValue(tx, d.meta, keyState)
	if len(v) != 9 {
		return stNone, 0
	}
	return v[0], binary.BigEndian.Uint64(v[1:])
}

func (d *derivedIndex) setState(tx *bolt.Tx, st byte, watermark uint64) error {
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return err
	}
	if err := m.Put(keyState, append([]byte{st}, itob(watermark)...)); err != nil {
		return err
	}
	// Older versions read these markers; they're set only while live, so
	// an older version opening the store rebuilds what it can't trust.
	for _, k := range d.legacy {
		if st == stLive {
			v := []byte{1}
			if string(k) == string(socialBuiltAt) {
				v = itob(uint64(time.Now().Unix()))
			}
			if err := m.Put(k, v); err != nil {
				return err
			}
		} else if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (d *derivedIndex) manifest(tx *bolt.Tx) indexManifest {
	var m indexManifest
	if v := metaValue(tx, d.meta, keyManifest); v != nil {
		_ = json.Unmarshal(v, &m)
	}
	return m
}

func (d *derivedIndex) putManifest(tx *bolt.Tx, man indexManifest) error {
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return err
	}
	v, err := json.Marshal(man)
	if err != nil {
		return err
	}
	return m.Put(keyManifest, v)
}

func (d *derivedIndex) entries(tx *bolt.Tx, gen []byte) int64 {
	if v := metaValue(tx, d.meta, entriesKey(gen)); len(v) == 8 {
		return int64(btoi(v))
	}
	return 0
}

func (d *derivedIndex) addEntries(tx *bolt.Tx, gen []byte, delta int64) error {
	if delta == 0 {
		return nil
	}
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return err
	}
	return addCounter(m, entriesKey(gen), delta)
}

// nextGen allocates a new bucket name with the index's prefix and tag
// ('g' generation, 't' tombstones).
func (d *derivedIndex) nextGen(tx *bolt.Tx, tag byte) ([]byte, error) {
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return nil, err
	}
	var gen uint64
	if v := m.Get(zapGenKey); len(v) == 8 {
		gen = btoi(v)
	}
	gen++
	if err := m.Put(zapGenKey, itob(gen)); err != nil {
		return nil, err
	}
	return append([]byte{d.prefix, tag}, itob(gen)...), nil
}

// kindsStored sums the counters of the index's kinds; ok is false while
// the counters are being backfilled.
func (d *derivedIndex) kindsStored(tx *bolt.Tx) (uint64, bool) {
	c := tx.Bucket(indexCounters)
	if c == nil || c.Get(ctrKindsDone) == nil {
		return 0, false
	}
	var n uint64
	for _, k := range d.kinds {
		if v := c.Get(kindCounterKey(itob(uint64(k)))); len(v) == 8 {
			n += btoi(v)
		}
	}
	return n, true
}

// stampKinds records the stored events of the index's kinds after a write
// this store made, so open can tell when another program changed them.
func (d *derivedIndex) stampKinds(tx *bolt.Tx) error {
	n, ok := d.kindsStored(tx)
	if !ok {
		return nil
	}
	m, err := tx.CreateBucketIfNotExists(d.meta)
	if err != nil {
		return err
	}
	return m.Put(keyKinds, itob(n))
}

// write is the hot path: an event of the index's kinds was stored (add) or
// deleted. An enabled index applies it to its active generation and to a
// rebuild in progress; a disabled one records what it missed.
func (s *EventStore) write(tx *bolt.Tx, d *derivedIndex, ev *nip01.Event, evsid uint64, add bool) error {
	if !d.matches(ev.Kind) {
		return nil
	}
	if !d.enabled {
		// Nothing to keep track of for an index that holds nothing usable.
		if st, _ := d.state(tx); st == stNone || st == stDirty {
			return nil
		}
		if err := d.stampKinds(tx); err != nil {
			return err
		}
		return s.skip(tx, d, ev, evsid, add)
	}
	if err := d.stampKinds(tx); err != nil {
		return err
	}
	return s.applyLive(tx, d, ev, evsid, add, d.active(tx), d.building(tx))
}

// applyLive applies one event to the given generations and queues the
// profiles it touched for a score refresh.
func (s *EventStore) applyLive(tx *bolt.Tx, d *derivedIndex, ev *nip01.Event, evsid uint64, add bool, gens ...[]byte) error {
	var touched []string
	for _, gen := range gens {
		if gen == nil {
			continue
		}
		delta, t, err := d.apply(s, tx, gen, ev, evsid, add)
		if err != nil {
			return err
		}
		if err := d.addEntries(tx, gen, delta); err != nil {
			return err
		}
		touched = t
	}
	return s.markSocialDirty(tx, touched...)
}

// skip records a write a disabled index misses. A live index freezes at
// the last event it reflects; after that only deletes of events it holds
// matter, kept as tombstones for the catch-up.
func (s *EventStore) skip(tx *bolt.Tx, d *derivedIndex, ev *nip01.Event, evsid uint64, add bool) error {
	st, w := d.state(tx)
	switch st {
	case stLive:
		w = evsid - 1
		if !add {
			w = tx.Bucket(indexEvents).Sequence()
		}
		if err := d.setState(tx, stFrozen, w); err != nil {
			return err
		}
	case stFrozen:
	default:
		return nil
	}
	if add || evsid > w {
		return nil
	}
	return s.tombstone(tx, d, ev, evsid)
}

func (s *EventStore) tombstone(tx *bolt.Tx, d *derivedIndex, ev *nip01.Event, evsid uint64) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	m := tx.Bucket(d.meta)
	var n, size int64
	if v := m.Get(keyTombN); len(v) == 8 {
		n = int64(btoi(v))
	}
	if v := m.Get(keyTombB); len(v) == 8 {
		size = int64(btoi(v))
	}
	man := d.manifest(tx)
	if n+1 > maxTombstones || size+int64(len(raw)) > maxTombstoneBytes {
		return s.markDirty(tx, d, "too many deletes while the index was off")
	}
	if man.Tomb == nil {
		if man.Tomb, err = d.nextGen(tx, 't'); err != nil {
			return err
		}
		if err := d.putManifest(tx, man); err != nil {
			return err
		}
	}
	b, err := tx.CreateBucketIfNotExists(man.Tomb)
	if err != nil {
		return err
	}
	if err := b.Put(itob(evsid), raw); err != nil {
		return err
	}
	if err := m.Put(keyTombN, itob(uint64(n+1))); err != nil {
		return err
	}
	return m.Put(keyTombB, itob(uint64(size+int64(len(raw)))))
}

// markDirty gives up on catching the index up: it needs a rebuild. Its
// tombstones are retired, not deleted, so this stays cheap on a hot path.
func (s *EventStore) markDirty(tx *bolt.Tx, d *derivedIndex, reason string) error {
	man := d.manifest(tx)
	man.Reason = reason
	if man.Tomb != nil {
		man.Retired = append(man.Retired, man.Tomb)
		man.Tomb = nil
	}
	if err := d.putManifest(tx, man); err != nil {
		return err
	}
	m := tx.Bucket(d.meta)
	for _, k := range [][]byte{keyTombN, keyTombB} {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return d.setState(tx, stDirty, 0)
}

// prepareIndexes settles each index's state on open, cheaply and in one
// transaction: it adopts an index from before states were recorded, notices
// events another program changed since this store last wrote, retires a
// disabled index's unfinished rebuild, and marks an enabled index on an
// empty store current. Everything heavier is left to the index operations.
// A store whose indexes need none of that is opened without a write.
func (s *EventStore) prepareIndexes() error {
	need := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		need = s.indexesNeedPrepare(tx)
		return nil
	})
	if !need {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		head := tx.Bucket(indexEvents).Sequence()
		empty := true
		if k, _ := tx.Bucket(indexEvents).Cursor().First(); k != nil {
			empty = false
		}
		seq, stamped := s.writtenSeq(tx)
		for _, d := range []*derivedIndex{s.zaps, s.social} {
			if err := s.prepareIndex(tx, d, head, empty, seq, stamped); err != nil {
				return err
			}
		}
		return s.stampSeq(tx, head)
	})
}

func (s *EventStore) indexesNeedPrepare(tx *bolt.Tx) bool {
	head := tx.Bucket(indexEvents).Sequence()
	seq, stamped := s.writtenSeq(tx)
	if !stamped || seq != head {
		return true
	}
	if s.social.enabled && !bytes.Equal(metaValue(tx, socialMeta, socialScoringKey), scoringFingerprint()) {
		return true
	}
	for _, d := range []*derivedIndex{s.zaps, s.social} {
		if metaValue(tx, d.meta, keyState) == nil && s.hasData(tx, d) {
			return true
		}
		st, _ := d.state(tx)
		if d.enabled && st == stNone {
			return true
		}
		if !d.enabled && d.manifest(tx).Build != nil {
			return true
		}
		if st != stNone && st != stDirty && s.kindsChanged(tx, d) {
			return true
		}
	}
	return false
}

func (s *EventStore) kindsChanged(tx *bolt.Tx, d *derivedIndex) bool {
	stamp := metaValue(tx, d.meta, keyKinds)
	n, ok := d.kindsStored(tx)
	return ok && len(stamp) == 8 && btoi(stamp) != n
}

func (s *EventStore) prepareIndex(tx *bolt.Tx, d *derivedIndex, head uint64, empty bool, seq uint64, stamped bool) error {
	if metaValue(tx, d.meta, keyState) == nil {
		// From before states were recorded: whatever it holds is rebuilt.
		if s.hasData(tx, d) {
			if err := s.markDirty(tx, d, "built by an older version"); err != nil {
				return err
			}
		}
	}
	st, _ := d.state(tx)
	if st != stNone && st != stDirty && ((stamped && seq != head) || s.kindsChanged(tx, d)) {
		if err := s.markDirty(tx, d, "events changed by another program since this index was updated"); err != nil {
			return err
		}
	}
	if d == s.social && d.enabled {
		if err := s.checkScoring(tx); err != nil {
			return err
		}
	}
	man := d.manifest(tx)
	if !d.enabled && man.Build != nil {
		if err := s.retireBuild(tx, d); err != nil {
			return err
		}
	}
	st, _ = d.state(tx)
	if d.enabled && st == stNone && empty && man.Build == nil {
		man = d.manifest(tx)
		man.Schema, man.Reason, man.BuiltAt = indexSchema, "", time.Now().Unix()
		if err := d.putManifest(tx, man); err != nil {
			return err
		}
		if err := d.stampKinds(tx); err != nil {
			return err
		}
		return d.setState(tx, stLive, 0)
	}
	return nil
}

// scoringFingerprint identifies the social scoring settings in force.
func scoringFingerprint() []byte {
	raw, _ := json.Marshal(config.Get().Search.Social)
	sum := sha256.Sum256(raw)
	return sum[:]
}

// checkScoring queues a rescore of every profile when the scoring settings
// changed since scores were last computed.
func (s *EventStore) checkScoring(tx *bolt.Tx) error {
	fp := scoringFingerprint()
	m, err := tx.CreateBucketIfNotExists(socialMeta)
	if err != nil {
		return err
	}
	if prev := m.Get(socialScoringKey); prev != nil && !bytes.Equal(prev, fp) && m.Get(socialRescoreKey) == nil {
		if err := m.Put(socialRescoreKey, []byte("the scoring settings changed")); err != nil {
			return err
		}
		if err := m.Delete(socialRescoreAfter); err != nil {
			return err
		}
	}
	return m.Put(socialScoringKey, fp)
}

// retireBuild abandons a rebuild in progress.
func (s *EventStore) retireBuild(tx *bolt.Tx, d *derivedIndex) error {
	man := d.manifest(tx)
	if man.Build == nil {
		return nil
	}
	man.Retired = append(man.Retired, man.Build.Gen)
	man.Build = nil
	if err := d.putManifest(tx, man); err != nil {
		return err
	}
	return tx.Bucket(d.meta).Delete(zapBuildingKey)
}

// hasData reports whether the active generation holds anything.
func (s *EventStore) hasData(tx *bolt.Tx, d *derivedIndex) bool {
	b := tx.Bucket(d.active(tx))
	if b == nil {
		return false
	}
	if k, _ := b.Cursor().First(); k == nil {
		return false
	}
	if d == s.social {
		for _, sub := range [][]byte{subZapsRecd, subZapsSent, subFollowEdges, subFollowers, subFollowing} {
			if b := b.Bucket(sub); b != nil {
				if k, _ := b.Cursor().First(); k != nil {
					return true
				}
			}
		}
		return false
	}
	return true
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
