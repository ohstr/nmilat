package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"
)

// The social index holds, per profile, the zap receipts it received and
// sent and its follow edges from kind 3 contact lists. Like the zap index
// it lives in a generation bucket named by socialMeta's "active" key, so
// RebuildSocialIndex swaps a new one in without an empty window.
//
// Inside a generation:
//
//	zr: receiver(32) + created_at(8) + evsid(8) -> zapEntry (Other = sender)
//	zs: sender(32)   + created_at(8) + evsid(8) -> zapEntry (Other = receiver)
//	fe: followed(32) + follower(32)             -> nil
//	fc: followed(32) -> followers (8)
//	fg: author(32)   -> following (8)
var (
	socialMeta    = []byte{17, 'm'}
	socialDefault = []byte{17}
	socialBuiltAt = []byte("built")

	subZapsRecd    = []byte("zr")
	subZapsSent    = []byte("zs")
	subFollowEdges = []byte("fe")
	subFollowers   = []byte("fc")
	subFollowing   = []byte("fg")
)

// ErrSocialRebuildInProgress is returned by RebuildSocialIndex while
// another rebuild is running.
var ErrSocialRebuildInProgress = errors.New("social index rebuild already in progress")

const kindContacts = 3

func isSocialKind(kind int) bool { return kind == kindContacts || isZapKind(kind) }

func activeSocialBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(socialMeta); m != nil {
		if v := m.Get(zapActiveKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return socialDefault
}

func buildingSocialBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(socialMeta); m != nil {
		if v := m.Get(zapBuildingKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return nil
}

// indexSocial adds an event to the social index (and to a rebuild in
// progress), marking the profiles it touches for a score refresh.
func (s *EventStore) indexSocial(tx *bolt.Tx, ev *nip01.Event, evsid uint64) error {
	return s.applySocial(tx, ev, evsid, true)
}

// unindexSocial removes what indexSocial added for a deleted event.
func (s *EventStore) unindexSocial(tx *bolt.Tx, ev *nip01.Event, evsid uint64) error {
	return s.applySocial(tx, ev, evsid, false)
}

func (s *EventStore) applySocial(tx *bolt.Tx, ev *nip01.Event, evsid uint64, add bool) error {
	if !isSocialKind(ev.Kind) {
		return nil
	}
	for _, name := range [][]byte{activeSocialBucket(tx), buildingSocialBucket(tx)} {
		if name == nil {
			continue
		}
		gen, err := tx.CreateBucketIfNotExists(name)
		if err != nil {
			return err
		}
		touched, err := applySocialTo(gen, ev, evsid, add)
		if err != nil {
			return err
		}
		s.markSocialDirty(touched...)
	}
	return nil
}

// applySocialTo adds (or removes) one event in a generation bucket and
// returns the profiles whose stats changed.
func applySocialTo(gen *bolt.Bucket, ev *nip01.Event, evsid uint64, add bool) ([]string, error) {
	if ev.Kind == kindContacts {
		return applyFollows(gen, ev, add)
	}
	f, err := parseZapFact(ev)
	if err != nil {
		return nil, nil // nothing to credit
	}
	recd, err := gen.CreateBucketIfNotExists(subZapsRecd)
	if err != nil {
		return nil, err
	}
	sent, err := gen.CreateBucketIfNotExists(subZapsSent)
	if err != nil {
		return nil, err
	}
	entry := zapEntry{Amount: f.Amount, Signer: f.Signer, PaymentHash: f.PaymentHash, Valid: f.Valid, Coin: f.Coin}
	touched := []string{f.Receiver}
	keys := []struct {
		b     *bolt.Bucket
		party string
		other string
	}{{recd, f.Receiver, f.Sender}}
	if f.Sender != "" {
		keys = append(keys, struct {
			b     *bolt.Bucket
			party string
			other string
		}{sent, f.Sender, f.Receiver})
		touched = append(touched, f.Sender)
	}
	for _, k := range keys {
		key := socialZapKey(k.party, ev.CreatedAt, evsid)
		if key == nil {
			continue
		}
		if !add {
			if err := k.b.Delete(key); err != nil {
				return nil, err
			}
			continue
		}
		e := entry
		e.Other = k.other
		if err := k.b.Put(key, e.encode()); err != nil {
			return nil, err
		}
	}
	return touched, nil
}

func socialZapKey(party string, createdAt uint64, evsid uint64) []byte {
	pk, err := hex.DecodeString(party)
	if err != nil || len(pk) != 32 {
		return nil
	}
	return append(append(pk, itob(createdAt)...), itob(evsid)...)
}

// applyFollows records (or removes) the follow edges of a contact list.
func applyFollows(gen *bolt.Bucket, ev *nip01.Event, add bool) ([]string, error) {
	author, err := hex.DecodeString(ev.PubKey)
	if err != nil || len(author) != 32 {
		return nil, nil
	}
	edges, err := gen.CreateBucketIfNotExists(subFollowEdges)
	if err != nil {
		return nil, err
	}
	counts, err := gen.CreateBucketIfNotExists(subFollowers)
	if err != nil {
		return nil, err
	}
	following, err := gen.CreateBucketIfNotExists(subFollowing)
	if err != nil {
		return nil, err
	}

	targets := followedPubkeys(ev)
	touched := []string{ev.PubKey}
	for _, t := range targets {
		target, _ := hex.DecodeString(t)
		key := append(append([]byte(nil), target...), author...)
		exists := edges.Get(key) != nil
		switch {
		case add && !exists:
			if err := edges.Put(key, nil); err != nil {
				return nil, err
			}
			if err := addCount(counts, target, 1); err != nil {
				return nil, err
			}
		case !add && exists:
			if err := edges.Delete(key); err != nil {
				return nil, err
			}
			if err := addCount(counts, target, -1); err != nil {
				return nil, err
			}
		default:
			continue
		}
		touched = append(touched, t)
	}
	if add {
		return touched, following.Put(author, itob(uint64(len(targets))))
	}
	return touched, following.Delete(author)
}

// followedPubkeys is a contact list's distinct, valid "p" pubkeys, not
// counting the author.
func followedPubkeys(ev *nip01.Event) []string {
	seen := map[string]bool{}
	var out []string
	for _, tag := range ev.Tags {
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		pk := strings.ToLower(tag[1])
		if seen[pk] || pk == ev.PubKey || utils.Validate32Key(pk) != nil {
			continue
		}
		seen[pk] = true
		out = append(out, pk)
	}
	return out
}

func addCount(b *bolt.Bucket, key []byte, delta int64) error {
	var n int64
	if v := b.Get(key); len(v) == 8 {
		n = int64(btoi(v))
	}
	n += delta
	if n <= 0 {
		return b.Delete(key)
	}
	return b.Put(key, itob(uint64(n)))
}

// markSocialDirty queues profiles for a social score refresh.
func (s *EventStore) markSocialDirty(pubkeys ...string) {
	if len(pubkeys) == 0 {
		return
	}
	s.socialMu.Lock()
	defer s.socialMu.Unlock()
	if s.socialDirty == nil {
		s.socialDirty = map[string]bool{}
	}
	for _, pk := range pubkeys {
		if len(s.socialDirty) >= maxSocialDirty {
			return
		}
		s.socialDirty[pk] = true
	}
}

// maxSocialDirty bounds the pending score refreshes; a rebuild rescores
// anything dropped.
const maxSocialDirty = 200_000

// TakeSocialDirty returns up to limit profiles whose social stats changed
// since the last call.
func (s *EventStore) TakeSocialDirty(limit int) []string {
	s.socialMu.Lock()
	defer s.socialMu.Unlock()
	var out []string
	for pk := range s.socialDirty {
		if len(out) >= limit {
			break
		}
		out = append(out, pk)
		delete(s.socialDirty, pk)
	}
	return out
}

// ProfileStats summarizes a profile's zaps and follows. Only zaps that
// count are included (see zapCounts). Amounts are in milli-units.
type ProfileStats struct {
	Pubkey string `json:"pubkey"`

	ZapCntRecd  int    `json:"zap_cnt_recd"`
	ZapAmtRecd  uint64 `json:"zap_amt_recd"`
	ZappersRecd int    `json:"zappers_recd"`
	ZapCntSent  int    `json:"zap_cnt_sent"`
	ZapAmtSent  uint64 `json:"zap_amt_sent"`

	// Unix times; 0 when there is none.
	ZapFirstRecd int64 `json:"zap_first_recd"`
	ZapLastRecd  int64 `json:"zap_last_recd"`
	ZapFirstSent int64 `json:"zap_first_sent"`
	ZapLastSent  int64 `json:"zap_last_sent"`

	Followers int64 `json:"followers"`
	Following int64 `json:"following"`

	// RecdBySender is the counted amount received from each sender.
	RecdBySender map[string]uint64 `json:"-"`
}

// GetProfileStats computes a profile's stats from the social index.
func (s *EventStore) GetProfileStats(pubkey string) (*ProfileStats, error) {
	pk, err := hex.DecodeString(pubkey)
	if err != nil || len(pk) != 32 {
		return nil, errors.New("invalid pubkey")
	}
	st := &ProfileStats{Pubkey: pubkey, RecdBySender: map[string]uint64{}}
	err = s.db.View(func(tx *bolt.Tx) error {
		gen := tx.Bucket(activeSocialBucket(tx))
		if gen == nil {
			return nil
		}
		keys := lnurlKeys{tx: tx, cache: map[string]string{}}

		if b := gen.Bucket(subFollowers); b != nil {
			if v := b.Get(pk); len(v) == 8 {
				st.Followers = int64(btoi(v))
			}
		}
		if b := gen.Bucket(subFollowing); b != nil {
			if v := b.Get(pk); len(v) == 8 {
				st.Following = int64(btoi(v))
			}
		}

		seen := map[string]bool{}
		eachZap(gen.Bucket(subZapsRecd), pk, func(at int64, e zapEntry) {
			if !zapCounts(e, e.Other, pubkey, keys.get(pubkey), seen) {
				return
			}
			st.ZapCntRecd++
			st.ZapAmtRecd += e.Amount
			st.RecdBySender[e.Other] += e.Amount
			st.ZapFirstRecd = minNonZero(st.ZapFirstRecd, at)
			st.ZapLastRecd = max(st.ZapLastRecd, at)
		})
		st.ZappersRecd = len(st.RecdBySender)

		seen = map[string]bool{}
		eachZap(gen.Bucket(subZapsSent), pk, func(at int64, e zapEntry) {
			if !zapCounts(e, pubkey, e.Other, keys.get(e.Other), seen) {
				return
			}
			st.ZapCntSent++
			st.ZapAmtSent += e.Amount
			st.ZapFirstSent = minNonZero(st.ZapFirstSent, at)
			st.ZapLastSent = max(st.ZapLastSent, at)
		})
		return nil
	})
	return st, err
}

// zapCounts applies the counting rules to one stored zap: the receipt
// validated, it isn't a self-zap, it isn't a second receipt for the same
// payment, and, once the recipient's LNURL server key is known (a verified
// lud16/lud06 with nostrPubkey), that server signed it.
func zapCounts(e zapEntry, sender, receiver, receiverKey string, seen map[string]bool) bool {
	if !e.Valid || (sender != "" && sender == receiver) {
		return false
	}
	if receiverKey != "" && e.Signer != receiverKey {
		return false
	}
	if e.PaymentHash != "" {
		if seen[e.PaymentHash] {
			return false
		}
		seen[e.PaymentHash] = true
	}
	return true
}

func eachZap(b *bolt.Bucket, party []byte, fn func(at int64, e zapEntry)) {
	if b == nil {
		return
	}
	c := b.Cursor()
	for k, v := c.Seek(party); k != nil && bytes.HasPrefix(k, party); k, v = c.Next() {
		if len(k) != 48 {
			continue
		}
		if e, ok := decodeZapEntry(v); ok {
			fn(int64(binary.BigEndian.Uint64(k[32:40])), e)
		}
	}
}

func minNonZero(a, b int64) int64 {
	if a == 0 || b < a {
		return b
	}
	return a
}

// lnurlKeys reads profiles' verified LNURL server pubkeys within one
// transaction.
type lnurlKeys struct {
	tx    *bolt.Tx
	cache map[string]string
}

func (k lnurlKeys) get(pubkey string) string {
	if v, ok := k.cache[pubkey]; ok {
		return v
	}
	var key string
	if b := k.tx.Bucket(indexProfileMetrics); b != nil {
		if data := b.Get([]byte(pubkey)); data != nil {
			var m ProfileMetrics
			if json.Unmarshal(data, &m) == nil && m.Lud16NostrPubkey != "" && (m.Lud16.Status == CheckOK || m.Lud16.Status == CheckError) {
				key = strings.ToLower(m.Lud16NostrPubkey)
			}
		}
	}
	k.cache[pubkey] = key
	return key
}

// SocialIndexBuilt reports whether the social index has been backfilled
// from the stored events at least once.
func (s *EventStore) SocialIndexBuilt() bool {
	built := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		if m := tx.Bucket(socialMeta); m != nil {
			built = m.Get(socialBuiltAt) != nil
		}
		return nil
	})
	return built
}

// CountSocialProfiles returns how many profiles have zaps or followers in
// the social index (approximate: it counts index keys, not distinct
// profiles across both).
func (s *EventStore) CountSocialProfiles() int64 {
	var n int
	_ = s.db.View(func(tx *bolt.Tx) error {
		gen := tx.Bucket(activeSocialBucket(tx))
		if gen == nil {
			return nil
		}
		if b := gen.Bucket(subFollowers); b != nil {
			n = b.Stats().KeyN
		}
		return nil
	})
	return int64(n)
}

// ClearSocialIndex empties the active social index without touching the
// stored events.
func (s *EventStore) ClearSocialIndex(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		name := activeSocialBucket(tx)
		if err := tx.DeleteBucket(name); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(name)
		return err
	})
}

// RebuildSocialIndex rebuilds the social index from every stored event
// into a new generation and swaps it in once complete. Events stored
// meanwhile land in both. progress, if set, gets events scanned and
// indexed after each batch; cancelling ctx discards the new generation.
func (s *EventStore) RebuildSocialIndex(ctx context.Context, progress func(scanned, indexed int)) (int, error) {
	if !s.socialRebuilding.CompareAndSwap(false, true) {
		return 0, ErrSocialRebuildInProgress
	}
	defer s.socialRebuilding.Store(false)

	var next []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		m, err := tx.CreateBucketIfNotExists(socialMeta)
		if err != nil {
			return err
		}
		if stale := m.Get(zapBuildingKey); stale != nil {
			if err := tx.DeleteBucket(stale); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
				return err
			}
		}
		var gen uint64
		if v := m.Get(zapGenKey); len(v) == 8 {
			gen = btoi(v)
		}
		gen++
		next = append([]byte{17, 'g'}, itob(gen)...)
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

	_, indexed, err := s.scanEventsInto(ctx, isSocialKind, func(tx *bolt.Tx, ev *nip01.Event, evsid uint64) error {
		gen, err := tx.CreateBucketIfNotExists(next)
		if err != nil {
			return err
		}
		_, err = applySocialTo(gen, ev, evsid, true)
		return err
	}, progress)
	if err != nil {
		if dropErr := s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.DeleteBucket(next); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
				return err
			}
			return tx.Bucket(socialMeta).Delete(zapBuildingKey)
		}); dropErr != nil {
			s.logger.Warn().Err(dropErr).Msg("failed to discard an unfinished social index rebuild")
		}
		return indexed, err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		old := activeSocialBucket(tx)
		m := tx.Bucket(socialMeta)
		if err := m.Put(zapActiveKey, next); err != nil {
			return err
		}
		if err := m.Delete(zapBuildingKey); err != nil {
			return err
		}
		if err := m.Put(socialBuiltAt, itob(uint64(time.Now().Unix()))); err != nil {
			return err
		}
		if err := m.Put(coinsKey, []byte{1}); err != nil {
			return err
		}
		if err := tx.DeleteBucket(old); err != nil && !errors.Is(err, bolterrors.ErrBucketNotFound) {
			return err
		}
		return nil
	})
	return indexed, err
}

// SocialIndexRebuilding reports whether RebuildSocialIndex is running.
func (s *EventStore) SocialIndexRebuilding() bool { return s.socialRebuilding.Load() }

// backfillIndexes rebuilds, once and in the background, the social index
// when it was never built and either index when its entries predate coins.
// An empty store just records both as current.
func (s *EventStore) backfillIndexes() {
	var social, zaps bool
	_ = s.db.Update(func(tx *bolt.Tx) error {
		sm, zm := tx.Bucket(socialMeta), tx.Bucket(zapMeta)
		social = sm == nil || sm.Get(socialBuiltAt) == nil || sm.Get(coinsKey) == nil
		zaps = zm == nil || zm.Get(coinsKey) == nil
		if !social && !zaps {
			return nil
		}
		if b := tx.Bucket(indexEvents); b != nil {
			if k, _ := b.Cursor().First(); k != nil {
				return nil
			}
		}
		social, zaps = false, false
		sm, err := tx.CreateBucketIfNotExists(socialMeta)
		if err != nil {
			return err
		}
		zm, err = tx.CreateBucketIfNotExists(zapMeta)
		if err != nil {
			return err
		}
		if err := sm.Put(socialBuiltAt, itob(uint64(time.Now().Unix()))); err != nil {
			return err
		}
		if err := sm.Put(coinsKey, []byte{1}); err != nil {
			return err
		}
		return zm.Put(coinsKey, []byte{1})
	})
	if !social && !zaps {
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
		if social {
			s.logger.Info().Msg("building the social index from stored events")
			n, err := s.RebuildSocialIndex(ctx, nil)
			if !s.logRebuild("social", n, err) {
				return
			}
		}
		if zaps {
			s.logger.Info().Msg("rebuilding the zap index to record each zap's coin")
			n, err := s.RebuildZapIndex(ctx, nil)
			s.logRebuild("zap", n, err)
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
