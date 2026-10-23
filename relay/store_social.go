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
)

// The social index holds, per profile, the zap receipts it received and
// sent and its follow edges from kind 3 contact lists. Like the zap index
// it lives in a generation bucket named by socialMeta's "active" key, so
// RebuildIndex swaps a new one in without an empty window.
//
// Inside a generation:
//
//	zr: receiver(32) + created_at(8) + evsid(8) -> zapEntry (Other = sender)
//	zs: sender(32)   + created_at(8) + evsid(8) -> zapEntry (Other = receiver)
//	fe: followed(32) + follower(32)             -> evsid of the list (8)
//	fc: followed(32) -> followers (8)
//	fg: author(32)   -> following (8)
//	fo: author(32)   -> evsid of the list fg counts (8)
var (
	socialMeta    = []byte{17, 'm'}
	socialDefault = []byte{17}
	socialBuiltAt = []byte("built")

	// socialRescoreKey holds why every social score is to be recomputed.
	socialRescoreKey = []byte("rescore")
	// socialRescoreAfter is the last profile a rescore stored.
	socialRescoreAfter = []byte("rescore-after")
	// socialDirtyKey is the queue of profiles whose score is stale.
	socialDirtyKey = []byte("dirty")
	// socialScoringKey fingerprints the scoring settings scores were
	// computed with.
	socialScoringKey = []byte("scoring")

	subZapsRecd    = []byte("zr")
	subZapsSent    = []byte("zs")
	subFollowEdges = []byte("fe")
	subFollowers   = []byte("fc")
	subFollowing   = []byte("fg")
	subFollowOwner = []byte("fo")
)

const kindContacts = 3

func activeSocialBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(socialMeta); m != nil {
		if v := m.Get(zapActiveKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return socialDefault
}

// applySocialGen adds (or removes) one event in a social generation.
func applySocialGen(_ *EventStore, tx *bolt.Tx, name []byte, ev *nip01.Event, evsid uint64, add bool) (int64, []string, error) {
	gen, err := tx.CreateBucketIfNotExists(name)
	if err != nil {
		return 0, nil, err
	}
	return applySocialTo(gen, ev, evsid, add)
}

// applySocialTo adds (or removes) one event in a generation bucket. It
// returns the change in followed profiles and the profiles whose stats
// changed.
func applySocialTo(gen *bolt.Bucket, ev *nip01.Event, evsid uint64, add bool) (int64, []string, error) {
	if ev.Kind == kindContacts {
		return applyFollows(gen, ev, evsid, add)
	}
	f, err := parseZapFact(ev)
	if err != nil {
		return 0, nil, nil // nothing to credit
	}
	recd, err := gen.CreateBucketIfNotExists(subZapsRecd)
	if err != nil {
		return 0, nil, err
	}
	sent, err := gen.CreateBucketIfNotExists(subZapsSent)
	if err != nil {
		return 0, nil, err
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
				return 0, nil, err
			}
			continue
		}
		e := entry
		e.Other = k.other
		if err := k.b.Put(key, e.encode()); err != nil {
			return 0, nil, err
		}
	}
	return 0, touched, nil
}

func socialZapKey(party string, createdAt uint64, evsid uint64) []byte {
	pk, err := hex.DecodeString(party)
	if err != nil || len(pk) != 32 {
		return nil
	}
	return append(append(pk, itob(createdAt)...), itob(evsid)...)
}

// applyFollows records (or removes) the follow edges of a contact list.
// Each edge, and the author's following count (subFollowOwner), names the
// list that set it, and only that list removes it: a newer list that
// already replaced it keeps the edges both share, whatever order the two
// are applied in. An edge from before owners were recorded matches any.
func applyFollows(gen *bolt.Bucket, ev *nip01.Event, evsid uint64, add bool) (int64, []string, error) {
	author, err := hex.DecodeString(ev.PubKey)
	if err != nil || len(author) != 32 {
		return 0, nil, nil
	}
	edges, err := gen.CreateBucketIfNotExists(subFollowEdges)
	if err != nil {
		return 0, nil, err
	}
	counts, err := gen.CreateBucketIfNotExists(subFollowers)
	if err != nil {
		return 0, nil, err
	}
	following, err := gen.CreateBucketIfNotExists(subFollowing)
	if err != nil {
		return 0, nil, err
	}
	owners, err := gen.CreateBucketIfNotExists(subFollowOwner)
	if err != nil {
		return 0, nil, err
	}

	owner := itob(evsid)
	targets := followedPubkeys(ev)
	touched := []string{ev.PubKey}
	var delta int64
	for _, t := range targets {
		target, _ := hex.DecodeString(t)
		key := append(append([]byte(nil), target...), author...)
		cur := edges.Get(key)
		switch {
		case add && cur == nil:
			if err := edges.Put(key, owner); err != nil {
				return 0, nil, err
			}
			d, err := addFollowers(counts, target, 1)
			if err != nil {
				return 0, nil, err
			}
			delta += d
		case add:
			if !bytes.Equal(cur, owner) {
				if err := edges.Put(key, owner); err != nil {
					return 0, nil, err
				}
			}
			continue
		case cur != nil && ownedBy(cur, owner):
			if err := edges.Delete(key); err != nil {
				return 0, nil, err
			}
			d, err := addFollowers(counts, target, -1)
			if err != nil {
				return 0, nil, err
			}
			delta += d
		default:
			continue
		}
		touched = append(touched, t)
	}
	if add {
		if err := owners.Put(author, owner); err != nil {
			return 0, nil, err
		}
		return delta, touched, following.Put(author, itob(uint64(len(targets))))
	}
	if cur := owners.Get(author); cur == nil || bytes.Equal(cur, owner) {
		if err := owners.Delete(author); err != nil {
			return 0, nil, err
		}
		if err := following.Delete(author); err != nil {
			return 0, nil, err
		}
	}
	return delta, touched, nil
}

// ownedBy reports whether an edge value names owner; a value from before
// owners were recorded names any.
func ownedBy(v, owner []byte) bool { return len(v) != 8 || bytes.Equal(v, owner) }

// addFollowers moves a profile's follower count and returns the change in
// profiles with followers.
func addFollowers(b *bolt.Bucket, key []byte, delta int64) (int64, error) {
	var n int64
	if v := b.Get(key); len(v) == 8 {
		n = int64(btoi(v))
	}
	if err := addCount(b, key, delta); err != nil {
		return 0, err
	}
	switch before, after := n > 0, n+delta > 0; {
	case after && !before:
		return 1, nil
	case before && !after:
		return -1, nil
	}
	return 0, nil
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

// markSocialDirty queues profiles for a social score refresh. The queue
// is kept in the store, so a restart loses none.
func (s *EventStore) markSocialDirty(tx *bolt.Tx, pubkeys ...string) error {
	if len(pubkeys) == 0 {
		return nil
	}
	m, err := tx.CreateBucketIfNotExists(socialMeta)
	if err != nil {
		return err
	}
	b, err := m.CreateBucketIfNotExists(socialDirtyKey)
	if err != nil {
		return err
	}
	for _, pk := range pubkeys {
		if err := b.Put([]byte(pk), []byte{1}); err != nil {
			return err
		}
	}
	return nil
}

// TakeSocialDirty returns, and removes from the queue, up to limit profiles
// whose social stats changed.
func (s *EventStore) TakeSocialDirty(limit int) []string {
	var out []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		out = nil
		m := tx.Bucket(socialMeta)
		if m == nil {
			return nil
		}
		b := m.Bucket(socialDirtyKey)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil && len(out) < limit; k, _ = c.Next() {
			out = append(out, string(k))
		}
		for _, pk := range out {
			if err := b.Delete([]byte(pk)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to read the social score queue")
		return nil
	}
	return out
}

// ProfileStats summarizes a profile's zaps and follows. Only zaps that
// count are included (see zapCounts). Counts and zappers cover every coin;
// ZapAmtRecd/ZapAmtSent are sats and AmtRecd/AmtSent hold each coin's
// amount, all in milli-units.
type ProfileStats struct {
	Pubkey string `json:"pubkey"`

	ZapCntRecd  int    `json:"zap_cnt_recd"`
	ZapAmtRecd  uint64 `json:"zap_amt_recd"`
	ZappersRecd int    `json:"zappers_recd"`
	ZapCntSent  int    `json:"zap_cnt_sent"`
	ZapAmtSent  uint64 `json:"zap_amt_sent"`

	AmtRecd [numCoins]uint64 `json:"-"`
	AmtSent [numCoins]uint64 `json:"-"`

	// Unix times; 0 when there is none.
	ZapFirstRecd int64 `json:"zap_first_recd"`
	ZapLastRecd  int64 `json:"zap_last_recd"`
	ZapFirstSent int64 `json:"zap_first_sent"`
	ZapLastSent  int64 `json:"zap_last_sent"`

	Followers int64 `json:"followers"`
	Following int64 `json:"following"`

	// RecdBySender is the counted sats received from each sender.
	RecdBySender map[string]uint64 `json:"-"`
}

// MarshalJSON adds zap_amt_recd_<coin>/zap_amt_sent_<coin> for each coin
// besides sats with an amount, as the NIP-85 tags name them.
func (st ProfileStats) MarshalJSON() ([]byte, error) {
	type plain ProfileStats
	b, err := json.Marshal(plain(st))
	if err != nil {
		return nil, err
	}
	extra := map[string]uint64{}
	for _, c := range Coins() {
		if c == CoinSats {
			continue
		}
		if st.AmtRecd[c] > 0 {
			extra["zap_amt_recd_"+c.String()] = st.AmtRecd[c]
		}
		if st.AmtSent[c] > 0 {
			extra["zap_amt_sent_"+c.String()] = st.AmtSent[c]
		}
	}
	if len(extra) == 0 {
		return b, nil
	}
	e, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	return append(append(b[:len(b)-1], ','), e[1:]...), nil
}

// GetProfileStats computes a profile's stats from the social index.
func (s *EventStore) GetProfileStats(pubkey string) (*ProfileStats, error) {
	pk, err := hex.DecodeString(pubkey)
	if err != nil || len(pk) != 32 {
		return nil, errors.New("invalid pubkey")
	}
	if !s.social.enabled {
		return nil, ErrIndexDisabled
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
		zappers := map[string]bool{}
		eachZap(gen.Bucket(subZapsRecd), pk, func(at int64, e zapEntry) {
			if !zapCounts(e, e.Other, pubkey, keys.get(pubkey), seen) {
				return
			}
			st.ZapCntRecd++
			st.AmtRecd[e.Coin] += e.Amount
			zappers[e.Other] = true
			if e.Coin == CoinSats {
				st.RecdBySender[e.Other] += e.Amount
			}
			st.ZapFirstRecd = minNonZero(st.ZapFirstRecd, at)
			st.ZapLastRecd = max(st.ZapLastRecd, at)
		})
		st.ZappersRecd = len(zappers)
		st.ZapAmtRecd = st.AmtRecd[CoinSats]

		seen = map[string]bool{}
		eachZap(gen.Bucket(subZapsSent), pk, func(at int64, e zapEntry) {
			if !zapCounts(e, pubkey, e.Other, keys.get(e.Other), seen) {
				return
			}
			st.ZapCntSent++
			st.AmtSent[e.Coin] += e.Amount
			st.ZapFirstSent = minNonZero(st.ZapFirstSent, at)
			st.ZapLastSent = max(st.ZapLastSent, at)
		})
		st.ZapAmtSent = st.AmtSent[CoinSats]
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

// rescorePending returns why every profile's social score is to be
// recomputed, or "" when it isn't.
func (s *EventStore) rescorePending(tx *bolt.Tx, d *derivedIndex) string {
	if d != s.social || !d.enabled {
		return ""
	}
	v := metaValue(tx, socialMeta, socialRescoreKey)
	if v == nil {
		return ""
	}
	if len(v) == 1 {
		return "after a rebuild"
	}
	return string(v)
}

// rescoreBatch is how many profiles one rescore step scores.
var rescoreBatch = 500

// RescoreIndex recomputes every profile's social score (each kind 0
// author), after a social rebuild or a change to the scoring settings. It
// stores its position, so a restart resumes it.
func (s *EventStore) RescoreIndex(ctx context.Context, name string, progress func(IndexProgress)) (IndexResult, error) {
	d, err := s.index(name)
	if err != nil {
		return IndexResult{}, err
	}
	if d != s.social {
		return IndexResult{}, ErrNothingToDo
	}
	if !d.enabled {
		return IndexResult{}, ErrIndexDisabled
	}
	if err := d.start(ActionRescore); err != nil {
		return IndexResult{}, err
	}
	defer d.finish()
	var res IndexResult
	pending := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		pending = s.rescorePending(tx, d) != ""
		return nil
	})
	if !pending {
		return res, ErrNothingToDo
	}
	total := int64(s.Counts().Kind(0))
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var batch []string
		var last []byte
		done := false
		_ = s.db.View(func(tx *bolt.Tx) error {
			batch, last, done = profilesAfter(tx, metaValue(tx, socialMeta, socialRescoreAfter), rescoreBatch)
			return nil
		})
		scores := make(map[string]int64, len(batch))
		for _, pk := range batch {
			if score, err := s.ComputeSocialScore(pk); err == nil {
				scores[pk] = score
			}
		}
		start := time.Now()
		var changed int64
		err := s.db.Update(func(tx *bolt.Tx) error {
			changed = 0
			for pk, score := range scores {
				err := s.updateProfileMetrics(tx, []byte(pk), func(m *ProfileMetrics) {
					if m.SocialScore != score {
						m.SocialScore = score
						changed++
					}
				})
				if err != nil {
					return err
				}
			}
			m, err := tx.CreateBucketIfNotExists(socialMeta)
			if err != nil {
				return err
			}
			if done {
				if err := m.Delete(socialRescoreKey); err != nil {
					return err
				}
				return m.Delete(socialRescoreAfter)
			}
			return m.Put(socialRescoreAfter, last)
		})
		s.observer().IndexBatchCommitted(d.name, time.Since(start))
		if err != nil {
			return res, err
		}
		res.Scanned += int64(len(batch))
		res.Applied += changed
		if progress != nil {
			progress(IndexProgress{Phase: "rescore", Done: res.Scanned, Total: max(total, res.Scanned), Applied: res.Applied})
		}
		if done {
			return res, nil
		}
		if err := s.yield(ctx); err != nil {
			return res, err
		}
	}
}

// profilesAfter lists up to limit kind 0 authors after the one given, in
// key order; done is true when the walk reached the end.
func profilesAfter(tx *bolt.Tx, after []byte, limit int) (out []string, last []byte, done bool) {
	b := tx.Bucket(indexKindPubkey)
	if b == nil {
		return nil, nil, true
	}
	kind0 := make([]byte, 8)
	seek := kind0
	if after != nil {
		seek = append(append(append([]byte(nil), kind0...), after...), bytes.Repeat([]byte{0xFF}, 16)...)
	}
	c := b.Cursor()
	k, _ := c.Seek(seek)
	for ; k != nil && bytes.HasPrefix(k, kind0) && len(out) < limit; k, _ = c.Next() {
		if len(k) != profileKeyLen || bytes.Equal(k[8:40], last) {
			continue
		}
		last = append(last[:0], k[8:40]...)
		out = append(out, hex.EncodeToString(last))
	}
	return out, last, k == nil || !bytes.HasPrefix(k, kind0)
}
