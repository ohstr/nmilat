package relay

import (
	"bytes"
	"encoding/json"

	"github.com/ohstr/nmilat/config"
	bolt "go.etcd.io/bbolt"
)

// Check statuses for a CheckState.
const (
	// CheckOK: the identifier or picture checked out.
	CheckOK = "ok"
	// CheckFailed: the server answered definitively that it doesn't.
	CheckFailed = "failed"
	// CheckInvalid: the value is malformed, so it was never fetched.
	CheckInvalid = "invalid"
	// CheckError: transient failures used up every retry.
	CheckError = "error"
	// CheckPending: a changed value awaits its first result.
	CheckPending = "pending"
)

// CheckState is what the relay knows about one NIP-05, LUD-16 or picture
// check for a profile.
type CheckState struct {
	// Value is the identifier or URL the state belongs to.
	Value  string `json:"value,omitempty"`
	Status string `json:"status,omitempty"`
	// CheckedAt is the last fetch attempt, VerifiedAt the last CheckOK.
	CheckedAt  int64 `json:"checked_at,omitempty"`
	VerifiedAt int64 `json:"verified_at,omitempty"`
	// NextCheckAt is when it's fetched again; 0 means never on its own.
	NextCheckAt int64 `json:"next_check_at,omitempty"`
	// Attempts counts consecutive transient failures.
	Attempts  int    `json:"attempts,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// ProfileMetrics holds the parsed metrics for a profile,
// allowing unified scoring in search and other components.
type ProfileMetrics struct {
	BaseScore    int64 `json:"base_score"`
	Nip05Score   int64 `json:"nip05_score"`
	Lud16Score   int64 `json:"lud16_score"`
	PictureScore int64 `json:"picture_score"`
	// SocialScore is followers and zaps (EventStore.SocialScore), kept
	// current as they change.
	SocialScore int64 `json:"social_score,omitempty"`

	Nip05   CheckState `json:"nip05"`
	Lud16   CheckState `json:"lud16"`
	Picture CheckState `json:"picture"`

	// What the LUD-16 pay endpoint advertised at its last CheckOK.
	Lud16Chains      int    `json:"lud16_chains,omitempty"`
	Lud16AllowsNostr bool   `json:"lud16_allows_nostr,omitempty"`
	Lud16NostrPubkey string `json:"lud16_nostr_pubkey,omitempty"`

	// RequeueAt asks for a check of the latest kind 0 at that time, for a
	// job that couldn't be queued when it arrived.
	RequeueAt int64 `json:"requeue_at,omitempty"`
}

// TotalScore is the profile's search score: base, checks and social.
func (p *ProfileMetrics) TotalScore() int64 {
	return p.BaseScore + p.CheckScore() + p.SocialScore
}

// CheckScore is what the NIP-05, LUD-16 and picture checks add to a
// profile's base score, using the current scoring config.
func (p *ProfileMetrics) CheckScore() int64 {
	nip05, lud16, picture := p.checkScores(config.Get())
	return nip05 + lud16 + picture
}

// checkScores derives each check's score from its status. A field with no
// status yet (stored before checks were tracked) keeps its stored score.
func (p *ProfileMetrics) checkScores(appCfg *config.AppConfig) (nip05, lud16, picture int64) {
	cfg := appCfg.Search.Verification
	nip05, lud16, picture = p.Nip05Score, p.Lud16Score, p.PictureScore
	if p.Nip05.Status != "" || p.Nip05.Value == "" {
		nip05 = 0
		if p.Nip05.Status == CheckOK {
			nip05 = cfg.Nip05Score
		}
	}
	if p.Lud16.Status != "" || p.Lud16.Value == "" {
		lud16 = 0
		if p.Lud16.Status == CheckOK {
			lud16 = int64(max(p.Lud16Chains, 1)) * cfg.Lud16Score
			if cfg.Lud16ChainLimit > 0 && lud16 > cfg.Lud16ChainLimit {
				lud16 = cfg.Lud16ChainLimit
			}
		}
	}
	// The base score already counts a picture URL; a picture that turns
	// out broken takes that bonus back.
	if p.Picture.Status != "" || p.Picture.Value == "" {
		picture = 0
		if p.Picture.Status == CheckFailed || p.Picture.Status == CheckError {
			picture = -appCfg.Search.Scoring.PictureBonus
		}
	}
	return nip05, lud16, picture
}

// NextDue is the earliest time a check is due, 0 if none is.
func (p *ProfileMetrics) NextDue() int64 {
	var due int64
	for _, at := range []int64{p.Nip05.NextCheckAt, p.Lud16.NextCheckAt, p.Picture.NextCheckAt, p.RequeueAt} {
		if at > 0 && (due == 0 || at < due) {
			due = at
		}
	}
	return due
}

// verificationDueKey orders the due queue by time: At(8) + pubkey.
func verificationDueKey(at int64, pubkey []byte) []byte {
	return append(itob(uint64(at)), pubkey...)
}

// GetProfileMetrics returns the persisted metrics or an empty ProfileMetrics struct.
func (s *EventStore) GetProfileMetrics(pubkey string) (*ProfileMetrics, error) {
	var metrics ProfileMetrics
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexProfileMetrics)
		if b == nil {
			return nil
		}
		data := b.Get([]byte(pubkey))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &metrics)
	})
	return &metrics, err
}

// UpdateProfileMetrics performs a thread-safe read-modify-write on the
// metrics, keeping the verification due queue in step with NextDue.
func (s *EventStore) UpdateProfileMetrics(pubkey string, modifier func(*ProfileMetrics)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return updateProfileMetrics(tx, []byte(pubkey), modifier)
	})
}

// UpdateProfileMetricsBatch applies modifier to several profiles in one
// transaction.
func (s *EventStore) UpdateProfileMetricsBatch(pubkeys []string, modifier func(*ProfileMetrics)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, pk := range pubkeys {
			if err := updateProfileMetrics(tx, []byte(pk), modifier); err != nil {
				return err
			}
		}
		return nil
	})
}

func updateProfileMetrics(tx *bolt.Tx, key []byte, modifier func(*ProfileMetrics)) error {
	b, err := tx.CreateBucketIfNotExists(indexProfileMetrics)
	if err != nil {
		return err
	}
	due, err := tx.CreateBucketIfNotExists(indexVerificationDue)
	if err != nil {
		return err
	}

	var metrics ProfileMetrics
	if data := b.Get(key); data != nil {
		if err := json.Unmarshal(data, &metrics); err != nil {
			return err
		}
	}
	before := metrics.NextDue()
	modifier(&metrics)
	after := metrics.NextDue()

	if before != after {
		if before > 0 {
			if err := due.Delete(verificationDueKey(before, key)); err != nil {
				return err
			}
		}
		if after > 0 {
			if err := due.Put(verificationDueKey(after, key), nil); err != nil {
				return err
			}
		}
	}

	newData, err := json.Marshal(metrics)
	if err != nil {
		return err
	}
	return b.Put(key, newData)
}

// DueVerifications returns up to limit pubkeys with a check due at or
// before now, earliest first, skipping any in skip.
func (s *EventStore) DueVerifications(now int64, limit int, skip func(string) bool) ([]string, error) {
	var out []string
	end := itob(uint64(now))
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexVerificationDue)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil && len(out) < limit; k, _ = c.Next() {
			if len(k) <= 8 || bytes.Compare(k[:8], end) > 0 {
				break
			}
			if pk := string(k[8:]); skip == nil || !skip(pk) {
				out = append(out, pk)
			}
		}
		return nil
	})
	return out, err
}
