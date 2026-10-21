package migrations

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// legacyVerificationTTL is how long the pre-v3 worker kept a result.
const legacyVerificationTTL = 14 * 24 * time.Hour

// ScheduleLegacyVerification queues a check for every profile verified
// before per-field check state existed: now when a NIP-05 or LUD-16 score
// is zero (possibly a false negative), else when its old result expires.
type ScheduleLegacyVerification struct {
	MetricsBucket []byte
	DueBucket     []byte
	DueKey        func(at int64, pubkey []byte) []byte
	Now           func() time.Time
}

func (m *ScheduleLegacyVerification) Version() uint64 { return 3 }

func (m *ScheduleLegacyVerification) Description() string {
	return "Schedule re-checks of profiles verified before per-field check state"
}

func (m *ScheduleLegacyVerification) Up(db *bolt.DB) error {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	ts := now().Unix()
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(m.MetricsBucket)
		if b == nil {
			return nil
		}
		due, err := tx.CreateBucketIfNotExists(m.DueBucket)
		if err != nil {
			return err
		}
		type update struct {
			key  []byte
			data []byte
			at   int64
		}
		var updates []update
		err = b.ForEach(func(k, v []byte) error {
			var raw map[string]json.RawMessage
			if json.Unmarshal(v, &raw) != nil {
				return nil
			}
			if _, tracked := raw["nip05"]; tracked {
				return nil
			}
			var legacy struct {
				Nip05Score     int64 `json:"nip05_score"`
				Lud16Score     int64 `json:"lud16_score"`
				LastVerifiedAt int64 `json:"last_verified_at"`
			}
			_ = json.Unmarshal(v, &legacy)
			at := legacy.LastVerifiedAt + int64(legacyVerificationTTL/time.Second)
			if legacy.Nip05Score == 0 || legacy.Lud16Score == 0 || at < ts {
				at = ts
			}
			delete(raw, "last_verified_at")
			raw["requeue_at"], _ = json.Marshal(at)
			data, err := json.Marshal(raw)
			if err != nil {
				return err
			}
			updates = append(updates, update{append([]byte(nil), k...), data, at})
			return nil
		})
		if err != nil {
			return err
		}
		for _, u := range updates {
			if err := b.Put(u.key, u.data); err != nil {
				return err
			}
			if err := due.Put(m.DueKey(u.at, u.key), nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func (m *ScheduleLegacyVerification) Down(*bolt.DB) error { return nil }
