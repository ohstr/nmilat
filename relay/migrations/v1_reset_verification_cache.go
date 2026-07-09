package migrations

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

type ResetVerificationCacheMigration struct {
	MetricsBucket []byte
}

func (m *ResetVerificationCacheMigration) Version() uint64 {
	return 1
}

func (m *ResetVerificationCacheMigration) Description() string {
	return "Reset verification cache to force re-verification of all profiles with latest logic"
}

func (m *ResetVerificationCacheMigration) Up(tx *bolt.Tx) error {
	b := tx.Bucket(m.MetricsBucket)
	if b == nil {
		return nil
	}

	c := b.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var metrics struct {
			BaseScore      int64 `json:"base_score"`
			Nip05Score     int64 `json:"nip05_score"`
			Lud16Score     int64 `json:"lud16_score"`
			PictureScore   int64 `json:"picture_score"`
			LastVerifiedAt int64 `json:"last_verified_at"`
		}

		if err := json.Unmarshal(v, &metrics); err != nil {
			continue
		}

		// Reset last verified timestamp to force re-verification
		metrics.LastVerifiedAt = 0

		newData, err := json.Marshal(metrics)
		if err != nil {
			return err
		}

		if err := b.Put(k, newData); err != nil {
			return err
		}
	}

	return nil
}

func (m *ResetVerificationCacheMigration) Down(tx *bolt.Tx) error {
	return nil
}
