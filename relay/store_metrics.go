package relay

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// ProfileMetrics holds the parsed metrics for a profile,
// allowing unified scoring in search and other components.
type ProfileMetrics struct {
	BaseScore      int64 `json:"base_score"`
	Nip05Score     int64 `json:"nip05_score"`
	Lud16Score     int64 `json:"lud16_score"`
	PictureScore   int64 `json:"picture_score"`
	LastVerifiedAt int64 `json:"last_verified_at"`
}

// TotalScore strictly evaluates the sum of all metrics
// to provide a single score metric.
func (p *ProfileMetrics) TotalScore() int64 {
	return p.BaseScore + p.Nip05Score + p.Lud16Score + p.PictureScore
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

// UpdateProfileMetrics performs a thread-safe read-modify-write on the metrics.
func (s *EventStore) UpdateProfileMetrics(pubkey string, modifier func(*ProfileMetrics)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(indexProfileMetrics)
		if err != nil {
			return err
		}

		var metrics ProfileMetrics
		key := []byte(pubkey)
		data := b.Get(key)

		if data != nil {
			if err := json.Unmarshal(data, &metrics); err != nil {
				return err
			}
		}

		// Apply modifications
		modifier(&metrics)

		// Save updated metrics
		newData, err := json.Marshal(metrics)
		if err != nil {
			return err
		}

		return b.Put(key, newData)
	})
}
