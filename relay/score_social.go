package relay

import (
	"math"

	"github.com/ohstr/nmilat/config"
	bolt "go.etcd.io/bbolt"
)

// SocialScore weighs a profile's followers and received zaps into its
// score. Each sender's sats are capped and scaled by senderFactor, so
// zaps from many throwaway keys or a self-run LNURL server add little.
func (s *EventStore) SocialScore(st *ProfileStats) int64 {
	cfg := config.Get().Search.Social
	followers := math.Min(cfg.FollowersCap, cfg.FollowersWeight*math.Log10(1+float64(st.Followers)))

	var sats, zappers float64
	for sender, amount := range st.RecdBySender {
		f := s.senderFactor(sender, cfg)
		sats += float64(min(amount/1000, cfg.PerSenderCap)) * f
		zappers += f
	}
	zaps := math.Min(cfg.ZapsCap, cfg.ZapsWeight*math.Log10(1+sats)+cfg.ZappersWeight*math.Log10(1+zappers))
	return int64(math.Round(followers + zaps))
}

// senderFactor scales a sender by their own base+check score (not their
// social score, so there's no recursion).
func (s *EventStore) senderFactor(sender string, cfg config.SocialConfig) float64 {
	m, err := s.GetProfileMetrics(sender)
	if err != nil || cfg.TrustedSenderScore <= 0 {
		return cfg.MinSenderFactor
	}
	score := float64(m.BaseScore + m.CheckScore())
	return math.Max(cfg.MinSenderFactor, math.Min(1, score/cfg.TrustedSenderScore))
}

// SetSocialScores stores social scores in one transaction and returns the
// metrics of the profiles whose score changed.
func (s *EventStore) SetSocialScores(scores map[string]int64) (map[string]*ProfileMetrics, error) {
	changed := map[string]*ProfileMetrics{}
	err := s.db.Update(func(tx *bolt.Tx) error {
		for pk, score := range scores {
			err := s.updateProfileMetrics(tx, []byte(pk), func(m *ProfileMetrics) {
				if m.SocialScore != score {
					m.SocialScore = score
					copied := *m
					changed[pk] = &copied
				}
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return changed, err
}

// ComputeSocialScore reads a profile's stats and scores them with the
// current weights.
func (s *EventStore) ComputeSocialScore(pubkey string) (int64, error) {
	st, err := s.GetProfileStats(pubkey)
	if err != nil {
		return 0, err
	}
	return s.SocialScore(st), nil
}
