package nip98

import (
	"sync"
	"time"
)

// DefaultSeenMax is SeenIDs' capacity when NewSeenIDs is given zero.
const DefaultSeenMax = 1 << 20

// SeenIDs remembers the NIP-98 event ids a server has accepted, each until
// the moment it would fail the freshness window anyway, so that a captured
// Authorization header can't be used a second time (Options.Seen). It is
// safe for concurrent use.
//
// It is bounded: when it holds max live ids, a new one is refused
// (ErrReplayCacheFull) rather than an old one forgotten, so a flood of
// valid logins fails closed instead of reopening replay. Expired ids are
// swept as it fills.
type SeenIDs struct {
	mu      sync.Mutex
	max     int
	ids     map[string]time.Time // id -> when it may be forgotten
	nextGC  time.Time
	gcEvery time.Duration
}

// NewSeenIDs makes an empty cache holding at most max live ids (zero:
// DefaultSeenMax).
func NewSeenIDs(max int) *SeenIDs {
	if max <= 0 {
		max = DefaultSeenMax
	}
	return &SeenIDs{max: max, ids: make(map[string]time.Time), gcEvery: 10 * time.Second}
}

// Use records id as spent until forgetAt and reports ErrReplayed if it
// was already spent and not yet forgotten at now. The check and the
// record are one step.
func (s *SeenIDs) Use(id string, forgetAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.ids[id]; ok && now.Before(until) {
		return ErrReplayed
	}
	if !now.Before(s.nextGC) || len(s.ids) >= s.max {
		s.sweep(now)
	}
	if _, ok := s.ids[id]; !ok && len(s.ids) >= s.max {
		return ErrReplayCacheFull
	}
	s.ids[id] = forgetAt
	return nil
}

// Len is the number of ids held, expired ones not yet swept included.
func (s *SeenIDs) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ids)
}

func (s *SeenIDs) sweep(now time.Time) {
	for id, until := range s.ids {
		if !now.Before(until) {
			delete(s.ids, id)
		}
	}
	s.nextGC = now.Add(s.gcEvery)
}
