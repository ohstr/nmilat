package relay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip11"
)

const (
	defaultMaxSubscriptions = 355
	eventBufferCapacity     = 55
)

const (
	liveTailMinGap   = 50 * time.Millisecond
	liveTailFallback = time.Second
)

var (
	ErrSubscriptionClosed = errors.New("subscription closed")
)

type Subscription struct {
	id       string
	query    *StoreQuery
	outgoing chan *PotentialEvent
	errors   chan error
	eose     chan bool
	closeCh  chan interface{}
	closer   sync.Once
	cancelMu sync.Mutex
	cancel   context.CancelFunc
	// Live-tail pacing; fields so a test can isolate the commit wake-up.
	minGap   time.Duration
	fallback time.Duration
}

func NewSubscription(id string, query *StoreQuery) (*Subscription, <-chan *PotentialEvent, <-chan error, <-chan bool) {
	sub := &Subscription{
		id:       id,
		query:    query,
		outgoing: make(chan *PotentialEvent, eventBufferCapacity),
		errors:   make(chan error, 1),
		eose:     make(chan bool),
		closeCh:  make(chan interface{}),
		minGap:   liveTailMinGap,
		fallback: liveTailFallback,
	}
	return sub, sub.outgoing, sub.errors, sub.eose
}

func (sub *Subscription) Start(parent context.Context, wg *sync.WaitGroup) {
	ctx, cancel := context.WithCancel(parent)
	sub.cancelMu.Lock()
	sub.cancel = cancel
	sub.cancelMu.Unlock()
	defer cancel()

	err := sub.query.Fetch(ctx, sub.outgoing, wg, false)
	if err != nil {
		sub.errors <- err
		return
	}

	wg.Wait()
	select {
	case <-sub.closeCh:
		return
	case sub.eose <- true:
	}

	defer wg.Wait()

	// Live tail: run when a write commits, at most once per minGap so a busy
	// ingest can't multiply passes, and at least every fallback in case a
	// write path doesn't signal.
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for {
		changed := sub.query.changed()
		last := time.Now()
		if err := sub.query.Fetch(ctx, sub.outgoing, wg, true); err != nil {
			sub.errors <- err
			return
		}

		timer.Reset(sub.fallback)
		select {
		case <-changed:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-sub.closeCh:
			return
		}

		if gap := sub.minGap - time.Since(last); gap > 0 {
			timer.Reset(gap)
			select {
			case <-timer.C:
			case <-sub.closeCh:
				return
			}
		}
	}
}

func (sub *Subscription) Stop() {
	sub.closer.Do(func() {
		sub.cancelMu.Lock()
		cancel := sub.cancel
		sub.cancelMu.Unlock()
		if cancel != nil {
			cancel()
		}
		close(sub.closeCh)
	})
}

func (sub *Subscription) Closed() <-chan interface{} {
	return sub.closeCh
}

type SubscriptionsMap struct {
	subs            map[string]*Subscription
	mu              sync.Mutex
	maxSubscription int
}

// NewSubscriptions never writes to cfg: every session shares the relay's
// one Limitation, so defaulting it here raced between connections.
func NewSubscriptions(cfg *nip11.Limitation) *SubscriptionsMap {
	maxSubs := cfg.MaxSubscriptions
	if maxSubs == 0 {
		maxSubs = defaultMaxSubscriptions
	}
	return &SubscriptionsMap{
		subs:            make(map[string]*Subscription),
		maxSubscription: maxSubs,
	}
}

func (s *SubscriptionsMap) Add(sub *Subscription) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.subs) >= s.maxSubscription {
		return false
	}

	s.subs[sub.id] = sub
	return true
}

func (s *SubscriptionsMap) Get(subID string) (*Subscription, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, exists := s.subs[subID]
	return sub, exists
}

func (s *SubscriptionsMap) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sub := range s.subs {
		sub.Stop()
		delete(s.subs, sub.id)
	}
}

// StopAllIDs is StopAll, returning the ids it stopped so the caller can
// tell the client.
func (s *SubscriptionsMap) StopAllIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := make([]string, 0, len(s.subs))
	for id, sub := range s.subs {
		sub.Stop()
		delete(s.subs, id)
		ids = append(ids, id)
	}
	return ids
}

func (s *SubscriptionsMap) Close(subID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, exists := s.subs[subID]
	if exists {
		delete(s.subs, subID)
		sub.Stop()
	}

	return exists
}

func (s *SubscriptionsMap) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.subs)
}
