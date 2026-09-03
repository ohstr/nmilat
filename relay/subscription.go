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
}

func NewSubscription(id string, query *StoreQuery) (*Subscription, <-chan *PotentialEvent, <-chan error, <-chan bool) {
	sub := &Subscription{
		id:       id,
		query:    query,
		outgoing: make(chan *PotentialEvent, eventBufferCapacity),
		errors:   make(chan error, 1),
		eose:     make(chan bool),
		closeCh:  make(chan interface{}),
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

	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()

	defer wg.Wait()

	for {
		select {
		case <-ticker.C:
			// Continuous query for new events
			err := sub.query.Fetch(ctx, sub.outgoing, wg, true)
			if err != nil {
				sub.errors <- err
				return
			}
		case <-sub.closeCh:
			return
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

func NewSubscriptions(cfg *nip11.Limitation) *SubscriptionsMap {
	if cfg.MaxSubscriptions == 0 {
		cfg.MaxSubscriptions = defaultMaxSubscriptions
	}
	return &SubscriptionsMap{
		subs:            make(map[string]*Subscription),
		maxSubscription: cfg.MaxSubscriptions,
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
