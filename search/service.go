// Package search implements profile search indexing and ranking used by
// the relay package to serve NIP-50 search queries: a pluggable Backend
// interface, a batching Service that indexes profile updates
// asynchronously, and a ReadOnlyService decorator for relay instances that
// should query but never index.
package search

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Backend defines the methods we use from the infrastructure layer.
// This allows mocking for tests and swapping the underlying search engine.
type Backend interface {
	Initialize(ctx context.Context) error
	IndexProfile(ctx context.Context, doc *ProfileDocument) error
	BulkIndex(docs []*ProfileDocument) error
	FindProfiles(ctx context.Context, query string, limit int) ([]string, error)
	DeleteProfile(ctx context.Context, pubkey string) error
	UpdateScore(ctx context.Context, pubkey string, score int64) error
	DeleteIndex(ctx context.Context) error
	IndexProfileWithMetrics(ctx context.Context, doc *ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error
}

type ServiceImpl struct {
	client Backend

	// Write path
	inputChan chan *ProfileDocument
	closeCh   chan struct{}
	wg        sync.WaitGroup

	batchSize     int
	batchInterval time.Duration
}

func NewService(client Backend, batchSize int, maxChSize int) *ServiceImpl {
	if batchSize <= 0 {
		batchSize = 500
	}
	if maxChSize <= 0 {
		maxChSize = 5000
	}

	return &ServiceImpl{
		client:        client,
		inputChan:     make(chan *ProfileDocument, maxChSize),
		closeCh:       make(chan struct{}),
		batchSize:     batchSize,
		batchInterval: 2 * time.Second,
	}
}

func (s *ServiceImpl) Initialize(ctx context.Context) error {
	if err := s.client.Initialize(ctx); err != nil {
		return err
	}
	s.startWorker()
	return nil
}

func (s *ServiceImpl) Shutdown(ctx context.Context) error {
	close(s.closeCh)
	s.wg.Wait()
	return nil
}

// IndexProfile implements Indexer.
// It is non-blocking. If channel is full, it drops the update to preserve Relay stability.
func (s *ServiceImpl) IndexProfile(ctx context.Context, doc *ProfileDocument) error {
	select {
	case s.inputChan <- doc:
		return nil
	default:
		log.Warn().Str("id", doc.ID).Msg("search indexing channel full, dropping update")
		return fmt.Errorf("indexing channel full")
	}
}

// IndexProfileWithMetrics adds any existing verified metrics (Nip05/Lud16/Picture)
// to the base score before pushing to the index channel.
func (s *ServiceImpl) IndexProfileWithMetrics(ctx context.Context, doc *ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error {
	if getMetricsFunc != nil {
		if extraMetrics, err := getMetricsFunc(doc.ID); err == nil {
			doc.Score += extraMetrics
		}
	}
	return s.IndexProfile(ctx, doc)
}

func (s *ServiceImpl) DeleteProfile(ctx context.Context, pubkey string) error {
	// For R1, we can just call directly or add a DeleteDocument struct to channel.
	// Direct call is fine for deletes as they are rare compared to updates.
	return s.client.DeleteProfile(ctx, pubkey)
}

func (s *ServiceImpl) UpdateScore(ctx context.Context, pubkey string, score int64) error {
	return s.client.UpdateScore(ctx, pubkey, score)
}

func (s *ServiceImpl) DeleteIndex(ctx context.Context) error {
	return s.client.DeleteIndex(ctx)
}

// FindProfiles implements Searcher.
func (s *ServiceImpl) FindProfiles(ctx context.Context, query string, limit int) ([]string, error) {
	return s.client.FindProfiles(ctx, query, limit)
}

func (s *ServiceImpl) startWorker() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.workerLoop()
	}()
}

func (s *ServiceImpl) workerLoop() {
	buffer := make([]*ProfileDocument, 0, s.batchSize)
	ticker := time.NewTicker(s.batchInterval)
	defer ticker.Stop()

	flush := func() {
		if len(buffer) > 0 {
			if err := s.client.BulkIndex(buffer); err != nil {
				log.Error().Err(err).Int("batch_size", len(buffer)).Msg("failed to bulk index profiles")
			} else {
				log.Debug().Int("count", len(buffer)).Msg("bulk indexed profiles")
			}
			// Reset buffer (keep capacity)
			buffer = buffer[:0]
		}
	}

	for {
		select {
		case doc := <-s.inputChan:
			buffer = append(buffer, doc)
			if len(buffer) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.closeCh:
			// Drain remaining items in channel
		drainLoop:
			for {
				select {
				case doc := <-s.inputChan:
					buffer = append(buffer, doc)
					if len(buffer) >= s.batchSize {
						flush()
					}
				default:
					break drainLoop
				}
			}
			flush()
			return
		}
	}
}
