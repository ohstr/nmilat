package search

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockBackend is a mock of search.Backend
type MockBackend struct {
	mock.Mock
}

func (m *MockBackend) Initialize(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockBackend) IndexProfile(ctx context.Context, doc *ProfileDocument) error {
	args := m.Called(ctx, doc)
	return args.Error(0)
}

func (m *MockBackend) IndexProfileWithMetrics(ctx context.Context, doc *ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error {
	args := m.Called(ctx, doc, getMetricsFunc)
	return args.Error(0)
}

func (m *MockBackend) BulkIndex(docs []*ProfileDocument) error {
	args := m.Called(docs)
	return args.Error(0)
}

func (m *MockBackend) FindProfiles(ctx context.Context, query string, limit int) ([]string, error) {
	args := m.Called(ctx, query, limit)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockBackend) DeleteProfile(ctx context.Context, pubkey string) error {
	args := m.Called(ctx, pubkey)
	return args.Error(0)
}

func (m *MockBackend) UpdateScore(ctx context.Context, pubkey string, score int64) error {
	args := m.Called(ctx, pubkey, score)
	return args.Error(0)
}

func (m *MockBackend) DeleteIndex(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestService_Initialize(t *testing.T) {
	mockClient := new(MockBackend)
	mockClient.On("Initialize", mock.Anything).Return(nil)

	svc := NewService(mockClient, 10, 100)
	err := svc.Initialize(context.Background())

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	// clean shutdown to avoid goroutine leak
	svc.Shutdown(context.Background())
}

func TestService_Batching(t *testing.T) {
	mockClient := new(MockBackend)
	// Expect BulkIndex to be called when batch fills up (size 10)
	// We will send 12 items.
	// 1. First batch of 10
	// 2. Second batch of 2 (flushed on shutdown)
	var wg sync.WaitGroup
	wg.Add(2)

	mockClient.On("BulkIndex", mock.MatchedBy(func(docs []*ProfileDocument) bool {
		return len(docs) == 10
	})).Return(nil).Run(func(args mock.Arguments) {
		wg.Done()
	})

	mockClient.On("BulkIndex", mock.MatchedBy(func(docs []*ProfileDocument) bool {
		return len(docs) == 2
	})).Return(nil).Run(func(args mock.Arguments) {
		wg.Done()
	})

	svc := NewService(mockClient, 10, 100)
	svc.startWorker() // Start manually as we don't need Initialize for this test

	ctx := context.Background()
	for i := 0; i < 12; i++ {
		svc.IndexProfile(ctx, &ProfileDocument{ID: "id"})
	}

	// We can't easily wait for the ANY bulk index via mock without a WaitGroup hook
	// But `svc.Shutdown` flushes remaining items.
	// However, the first batch (10 items) happens asynchronously in the loop.
	// We need to ensure it happened.
	// We added Run hook to wg.Done().

	svc.Shutdown(ctx)

	// Wait for expectations? Shutdown waits for worker loop to exit.
	// Worker loop handles flush.
	// So calling Shutdown ensures all processing is done.
	wg.Wait()
	mockClient.AssertExpectations(t)
}

func TestService_Ticker(t *testing.T) {
	mockClient := new(MockBackend)

	// Expect BulkIndex called due to ticker
	var wg sync.WaitGroup
	wg.Add(1)

	mockClient.On("BulkIndex", mock.MatchedBy(func(docs []*ProfileDocument) bool {
		return len(docs) == 1
	})).Return(nil).Run(func(args mock.Arguments) {
		wg.Done()
	})

	// Set short ticker for test
	svc := NewService(mockClient, 10, 100)
	svc.batchInterval = 100 * time.Millisecond
	svc.startWorker()

	svc.IndexProfile(context.Background(), &ProfileDocument{ID: "ticker_id"})

	// Wait for ticker
	// We wait via wg, which is triggered by mock run
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Ticker flush timed out")
	}

	svc.Shutdown(context.Background())
	mockClient.AssertExpectations(t)
}

func TestService_IndexProfile_NonBlocking(t *testing.T) {
	mockClient := new(MockBackend)
	// Small channel
	svc := NewService(mockClient, 10, 1) // ch size 1

	// Fill channel
	svc.inputChan <- &ProfileDocument{ID: "1"}

	// Next add should fail or log warn?
	// Implementation says: "If channel is full, it drops the update" and returns error.
	err := svc.IndexProfile(context.Background(), &ProfileDocument{ID: "2"})

	assert.Error(t, err)
	assert.Equal(t, "indexing channel full", err.Error())
}
