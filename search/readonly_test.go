package search

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/testlogger"
)

type mockInnerService struct {
	findProfilesCalled  bool
	indexCalled         bool
	updateScoreCalled   bool
	deleteIndexCalled   bool
	deleteProfileCalled bool
}

func (m *mockInnerService) Initialize(ctx context.Context) error { return nil }
func (m *mockInnerService) Shutdown(ctx context.Context) error   { return nil }
func (m *mockInnerService) DeleteIndex(ctx context.Context) error {
	m.deleteIndexCalled = true
	return nil
}
func (m *mockInnerService) UpdateScore(ctx context.Context, pubkey string, score int64) error {
	m.updateScoreCalled = true
	return nil
}
func (m *mockInnerService) IndexProfile(ctx context.Context, doc *ProfileDocument) error {
	m.indexCalled = true
	return nil
}
func (m *mockInnerService) IndexProfileWithMetrics(ctx context.Context, doc *ProfileDocument, fn func(string) (int64, error)) error {
	m.indexCalled = true
	return nil
}
func (m *mockInnerService) FindProfiles(ctx context.Context, query string, limit int) ([]string, error) {
	m.findProfilesCalled = true
	return []string{"abc123"}, nil
}
func (m *mockInnerService) DeleteProfile(ctx context.Context, pubkey string) error {
	m.deleteProfileCalled = true
	return nil
}

func TestReadOnlyService_FindProfiles_Delegates(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	results, err := ro.FindProfiles(context.Background(), "alice", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inner.findProfilesCalled {
		t.Fatal("expected FindProfiles to be delegated to inner service")
	}
	if len(results) != 1 || results[0] != "abc123" {
		t.Fatalf("unexpected results: %v", results)
	}
}

func TestReadOnlyService_IndexProfile_NoOp(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	err := ro.IndexProfile(context.Background(), &ProfileDocument{ID: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.indexCalled {
		t.Fatal("IndexProfile should NOT be delegated in readonly mode")
	}
}

func TestReadOnlyService_IndexProfileWithMetrics_NoOp(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	err := ro.IndexProfileWithMetrics(context.Background(), &ProfileDocument{ID: "test"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.indexCalled {
		t.Fatal("IndexProfileWithMetrics should NOT be delegated in readonly mode")
	}
}

func TestReadOnlyService_UpdateScore_NoOp(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	err := ro.UpdateScore(context.Background(), "pubkey", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.updateScoreCalled {
		t.Fatal("UpdateScore should NOT be delegated in readonly mode")
	}
}

func TestReadOnlyService_DeleteIndex_NoOp(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	err := ro.DeleteIndex(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.deleteIndexCalled {
		t.Fatal("DeleteIndex should NOT be delegated in readonly mode")
	}
}

func TestReadOnlyService_DeleteProfile_NoOp(t *testing.T) {
	inner := &mockInnerService{}
	ro := NewReadOnlyServiceWithLogger(inner, testlogger.New(t))

	err := ro.DeleteProfile(context.Background(), "pubkey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.deleteProfileCalled {
		t.Fatal("DeleteProfile should NOT be delegated in readonly mode")
	}
}
