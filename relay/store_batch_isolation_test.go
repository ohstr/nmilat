package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip01"
)

// TestExecuteBatch_FailureIsolated: a task that aborts the batch transaction
// fails alone; the rest of the batch is still stored.
func TestExecuteBatch_FailureIsolated(t *testing.T) {
	store := newStore(t)
	good := CreateEvents(t, 2, 1)
	bad := CreateEvent(t, 1)
	bad.ID = "not-hex"

	tasks := []*EventInsertTask{
		NewEventInsertTask([]*nip01.Event{good[0]}),
		NewEventInsertTask([]*nip01.Event{bad}),
		NewEventInsertTask([]*nip01.Event{good[1]}),
	}
	store.ExecuteBatch([]Task{tasks[0], tasks[1], tasks[2]})

	for i, task := range tasks {
		select {
		case <-task.Completed():
			if i == 1 {
				t.Fatal("bad task succeeded")
			}
		case err := <-task.Errors():
			if i != 1 {
				t.Fatalf("task %d failed with %v; only the bad task should", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("task %d never completed", i)
		}
	}

	all, err := store.FetchAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("stored %d events, want 2", len(all))
	}
}

// TestViewScan_WaitsForSlot: with every scan slot taken, a query waits and
// gives up with its own context instead of opening another read.
func TestViewScan_WaitsForSlot(t *testing.T) {
	store := newStore(t)
	store.scanSlots = make(chan struct{}, 1)
	store.scanSlots <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	ran := false
	err := store.viewScan(ctx, func(*bolt.Tx) error { ran = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || ran {
		t.Fatalf("err=%v ran=%v, want deadline exceeded without running", err, ran)
	}

	<-store.scanSlots
	if err := store.viewScan(context.Background(), func(*bolt.Tx) error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("err=%v ran=%v once a slot is free", err, ran)
	}
}
