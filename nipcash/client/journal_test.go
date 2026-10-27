package client

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ohstr/nmilat/nipcash"
)

// testJournal is the Journal double: it stores calls as JSON and reads each one
// back before WriteAhead returns, as the contract requires.
type testJournal struct {
	mu       sync.Mutex
	calls    map[string][]byte
	order    []string
	derived  map[string]int64
	accepted map[string][]string
	failNext error
}

func newTestJournal() *testJournal {
	return &testJournal{calls: map[string][]byte{}, derived: map[string]int64{}, accepted: map[string][]string{}}
}

func (j *testJournal) WriteAhead(_ context.Context, calls []nipcash.PendingCall) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.failNext; err != nil {
		j.failNext = nil
		return err
	}
	for _, pc := range calls {
		raw, err := json.Marshal(pc)
		if err != nil {
			return err
		}
		j.calls[pc.RequestID] = raw
		j.order = append(j.order, pc.RequestID)
	}
	for _, pc := range calls {
		var back nipcash.PendingCall
		if err := json.Unmarshal(j.calls[pc.RequestID], &back); err != nil {
			return err
		}
	}
	return nil
}

func (j *testJournal) RecordDerived(_ context.Context, id string, keepUntil int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.derived[id] = keepUntil
	return nil
}

func (j *testJournal) DerivedPlaced(_ context.Context, id string) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.derived[id]
	return ok, nil
}

func (j *testJournal) RecordAccepted(_ context.Context, id string, relays []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.accepted[id] = relays
	return nil
}

func (j *testJournal) call(id string) (nipcash.PendingCall, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	raw, ok := j.calls[id]
	if !ok {
		return nipcash.PendingCall{}, false
	}
	var pc nipcash.PendingCall
	_ = json.Unmarshal(raw, &pc)
	return pc, true
}

func (j *testJournal) all() []nipcash.PendingCall {
	j.mu.Lock()
	ids := append([]string(nil), j.order...)
	j.mu.Unlock()
	out := make([]nipcash.PendingCall, 0, len(ids))
	for _, id := range ids {
		pc, _ := j.call(id)
		out = append(out, pc)
	}
	return out
}
