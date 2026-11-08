package testlogger

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// fakeTB records Log calls and holds Cleanup funcs until runCleanups.
type fakeTB struct {
	testing.TB
	mu       sync.Mutex
	lines    []string
	cleanups []func()
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Log(args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lines = append(f.lines, fmt.Sprint(args...))
}

func (f *fakeTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }

func (f *fakeTB) runCleanups() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

func (f *fakeTB) logged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

// A goroutine that outlives its test (a hijacked WebSocket handler logging
// "session ended") must not reach t.Log once the test is over: that races
// testing's completion bookkeeping under -race.
func TestNoLogAfterCleanup(t *testing.T) {
	tb := &fakeTB{}
	log := New(tb)
	log.Info().Msg("during the test")
	if got := tb.logged(); len(got) != 1 || !strings.Contains(got[0], "during the test") {
		t.Fatalf("logged %q, want the one line", got)
	}

	tb.runCleanups()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info().Msg("after the test")
		}()
	}
	wg.Wait()
	if got := tb.logged(); len(got) != 1 {
		t.Fatalf("logged %q after cleanup, want nothing new", got)
	}
}
