package cashtest

import (
	"sync"
	"time"
)

// Clock is the time source every decision of the fake Hub reads.
type Clock interface{ Now() time.Time }

// RealClock reads the wall clock.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// ManualClock is a Clock that moves only when a test moves it.
//
// The zero value starts at the wall clock's time on first read, so a fresh
// ManualClock agrees with the timestamps the SDK writes.
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock returns a ManualClock set to t.
func NewManualClock(t time.Time) *ManualClock { return &ManualClock{now: t} }

// Now returns the clock's current time.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now.IsZero() {
		c.now = time.Now()
	}
	return c.now
}

// Set moves the clock to t.
func (c *ManualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance moves the clock forward by d.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now.IsZero() {
		c.now = time.Now()
	}
	c.now = c.now.Add(d)
}
