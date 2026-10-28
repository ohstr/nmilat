package client

import (
	"context"
	"github.com/ohstr/nmilat/nipcash"
	"testing"
	"time"
)

// e2eContext bounds an end-to-end test by the test binary's own deadline (go test
// -timeout) instead of a fixed 20–30 s. The fixed deadlines timed out on a busy
// machine while catching nothing a hung test would not also hit here.
func e2eContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if d, ok := t.Deadline(); ok {
		return context.WithDeadline(context.Background(), d.Add(-10*time.Second))
	}
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// mustCashTarget is a fresh cash target, failing the test on a CSPRNG error.
func mustCashTarget(t *testing.T) *nipcash.CashTarget {
	t.Helper()
	c, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
