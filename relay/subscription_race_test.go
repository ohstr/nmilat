package relay

import (
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip11"
)

// Sessions share one Limitation; building their subscription maps
// concurrently must not write to it (run with -race).
func TestNewSubscriptions_SharedLimitationUntouched(t *testing.T) {
	lim := &nip11.Limitation{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m := NewSubscriptions(lim); m.maxSubscription != defaultMaxSubscriptions {
				t.Errorf("maxSubscription = %d, want the default", m.maxSubscription)
			}
		}()
	}
	wg.Wait()
	if lim.MaxSubscriptions != 0 {
		t.Errorf("shared Limitation was mutated: MaxSubscriptions = %d", lim.MaxSubscriptions)
	}
}
