package cashtest

import (
	"sync"
	"time"
)

// nonceBook remembers the envelope nonces the Hub served, each until its
// envelope's not_after: past that the envelope is refused as expired anyway, so a
// Hub need remember no longer (NIP-CASH §Serving an Envelope).
type nonceBook struct {
	mu     sync.Mutex
	served map[string]time.Time
}

// claim records nonce as served and reports whether it was new. Entries past
// their not_after are dropped first.
func (b *nonceBook) claim(nonce string, notAfter, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.served == nil {
		b.served = map[string]time.Time{}
	}
	for n, until := range b.served {
		if now.After(until) {
			delete(b.served, n)
		}
	}
	if _, dup := b.served[nonce]; dup {
		return false
	}
	b.served[nonce] = notAfter
	return true
}

// seen reports whether nonce was served and is still remembered at now.
func (b *nonceBook) seen(nonce string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.served[nonce]
	return ok && !now.After(until)
}

// release forgets nonce, for an envelope a Hub stopped serving before it committed
// anything.
func (b *nonceBook) release(nonce string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.served, nonce)
}
