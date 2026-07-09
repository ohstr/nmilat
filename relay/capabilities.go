package relay

import (
	"sort"
	"sync"

	"github.com/ohstr/nmilat/nip11"
)

// coreNIPs are enforced directly by the event store / wire protocol,
// regardless of how a SessionHandler is configured.
var coreNIPs = []int{
	1,  // NIP-01: basic protocol, always on.
	9,  // NIP-09: deletion, see nip09.IsDeletionKind in store.go.
	11, // NIP-11: this document itself.
	16, // NIP-16: replaceable events, see nip16.IsReplaceableKind in store.go.
	33, // NIP-33: parameterized replaceable events, see nip33.IsParamReplaceableKind in store.go.
	40, // NIP-40: expiration timestamp, see getExpiration in store.go.
	77, // NIP-77: negentropy set reconciliation, always wired in session.go.
}

var (
	nipRegistryMu sync.RWMutex
	nipRegistry   = make(map[int]struct{})
)

// RegisterNIP declares that this build supports the given NIP. Feature
// packages call this from init(), typically alongside RegisterEventValidator,
// so the set of supported NIPs is derived from which packages are actually
// linked into the binary rather than asserted by config.
func RegisterNIP(n int) {
	nipRegistryMu.Lock()
	nipRegistry[n] = struct{}{}
	nipRegistryMu.Unlock()
}

// RegisteredNIPs returns the NIPs declared via RegisterNIP, sorted.
func RegisteredNIPs() []int {
	nipRegistryMu.RLock()
	defer nipRegistryMu.RUnlock()

	nips := make([]int, 0, len(nipRegistry))
	for n := range nipRegistry {
		nips = append(nips, n)
	}
	sort.Ints(nips)
	return nips
}

// SupportedNIPs derives the set of NIPs this SessionHandler actually
// implements from its wired-in configuration and services. Operators cannot
// override this list — it is computed, not configured.
func (sh *SessionHandler) SupportedNIPs() nip11.NIPSet {
	nips := append([]int{}, coreNIPs...)
	nips = append(nips, RegisteredNIPs()...)

	if sh.relayMetadata != nil && sh.relayMetadata.Limitation.AuthRequired {
		nips = append(nips, 42) // NIP-42: Authentication
	}
	if sh.config != nil && sh.config.Delegation != nil {
		nips = append(nips, 26) // NIP-26: Delegated Event Signing
	}
	if sh.searchService != nil {
		nips = append(nips, 50) // NIP-50: Search Capability
	}

	return nip11.NewNIPSet(nips...)
}
