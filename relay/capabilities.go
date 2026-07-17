package relay

import (
	"sync"

	"github.com/ohstr/nmilat/nip11"
)

// coreNIPs are enforced directly by the event store / wire protocol,
// regardless of how a SessionHandler is configured.
var coreNIPs = []int{
	1,  // NIP-01
	9,  // NIP-09
	11, // NIP-11
	16, // NIP-16
	33, // NIP-33
	40, // NIP-40
	77, // NIP-77
}

var (
	nipRegistryMu sync.RWMutex
	nipRegistry   = make(map[string]nip11.NIPID)
)

// RegisterNIP declares that this build supports the given numbered NIP.
// Feature packages call this from init(), typically alongside
// RegisterEventValidator, so the set of supported NIPs is derived from which
// packages are actually linked into the binary rather than asserted by
// config.
func RegisterNIP(n int) {
	registerNIPID(nip11.NIP(n))
}

// RegisterLetteredNIP declares support for a letter-suffixed NIP (e.g. "B0",
// "B7") whose ID isn't a plain number. See RegisterNIP.
func RegisterLetteredNIP(s string) {
	registerNIPID(nip11.NIPLetter(s))
}

func registerNIPID(id nip11.NIPID) {
	nipRegistryMu.Lock()
	nipRegistry[id.String()] = id
	nipRegistryMu.Unlock()
}

// RegisteredNIPs returns the NIPs declared via RegisterNIP/RegisterLetteredNIP.
func RegisteredNIPs() []nip11.NIPID {
	nipRegistryMu.RLock()
	defer nipRegistryMu.RUnlock()

	nips := make([]nip11.NIPID, 0, len(nipRegistry))
	for _, id := range nipRegistry {
		nips = append(nips, id)
	}
	return nips
}

// SupportedNIPs derives the set of NIPs this SessionHandler actually
// implements from its wired-in configuration and services. Operators cannot
// override this list — it is computed, not configured.
func (sh *SessionHandler) SupportedNIPs() nip11.NIPSet {
	nips := make([]nip11.NIPID, 0, len(coreNIPs))
	for _, n := range coreNIPs {
		nips = append(nips, nip11.NIP(n))
	}
	nips = append(nips, RegisteredNIPs()...)

	if sh.relayMetadata != nil && sh.relayMetadata.Limitation.AuthRequired {
		nips = append(nips, nip11.NIP(42)) // NIP-42: Authentication
	}
	if sh.relayMetadata != nil && sh.relayMetadata.Self != "" {
		nips = append(nips, nip11.NIP(43)) // NIP-43: Relay Access Metadata and Requests
	}
	if sh.config != nil && sh.config.Delegation != nil {
		nips = append(nips, nip11.NIP(26)) // NIP-26: Delegated Event Signing
	}
	if sh.searchService != nil {
		nips = append(nips, nip11.NIP(50)) // NIP-50: Search Capability
	}

	return nip11.NewNIPSet(nips...)
}
