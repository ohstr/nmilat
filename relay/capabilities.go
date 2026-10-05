package relay

import (
	"errors"
	"fmt"
	"strings"
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
	70, // NIP-70
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

// RegisterLetteredNIP declares support for a NIP whose ID isn't a plain
// number (e.g. "B0", "B7", "A0"). See RegisterNIP.
//
// The id is trimmed and upper-cased, so "b7" and "B7" declare the same NIP
// rather than two entries that both reach the wire. Every id registered in
// this SDK is upper-case, matching the upstream spec filenames.
//
// It panics on an id that cannot name a lettered NIP: empty, containing
// anything but letters and digits, or all digits. Each is a programming error
// in an init() that would otherwise serve a malformed supported_nips list to
// every client for the life of the process, and the all-digit case is the
// worst of the three -- "53" would serialize as a JSON string where every
// other implementation expects the number 53. Panicking at registration
// mirrors migrations.Register rejecting a duplicate version.
func RegisterLetteredNIP(s string) {
	normalized, err := normalizeLetteredNIP(s)
	if err != nil {
		panic(fmt.Sprintf("relay: RegisterLetteredNIP(%q): %v", s, err))
	}
	registerNIPID(nip11.NIPLetter(normalized))
}

// normalizeLetteredNIP validates and canonicalizes a lettered NIP id. It is
// separate from RegisterLetteredNIP so the rules can be tested without
// mutating the process-wide registry, which has no unregister.
func normalizeLetteredNIP(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", errors.New("id is empty")
	}

	allDigits := true
	for _, r := range trimmed {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			allDigits = false
		default:
			return "", fmt.Errorf("id must contain only letters and digits, found %q", r)
		}
	}
	if allDigits {
		return "", errors.New("id is all digits; use RegisterNIP for a numbered NIP")
	}

	return strings.ToUpper(trimmed), nil
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

	// NIP-42 is unconditional: Session.Start sends the AUTH challenge on
	// every connection now, not just when AuthRequired is on (see its own
	// comment), so every relay genuinely supports it regardless of this
	// flag -- a relay with MembershipRequired/a private NIP-29 group but
	// AuthRequired: false would otherwise keep lying in its own NIP-11
	// document about a capability it actually has.
	nips = append(nips, nip11.NIP(42)) // NIP-42: Authentication
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
