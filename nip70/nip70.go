// Package nip70 implements NIP-70: Protected Events.
//
// An event carrying a bare ["-"] tag is "protected": only its own author may
// publish it. A relay MUST reject such an event by default, and may accept one
// only after the NIP-42 AUTH flow has run and the authenticated pubkey matches
// the event's.
//
// This package is the tag predicate alone. Enforcement belongs to whatever owns
// the connection's authentication state.
package nip70

// TagName is the single-element tag that marks an event protected.
const TagName = "-"

// IsProtected reports whether tags carry the NIP-70 marker.
//
// The marker is the tag name alone; a value after it is not part of the spec and
// is ignored rather than treated as a different tag, so ["-"] and ["-", "x"]
// both protect the event. That way a client cannot slip a protected event past a
// relay by padding the tag.
func IsProtected(tags [][]string) bool {
	for _, tag := range tags {
		if len(tag) > 0 && tag[0] == TagName {
			return true
		}
	}
	return false
}
