// Package nip16 implements NIP-16: Event Treatment, the replaceable/
// ephemeral event-kind ranges (folded into NIP-01 upstream, kept here as a
// distinct package for the kind-range predicates).
package nip16

func IsReplaceableKind(kind int) bool {
	return kind == 0 ||
		kind == 3 ||
		(kind >= 10_000 && kind < 20_000)
}

func IsEphemeralKind(kind int) bool {
	return kind >= 20_000 && kind < 30_000
}
