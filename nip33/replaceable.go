// Package nip33 implements NIP-33: Parameterized Replaceable Events (kind
// 30000-39999, renamed "addressable events" and folded into NIP-01
// upstream), identified by pubkey+kind+"d" tag rather than pubkey+kind
// alone.
package nip33

func IsParamReplaceableKind(kind int) bool {
	return kind >= 30_000 && kind < 40_000
}
