// Package nip09 implements NIP-09: Event Deletion Request, the kind-5
// event a user publishes to ask relays to stop serving their earlier
// events.
package nip09

const KindDeletion = 5

func IsDeletionKind(kind int) bool {
	return kind == KindDeletion
}
