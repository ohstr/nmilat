// Package nip02 implements NIP-02: Follow List, the kind 3 list of
// followed pubkeys.
package nip02

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip51"
)

const KindContacts = 3

// Follow returns a new unsigned follow list: list (nil for none) plus each
// pubkey not already followed. Other tags and the content are kept.
func Follow(list *nip01.Event, pubkeys ...string) (*nip01.Event, []string) {
	tags := make([][]string, 0, len(pubkeys))
	for _, p := range pubkeys {
		tags = append(tags, []string{"p", strings.ToLower(p)})
	}
	return nip51.Add(list, KindContacts, tags...)
}

// Unfollow returns a new unsigned follow list without pubkeys.
func Unfollow(list *nip01.Event, pubkeys ...string) (*nip01.Event, []string) {
	return nip51.Remove(list, KindContacts, "p", pubkeys...)
}

// Follows lists the followed pubkeys, in order.
func Follows(list *nip01.Event) []string { return nip51.Values(list, "p") }
