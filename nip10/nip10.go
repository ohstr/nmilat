// Package nip10 implements NIP-10's marked "e" tags for replies to kind 1
// text notes.
package nip10

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// Root returns the id (and relay hint) of the thread root parent belongs
// to: its "e" marked "root", else (deprecated positional form) its first
// unmarked "e", else parent itself.
func Root(parent *nip01.Event) (id, relay, author string) {
	var first []string
	for _, t := range parent.Tags {
		if len(t) < 2 || t[0] != "e" {
			continue
		}
		if len(t) >= 4 && t[3] == "root" {
			return t[1], at(t, 2), at(t, 4)
		}
		if first == nil && (len(t) < 4 || t[3] == "") {
			first = t
		}
	}
	if first != nil {
		return first[1], at(first, 2), ""
	}
	return parent.ID, "", parent.PubKey
}

// ReplyTags are the tags of a reply to parent: "e" root and "e" reply
// (just "root" when parent is the root), then "p" for parent's author and
// every pubkey parent tags, once each. relay is parent's relay hint.
func ReplyTags(parent *nip01.Event, relay string) [][]string {
	rootID, rootRelay, rootAuthor := Root(parent)
	var tags [][]string
	if rootID == parent.ID {
		tags = append(tags, []string{"e", parent.ID, relay, "root", parent.PubKey})
	} else {
		tags = append(tags,
			[]string{"e", rootID, rootRelay, "root", rootAuthor},
			[]string{"e", parent.ID, relay, "reply", parent.PubKey})
	}
	seen := map[string]bool{}
	addP := func(pk string) {
		pk = strings.ToLower(pk)
		if pk == "" || seen[pk] {
			return
		}
		seen[pk] = true
		tags = append(tags, []string{"p", pk})
	}
	addP(parent.PubKey)
	for _, t := range parent.Tags {
		if len(t) >= 2 && t[0] == "p" {
			addP(t[1])
		}
	}
	return tags
}

func at(t []string, i int) string {
	if i < len(t) {
		return t[i]
	}
	return ""
}
