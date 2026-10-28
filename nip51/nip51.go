// Package nip51 implements NIP-51 lists: replaceable events whose public
// items are tags and whose private items are encrypted in the content.
package nip51

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

const (
	KindMuteList     = 10000
	KindSimpleGroups = 10009
)

// Add returns a new unsigned copy of list (or an empty list of kind when
// list is nil) with each tag appended unless an equal item (same name and
// value) is already there. Other tags and the content, which may hold
// encrypted private items, are kept as they are. added lists the values
// that were new.
func Add(list *nip01.Event, kind int, tags ...[]string) (out *nip01.Event, added []string) {
	out = base(list, kind)
	for _, tag := range tags {
		if len(tag) < 2 || Has(out, tag[0], tag[1]) {
			continue
		}
		out.Tags = append(out.Tags, append([]string(nil), tag...))
		added = append(added, tag[1])
	}
	return out, added
}

// Remove returns a new unsigned copy of list without the items named name
// with any of values. Everything else is kept. removed lists the values
// that were there.
func Remove(list *nip01.Event, kind int, name string, values ...string) (out *nip01.Event, removed []string) {
	out = base(list, kind)
	drop := map[string]bool{}
	for _, v := range values {
		drop[fold(name, v)] = true
	}
	kept := out.Tags[:0]
	for _, t := range out.Tags {
		if len(t) >= 2 && t[0] == name && drop[fold(name, t[1])] {
			removed = append(removed, t[1])
			continue
		}
		kept = append(kept, t)
	}
	out.Tags = kept
	return out, removed
}

// Has reports whether list has an item name=value. Pubkeys and event ids
// ("p", "e") are compared without case; words and topics exactly.
func Has(list *nip01.Event, name, value string) bool {
	if list == nil {
		return false
	}
	for _, t := range list.Tags {
		if len(t) >= 2 && t[0] == name && fold(name, t[1]) == fold(name, value) {
			return true
		}
	}
	return false
}

// Values lists every value of list's name tags, in order.
func Values(list *nip01.Event, name string) []string {
	out := []string{}
	if list == nil {
		return out
	}
	for _, t := range list.Tags {
		if len(t) >= 2 && t[0] == name {
			out = append(out, t[1])
		}
	}
	return out
}

// fold lower-cases hex values (pubkeys, event ids), which may be written
// either way; other values are kept as they are.
func fold(name, value string) string {
	if name == "p" || name == "e" {
		return strings.ToLower(value)
	}
	return value
}

// base copies list, or starts an empty list of kind. A list of another
// kind is not this list and is not copied.
func base(list *nip01.Event, kind int) *nip01.Event {
	out := nip01.NewEvent(kind, "")
	out.Tags = [][]string{}
	if list != nil && list.Kind == kind {
		out.Content = list.Content
		for _, t := range list.Tags {
			out.Tags = append(out.Tags, append([]string(nil), t...))
		}
	}
	return out
}
