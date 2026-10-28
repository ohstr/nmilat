// Package nip25 implements NIP-25: Reactions, a kind 7 event reacting to
// another event with "+", "-" or an emoji.
package nip25

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

const KindReaction = 7

// NewReaction builds an unsigned reaction to target: "e" (with relay hint
// and author), "p" (author), "k" (kind), "a" when target is addressable,
// and target's "h" when it belongs to a NIP-29 group. content defaults to
// "+".
func NewReaction(target *nip01.Event, content, relay string) *nip01.Event {
	if content == "" {
		content = "+"
	}
	ev := nip01.NewEvent(KindReaction, content)
	ev.Tags = [][]string{
		{"e", target.ID, relay, target.PubKey},
		{"p", target.PubKey, relay},
		{"k", strconv.Itoa(target.Kind)},
	}
	if a := Address(target); a != "" {
		ev.Tags = append(ev.Tags, []string{"a", a, relay})
	}
	if h := TagValue(target, "h"); h != "" {
		ev.Tags = append(ev.Tags, []string{"h", h})
	}
	return ev
}

// Address is target's "kind:pubkey:d" coordinate if it is addressable
// (kind 30000-39999), else "".
func Address(target *nip01.Event) string {
	if target.Kind < 30000 || target.Kind >= 40000 {
		return ""
	}
	return fmt.Sprintf("%d:%s:%s", target.Kind, strings.ToLower(target.PubKey), TagValue(target, "d"))
}

// TagValue is the first value of ev's tag name, or "".
func TagValue(ev *nip01.Event, name string) string {
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == name {
			return t[1]
		}
	}
	return ""
}
