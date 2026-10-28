// Package nip18 implements NIP-18: Reposts (kind 6 for text notes, kind 16
// for anything else) and "q" quote tags.
package nip18

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

const (
	KindRepost        = 6
	KindGenericRepost = 16
)

// NewRepost builds an unsigned repost of target. Its content is target's
// JSON, unless target is protected (NIP-70 "-" tag), which must not be
// copied.
func NewRepost(target *nip01.Event, relay string) (*nip01.Event, error) {
	content := ""
	if !isProtected(target) {
		b, err := json.Marshal(target)
		if err != nil {
			return nil, fmt.Errorf("nip18: %w", err)
		}
		content = string(b)
	}
	kind := KindRepost
	if target.Kind != 1 {
		kind = KindGenericRepost
	}
	ev := nip01.NewEvent(kind, content)
	ev.Tags = [][]string{{"e", target.ID, relay}, {"p", target.PubKey}}
	if kind == KindGenericRepost {
		ev.Tags = append(ev.Tags, []string{"k", strconv.Itoa(target.Kind)})
		if target.Kind >= 30000 && target.Kind < 40000 {
			ev.Tags = append(ev.Tags, []string{"a", fmt.Sprintf("%d:%s:%s", target.Kind, strings.ToLower(target.PubKey), dTag(target)), relay})
		}
	}
	return ev, nil
}

// QuoteTag is the "q" tag citing an event.
func QuoteTag(id, relay, author string) []string {
	return []string{"q", id, relay, author}
}

func isProtected(ev *nip01.Event) bool {
	for _, t := range ev.Tags {
		if len(t) == 1 && t[0] == "-" {
			return true
		}
	}
	return false
}

func dTag(ev *nip01.Event) string {
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "d" {
			return t[1]
		}
	}
	return ""
}
