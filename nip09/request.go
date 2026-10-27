package nip09

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// NewDeletionRequest builds an unsigned kind 5 asking relays to drop
// targets, all of which must be author's: "e" per event, "a" per
// addressable one, and one "k" per kind.
func NewDeletionRequest(author string, targets []*nip01.Event, reason string) (*nip01.Event, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("nip09: nothing to delete")
	}
	ev := nip01.NewEvent(KindDeletion, reason)
	ev.Tags = [][]string{}
	kinds := map[int]bool{}
	for _, t := range targets {
		if !strings.EqualFold(t.PubKey, author) {
			return nil, fmt.Errorf("nip09: event %s is by %s, not %s", t.ID, t.PubKey, author)
		}
		ev.Tags = append(ev.Tags, []string{"e", t.ID})
		if t.Kind >= 30000 && t.Kind < 40000 {
			d := ""
			for _, tag := range t.Tags {
				if len(tag) >= 2 && tag[0] == "d" {
					d = tag[1]
					break
				}
			}
			ev.Tags = append(ev.Tags, []string{"a", fmt.Sprintf("%d:%s:%s", t.Kind, strings.ToLower(t.PubKey), d)})
		}
		if !kinds[t.Kind] {
			kinds[t.Kind] = true
			ev.Tags = append(ev.Tags, []string{"k", strconv.Itoa(t.Kind)})
		}
	}
	return ev, nil
}
