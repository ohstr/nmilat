package nipLS

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

// guard refuses output that contains the signer's own key. It runs before
// the policy and can't be turned off.
type guard struct {
	needles []string
}

func newGuard(secrets ...string) *guard {
	g := &guard{}
	for _, s := range secrets {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			g.needles = append(g.needles, s)
		}
	}
	return g
}

// contains reports whether any of texts holds a needle, case-insensitively.
func (g *guard) contains(texts ...string) bool {
	for _, t := range texts {
		lt := strings.ToLower(t)
		for _, n := range g.needles {
			if strings.Contains(lt, n) {
				return true
			}
		}
	}
	return false
}

// containsEvent checks the event's content and every tag element.
func (g *guard) containsEvent(ev *nip01.Event) bool {
	if g.contains(ev.Content) {
		return true
	}
	for _, t := range ev.Tags {
		if g.contains(t...) {
			return true
		}
	}
	return false
}
