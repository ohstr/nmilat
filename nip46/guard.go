package nip46

import (
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
)

// KeyGuard refuses output that contains a signer's own key. Signer servers
// run it before their policy, so no policy can sign or encrypt the key out.
type KeyGuard struct {
	needles []string
}

// NewKeyGuard guards each private key given as hex (its hex and nsec forms)
// and any extra strings, such as the ncryptsec a key was loaded from.
func NewKeyGuard(privKeysHex []string, extra ...string) *KeyGuard {
	g := &KeyGuard{}
	for _, priv := range privKeysHex {
		g.add(priv)
		if nsec, err := nip19.EncodePrivateKey(priv); err == nil {
			g.add(nsec)
		}
	}
	for _, e := range extra {
		g.add(e)
	}
	return g
}

func (g *KeyGuard) add(s string) {
	if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
		g.needles = append(g.needles, s)
	}
}

// Contains reports whether any of texts holds a guarded string,
// case-insensitively.
func (g *KeyGuard) Contains(texts ...string) bool {
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

// ContainsEvent checks the event's content and every tag element.
func (g *KeyGuard) ContainsEvent(ev *nip01.Event) bool {
	if g.Contains(ev.Content) {
		return true
	}
	for _, t := range ev.Tags {
		if g.Contains(t...) {
			return true
		}
	}
	return false
}
