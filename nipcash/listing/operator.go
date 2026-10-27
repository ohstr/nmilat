package listing

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ohstr/nmilat/nip01"
)

// operatorAlt is the 11191's alt text.
const operatorAlt = "Cash offers run by this account"

// ErrOperatorOffers is a kind-11191 event ParseOperatorOffers refuses.
var ErrOperatorOffers = errors.New("listing: not a valid operator's offers event")

// OperatorOffers is a parsed kind 11191 (§The Operator's Offers). Offers[i].Pubkey
// holds a listing address ("31190:<node identity>:<d>"), Nodes the p tags, which
// verify nothing. Only public items are read.
type OperatorOffers struct {
	Event  *nip01.Event
	Author string
	Offers []Ref
	Nodes  []Ref
}

// NewOperatorOffers builds an unsigned 11191: one a per offer, one p per node,
// alt, content "". The operator's own client signs it.
func NewOperatorOffers(offers, nodes []Ref) *nip01.Event {
	tags := make([][]string, 0, len(offers)+len(nodes)+1)
	for _, o := range offers {
		tags = append(tags, refTag("a", o))
	}
	for _, n := range nodes {
		tags = append(tags, refTag("p", n))
	}
	tags = append(tags, []string{"alt", operatorAlt})
	return nip01.NewEvent(KindOperatorOffers, "", tags...)
}

// ParseOperatorOffers reads a signed 11191's public a (listing addresses) and p
// tags. Private items in content are ignored.
func ParseOperatorOffers(ev *nip01.Event) (*OperatorOffers, error) {
	if ev == nil || ev.Kind != KindOperatorOffers {
		return nil, fmt.Errorf("%w: kind", ErrOperatorOffers)
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOperatorOffers, err)
	}
	o := &OperatorOffers{Event: ev, Author: ev.PubKey}
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		r := Ref{Pubkey: t[1]}
		if len(t) > 2 {
			r.Relay = t[2]
		}
		switch t[0] {
		case "a":
			if k, _, _, ok := ParseAddress(t[1]); ok && k == KindListing {
				o.Offers = append(o.Offers, r)
			}
		case "p":
			if isHex64(t[1]) {
				o.Nodes = append(o.Nodes, r)
			}
		}
	}
	return o, nil
}

// NewestOperatorOffers is author's newest valid 11191 among evs: the highest
// created_at, the lowest id on a tie. Only it counts. Nil when none.
func NewestOperatorOffers(evs []*nip01.Event, author string) *OperatorOffers {
	var best *OperatorOffers
	for _, ev := range evs {
		if ev == nil || ev.PubKey != author {
			continue
		}
		o, err := ParseOperatorOffers(ev)
		if err != nil {
			continue
		}
		if best == nil || nip01.Supersedes(ev, best.Event) {
			best = o
		}
	}
	return best
}

// MergeOperatorOffers builds the unsigned 11191 to republish: every a of the
// newest copy (nil for a first publish) in its order without those in remove,
// then those in add not already present; the newest copy's p tags; alt;
// content "".
func MergeOperatorOffers(newest *OperatorOffers, add, remove []Ref) *nip01.Event {
	var offers, nodes []Ref
	removed := func(r Ref) bool {
		return slices.ContainsFunc(remove, func(x Ref) bool { return x.Pubkey == r.Pubkey })
	}
	has := func(r Ref) bool {
		return slices.ContainsFunc(offers, func(x Ref) bool { return x.Pubkey == r.Pubkey })
	}
	if newest != nil {
		for _, r := range newest.Offers {
			if !removed(r) && !has(r) {
				offers = append(offers, r)
			}
		}
		nodes = newest.Nodes
	}
	for _, r := range add {
		if !removed(r) && !has(r) {
			offers = append(offers, r)
		}
	}
	return NewOperatorOffers(offers, nodes)
}

// OperatorVerified reports §The Operator's Offers' verification: the listing's
// p names newest's author and newest (the author's newest 11191) carries the
// listing's address. Either side alone proves nothing.
func OperatorVerified(l *Listing, newest *OperatorOffers) bool {
	if l == nil || l.Operator == nil || newest == nil || l.Operator.Pubkey != newest.Author {
		return false
	}
	addr := l.Address()
	return slices.ContainsFunc(newest.Offers, func(r Ref) bool { return r.Pubkey == addr })
}
