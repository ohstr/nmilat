package listing

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
)

const recommendationAlt = "Recommendation of a cash offer"

// ErrRecommendation is a kind-31191 event ParseRecommendation refuses; a wallet
// ignores it.
var ErrRecommendation = errors.New("listing: not a valid recommendation")

// Recommendation is a parsed kind 31191 (§Recommendations): Node is d (the node
// identity), Offers the a values naming that node's listings. Content is the
// user's own text, plain.
type Recommendation struct {
	Event     *nip01.Event
	Author    string
	Node      string
	Content   string
	Offers    []string
	CreatedAt int64
}

// Address is the recommendation's address, "31191:<author>:<node>".
func (r *Recommendation) Address() string {
	return strconv.Itoa(KindRecommendation) + ":" + r.Author + ":" + r.Node
}

// NewRecommendation builds an unsigned 31191 for offers of node. content is
// exactly what the user typed: a wallet never pre-fills it.
func NewRecommendation(node, nodeRelay string, offers []Ref, content string) *nip01.Event {
	tags := [][]string{{"d", node}, {"k", strconv.Itoa(KindListing)}, refTag("p", Ref{Pubkey: node, Relay: nodeRelay})}
	for _, o := range offers {
		tags = append(tags, refTag("a", o))
	}
	tags = append(tags, []string{"alt", recommendationAlt})
	return nip01.NewEvent(KindRecommendation, content, tags...)
}

// ParseRecommendation reads a signed 31191. One whose k is not 31190 or whose p
// differs from d is refused; an a naming another node than d is dropped.
func ParseRecommendation(ev *nip01.Event) (*Recommendation, error) {
	if ev == nil || ev.Kind != KindRecommendation {
		return nil, fmt.Errorf("%w: kind", ErrRecommendation)
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecommendation, err)
	}
	r := &Recommendation{Event: ev, Author: ev.PubKey, Content: ev.Content, CreatedAt: int64(ev.CreatedAt)}
	var p string
	var hasD, hasP bool
	for _, t := range ev.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "d":
			if !hasD {
				r.Node, hasD = t[1], true
			}
		case "p":
			if !hasP {
				p, hasP = t[1], true
			}
		}
	}
	if !hasD || !isHex64(r.Node) || !hasTag(ev, "k", strconv.Itoa(KindListing)) {
		return nil, fmt.Errorf("%w: d or k", ErrRecommendation)
	}
	if p != r.Node {
		return nil, fmt.Errorf("%w: p differs from d", ErrRecommendation)
	}
	for _, t := range ev.Tags {
		if len(t) < 2 || t[0] != "a" {
			continue
		}
		if k, node, _, ok := ParseAddress(t[1]); ok && k == KindListing && node == r.Node && !slices.Contains(r.Offers, t[1]) {
			r.Offers = append(r.Offers, t[1])
		}
	}
	return r, nil
}

// CreditedOffers lists the addresses r is credited to (§Recommendations): the
// offers its a tags name, and any other listing in ofNode of the same node whose
// verified operator equals a named offer's verified operator; no other.
// operatorOf returns an address's verified operator (OperatorVerified), ok false
// when it has none.
func CreditedOffers(r *Recommendation, ofNode []*Listing, operatorOf func(addr string) (string, bool)) []string {
	if r == nil {
		return nil
	}
	out := slices.Clone(r.Offers)
	if operatorOf == nil {
		return out
	}
	ops := map[string]bool{}
	for _, a := range r.Offers {
		if op, ok := operatorOf(a); ok {
			ops[op] = true
		}
	}
	for _, l := range ofNode {
		if l == nil || l.NodeIdentity != r.Node {
			continue
		}
		addr := l.Address()
		if slices.Contains(out, addr) {
			continue
		}
		if op, ok := operatorOf(addr); ok && ops[op] {
			out = append(out, addr)
		}
	}
	return out
}

// RecommendAllowed reports whether a wallet may offer to recommend (§Wallet
// Rules "Recommending and reporting"): the user used the offer (ordered or
// joined through a string §Connection Signatures found signed by TLV 4 and that
// a listing carried; an unverified string earns none, so pass false), not in the
// session of that order or join (lastOrderOrJoin before sessionStart), and at
// least one day after it.
func RecommendAllowed(used bool, lastOrderOrJoin, sessionStart, now int64) bool {
	return used && lastOrderOrJoin < sessionStart && now-lastOrderOrJoin >= 86400
}

// NewRecommendationDeletion builds the unsigned NIP-09 withdrawal of a
// recommendation address "31191:<author>:<d>": ["a", addr], ["k", "31191"].
func NewRecommendationDeletion(addr string, createdAt int64) *nip01.Event {
	ev := nip01.NewEvent(kindDeletion, "", []string{"a", addr}, []string{"k", strconv.Itoa(KindRecommendation)})
	ev.CreatedAt = uint64(createdAt)
	return ev
}

// NewestRecommendations keeps, per author and d, the newest recommendation (the
// highest created_at, the lowest id on a tie), and drops it when its author
// withdrew it: a signed kind 5 by that author with ["a", "31191:<author>:<d>"]
// and ["k", "31191"] dated at or after it. A deletion by anyone else is
// ignored. Feed SignalsFor only its output.
func NewestRecommendations(recs []*Recommendation, deletions []*nip01.Event) []*Recommendation {
	newest := map[string]*Recommendation{}
	var order []string
	for _, r := range recs {
		if r == nil || r.Event == nil {
			continue
		}
		addr := r.Address()
		cur, ok := newest[addr]
		if !ok {
			order = append(order, addr)
		}
		if !ok || nip01.Supersedes(r.Event, cur.Event) {
			newest[addr] = r
		}
	}
	floors := map[string]int64{}
	k := strconv.Itoa(KindRecommendation)
	for _, ev := range deletions {
		if ev == nil || ev.Kind != kindDeletion || !hasTag(ev, "k", k) || ev.Verify() != nil {
			continue
		}
		for _, t := range ev.Tags {
			if len(t) < 2 || t[0] != "a" {
				continue
			}
			if kind, author, _, ok := ParseAddress(t[1]); ok && kind == KindRecommendation && author == ev.PubKey {
				floors[t[1]] = max(floors[t[1]], int64(ev.CreatedAt))
			}
		}
	}
	var out []*Recommendation
	for _, addr := range order {
		r := newest[addr]
		if f, ok := floors[addr]; ok && r.CreatedAt <= f {
			continue
		}
		out = append(out, r)
	}
	return out
}
