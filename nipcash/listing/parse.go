package listing

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcw"
)

// CheckOptions are the wallet's side of "before showing" step 4: the chains it
// holds, and whether the user enabled test networks.
type CheckOptions struct {
	Chains       []string
	TestNetworks bool
}

// ListingError is a listing a wallet must not show. Step is the first failing
// check of §Wallet Rules "Before showing a listing" (1 to 4; step 5 is
// VersionBook.Current). It is a display state, never a wire code.
type ListingError struct {
	Step   int
	Reason string
}

func (e *ListingError) Error() string { return fmt.Sprintf("listing: step %d: %s", e.Step, e.Reason) }

func refuse(step int, format string, a ...any) error {
	return &ListingError{Step: step, Reason: fmt.Sprintf(format, a...)}
}

// exactlyOne and atMostOne are the §Offer Listing counts.
var (
	exactlyOne = []string{"d", "n", "network", "connection", "status", "expiration"}
	atMostOne  = []string{"title", "image", "p", "location", "alt", "a"}
)

// ParseListing runs §Wallet Rules "Before showing a listing" steps 1 to 4 in
// order, the first failure winning (*ListingError): 1 the kind, id, signature
// and every count; 2 the type known and connection, lowercased, of that type's
// HRP, decoded (no other string of the listing is decoded); 3 the string signed
// by TLV 4, TLV 4 = pubkey, TLV 0 = d, TLV 6 = n; 4 n held and network mainnet
// unless test networks are enabled. Unknown summary values, a hint or a tag the
// type does not take, a hint of an unknown payment kind, a non-https image and a
// g longer than MaxGeohash are dropped, not refused.
func ParseListing(ev *nip01.Event, o CheckOptions) (*Listing, error) {
	return parseListing(ev, &o)
}

// parseListing skips step 4 when o is nil (a version restored from a snapshot
// passed it when it was offered).
func parseListing(ev *nip01.Event, o *CheckOptions) (*Listing, error) {
	// Step 1.
	if ev == nil || ev.Kind != KindListing {
		return nil, refuse(1, "not a kind %d event", KindListing)
	}
	if err := ev.Verify(); err != nil {
		return nil, refuse(1, "id or signature: %v", err)
	}
	counts := map[string]int{}
	typeCounts := map[string]int{}
	hintCounts := map[string]int{}
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		counts[t[0]]++
		switch t[0] {
		case "t":
			if v := tagValue(t); v == string(TypeCashOrder) || v == string(TypeCircleWallet) {
				typeCounts[v]++
			}
		case "hint":
			hintCounts[tagValue(t)]++
		}
	}
	for _, name := range exactlyOne {
		if counts[name] != 1 {
			return nil, refuse(1, "%d %s tags, want exactly 1", counts[name], name)
		}
	}
	for _, name := range atMostOne {
		if counts[name] > 1 {
			return nil, refuse(1, "%d %s tags, want at most 1", counts[name], name)
		}
	}
	for v, n := range typeCounts {
		if n > 1 {
			return nil, refuse(1, "%d type t tags %q", n, v)
		}
	}
	for p, n := range hintCounts {
		if n > 1 {
			return nil, refuse(1, "%d hint tags for %q", n, p)
		}
	}
	l := &Listing{Event: ev, NodeIdentity: ev.PubKey, Content: ev.Content}
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		v := tagValue(t)
		switch t[0] {
		case "d":
			l.D = v
		case "n":
			l.Chain = v
		case "network":
			l.Network = v
		case "connection":
			l.Connection = v
		case "status":
			l.Status = Status(v)
		case "expiration":
			if !decimal(v) {
				return nil, refuse(1, "expiration %q is not an unsigned decimal integer", v)
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, refuse(1, "expiration %q out of range", v)
			}
			l.Expiration = n
		case "title":
			l.Title = v
		case "image":
			if httpsURL(v) {
				l.Image = v
			}
		case "location":
			l.Location = v
		case "alt":
			l.Alt = v
		case "p":
			if isHex64(v) {
				r := Ref{Pubkey: v}
				if len(t) > 2 {
					r.Relay = t[2]
				}
				l.Operator = &r
			}
		}
	}
	switch l.Status {
	case StatusOpen, StatusPaused, StatusClosed:
	default:
		return nil, refuse(1, "status %q", l.Status)
	}

	// Step 2.
	if len(typeCounts) != 1 {
		return nil, refuse(2, "type t is neither or both values")
	}
	for v := range typeCounts {
		l.Type = Type(v)
	}
	conn := strings.ToLower(l.Connection)
	l.Connection = conn
	var tlv0, tlv4, tlv6 string
	var verify func() error
	switch l.Type {
	case TypeCashOrder:
		if !strings.HasPrefix(conn, nipCO.OrderConnectionHRP+"1") {
			return nil, refuse(2, "connection is not a %s1 string", nipCO.OrderConnectionHRP)
		}
		c, err := nipCO.DecodeOrderConnection(conn)
		if err != nil {
			return nil, refuse(2, "connection does not decode")
		}
		l.Order = &c
		tlv0, tlv4, tlv6, verify = c.Pubkey, c.HubIdentity, c.Chain, c.Verify
	case TypeCircleWallet:
		if !strings.HasPrefix(conn, nipcw.CircleHubConnectionHRP+"1") {
			return nil, refuse(2, "connection is not a %s1 string", nipcw.CircleHubConnectionHRP)
		}
		c, err := nipcw.DecodeCircleHubConnection(conn)
		if err != nil {
			return nil, refuse(2, "connection does not decode")
		}
		l.Circle = &c
		tlv0, tlv4, tlv6, verify = c.Pubkey, c.HubIdentity, c.Chain, c.Verify
	}

	// Step 3.
	if err := verify(); err != nil {
		return nil, refuse(3, "connection is not signed by its hub identity")
	}
	if tlv4 != ev.PubKey {
		return nil, refuse(3, "hub identity is not the listing's pubkey")
	}
	if tlv0 != l.D {
		return nil, refuse(3, "connection pubkey is not d")
	}
	if tlv6 != l.Chain {
		return nil, refuse(3, "connection chain is not n")
	}

	// Step 4.
	if o != nil {
		if !slices.Contains(o.Chains, l.Chain) {
			return nil, refuse(4, "chain %q is not held", l.Chain)
		}
		if l.Network != nip47.NetworkMainnet && (!o.TestNetworks || !nip47.ValidNetwork(l.Network)) {
			return nil, refuse(4, "network %q", l.Network)
		}
	}

	// Ignored, not refused.
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		v := tagValue(t)
		switch t[0] {
		case "t":
			if typeTakes(l.Type, v) && !slices.Contains(l.Summary, v) {
				l.Summary = append(l.Summary, v)
			}
		case "l":
			if len(t) > 2 && t[2] == languageNamespace && v != "" {
				l.Languages = append(l.Languages, v)
			}
		case "g":
			if v != "" && len(v) <= MaxGeohash {
				l.Geohashes = append(l.Geohashes, v)
			}
		}
	}
	for _, t := range ev.Tags {
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "hint":
			if l.Type != TypeCashOrder || !knownPayment(tagValue(t)) || len(t) < 6 {
				continue
			}
			h := Hint{Payment: t[1]}
			ok := true
			for i, dst := range []*uint64{&h.MinMillis, &h.MaxMillis, &h.FeeBase, &h.FeePpm} {
				n, err := strconv.ParseUint(t[2+i], 10, 64)
				if err != nil || !decimal(t[2+i]) {
					ok = false
					break
				}
				*dst = n
			}
			if ok {
				l.Hints = append(l.Hints, h)
			}
		case "a":
			if l.Type == TypeCircleWallet && slices.Contains(l.Summary, SummaryFollowSet) {
				if k, _, _, ok := ParseAddress(tagValue(t)); ok && k == CuratorSetKind {
					l.FollowSet = tagValue(t)
				}
			}
		}
	}
	return l, nil
}

func decimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
