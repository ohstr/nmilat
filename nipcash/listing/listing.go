package listing

import (
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcw"
)

// Event kinds of NIP-CASH §Listing Offers.
const (
	// KindListing is an offer listing, addressable, signed by the node identity.
	KindListing = 31190
	// KindOperatorOffers is the operator's offers, a NIP-51 standard list.
	KindOperatorOffers = 11191
	// KindRecommendation is a recommendation of one node's offers.
	KindRecommendation = 31191
	// KindReport is a NIP-56 report.
	KindReport = 1984
	// kindDeletion is NIP-09's deletion request.
	kindDeletion = 5
)

// Curators and reports.
const (
	// CuratorSetKind is the NIP-51 follow set that holds a user's curators.
	CuratorSetKind = 30000
	// CuratorSetD is the curator set's d tag.
	CuratorSetD = "cash-discover"
	// ReportNamespace is the NIP-32 namespace of a report's label.
	ReportNamespace = "cash.report"
)

// Numbers of §Wallet Rules and §Hub Rules.
const (
	// MaxExpirySecs caps a listing's life: it expires at
	// min(expiration, created_at + MaxExpirySecs) whatever it says (30 days).
	MaxExpirySecs = 2592000
	// MaxSkewSecs is how far ahead of the wallet's clock a version may be
	// dated (15 minutes); a later one is ignored.
	MaxSkewSecs = 900
	// StaleAfterSecs is the age past which a listing ranks lower (10 days).
	StaleAfterSecs = 864000
	// MaxTitle caps title, location and the string's label, in grapheme
	// clusters (SanitizeText).
	MaxTitle = 40
	// MaxContent caps content, in grapheme clusters.
	MaxContent = 280
	// MaxGeohash is the longest g a wallet reads; a longer one is ignored.
	MaxGeohash = 5
)

// Type is a listing's type t.
type Type string

// The two listing types.
const (
	TypeCashOrder    Type = "cash_order"
	TypeCircleWallet Type = "circle_wallet"
)

// Status is a listing's status tag.
type Status string

// The three statuses. A wallet shows open and paused listings only.
const (
	StatusOpen   Status = "open"
	StatusPaused Status = "paused"
	StatusClosed Status = "closed"
)

// Summary values a listing's type takes (display and filtering only, never
// terms).
const (
	SummaryLightning = "lightning"
	SummaryOnchain   = "onchain"
	SummaryAllowlist = "allowlist"
	SummaryFollowSet = "follow_set"
)

// languageNamespace is the NIP-32 namespace of a listing's language labels.
const languageNamespace = "ISO-639-1"

// Ref is a pubkey (or, in OperatorOffers.Offers, an address) with a relay hint.
type Ref struct{ Pubkey, Relay string }

// Hint is one hint tag: a payment kind and the NIP-CO terms numbers as listed.
// It is shown as listed, never as terms.
type Hint struct {
	Payment                               string
	MinMillis, MaxMillis, FeeBase, FeePpm uint64
}

// Listing is a kind-31190 event that passed ParseListing (steps 1 to 4). Title,
// Location, Content and the connection's label are the lister's raw claims:
// display them through SanitizeText.
type Listing struct {
	Event *nip01.Event
	// NodeIdentity is the event's pubkey, which equals the string's TLV 4.
	NodeIdentity string
	// D is the d tag, which equals the string's TLV 0.
	D    string
	Type Type
	// Summary holds the known summary values of the type only.
	Summary []string
	// Chain is n, which equals the string's TLV 6.
	Chain, Network string
	// Connection is the connection string, lowercased.
	Connection string
	// Order is set for a cash_order listing, Circle for a circle_wallet one.
	Order  *nipCO.OrderConnection
	Circle *nipcw.CircleHubConnection
	// Image is set only for an https URL.
	Title, Image, Content string
	// Location is a display label for the place; Geohashes are the g values of
	// at most MaxGeohash characters. Show a place no more precisely than them.
	Location string
	// Operator is the p tag: who the listing says runs it. It proves nothing
	// until OperatorVerified.
	Operator   *Ref
	Status     Status
	Expiration int64
	// Hints are cash_order only, of a known payment kind.
	Hints []Hint
	// FollowSet is the a tag of a follow_set circle.
	FollowSet string
	// Languages are the ISO-639-1 l values.
	Languages, Geohashes []string
	Alt                  string
}

// CreatedAt is the event's created_at.
func (l *Listing) CreatedAt() int64 { return int64(l.Event.CreatedAt) }

// Address is the listing's address, "31190:<pubkey>:<d>".
func (l *Listing) Address() string { return Address(l.NodeIdentity, l.D) }

// ExpiresAt is min(expiration, created_at + MaxExpirySecs): the cap applies
// whatever the listing says.
func (l *Listing) ExpiresAt() int64 { return min(l.Expiration, l.CreatedAt()+MaxExpirySecs) }

// Address builds a listing address from a node identity and a d.
func Address(nodeIdentity, d string) string {
	return strconv.Itoa(KindListing) + ":" + nodeIdentity + ":" + d
}

// ParseAddress splits an address "<kind>:<pubkey>:<d>" whose pubkey is 64
// lowercase hex.
func ParseAddress(addr string) (kind int, pubkey, d string, ok bool) {
	k, rest, found := strings.Cut(addr, ":")
	if !found {
		return 0, "", "", false
	}
	pubkey, d, found = strings.Cut(rest, ":")
	if !found || !isHex64(pubkey) {
		return 0, "", "", false
	}
	n, err := strconv.Atoi(k)
	if err != nil || strconv.Itoa(n) != k {
		return 0, "", "", false
	}
	return n, pubkey, d, true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func tagValue(t []string) string {
	if len(t) < 2 {
		return ""
	}
	return t[1]
}

func hasTag(ev *nip01.Event, name, value string) bool {
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == name && t[1] == value {
			return true
		}
	}
	return false
}

func typeTakes(typ Type, summary string) bool {
	switch typ {
	case TypeCashOrder:
		return summary == SummaryLightning || summary == SummaryOnchain
	case TypeCircleWallet:
		return summary == SummaryAllowlist || summary == SummaryFollowSet
	}
	return false
}

func knownPayment(p string) bool { return p == nipCO.PaymentLightning || p == nipCO.PaymentOnchain }
