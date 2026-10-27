package listing

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rivo/uniseg"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcw"
)

var (
	// ErrNotListable is a listing without exactly one of an Order connection or
	// a circle's Circle Wallet Hub connection.
	ErrNotListable = errors.New("listing: list exactly one Order connection or Circle Wallet Hub connection")
	// ErrPostDated is a created_at after now.
	ErrPostDated = errors.New("listing: created_at is in the future")
	// ErrExpiryTooFar is an expiration more than MaxExpirySecs after created_at.
	ErrExpiryTooFar = errors.New("listing: expiration is more than 30 days ahead")
	// ErrGeohashPrecision is a g the builder will not write: a lister gives 3 or
	// 4 characters.
	ErrGeohashPrecision = errors.New("listing: a geohash must have 3 or 4 characters")
	// ErrListingField is any other field the builder refuses.
	ErrListingField = errors.New("listing: invalid field")
	// ErrWrongSigner is an event signed by another key than it must be (the
	// listing by TLV 4, a deletion by the address's node identity).
	ErrWrongSigner = errors.New("listing: signed by the wrong key")
)

// ListingFields are what a Hub lists. Exactly one of Order or Circle, from the
// Hub's own records (never from pasted text). Network is what the Hub's
// get_info reports. Status defaults to open, Expiration to createdAt +
// MaxExpirySecs. Hints are cash_order only, one per payment kind sold, from the
// Hub's terms; FollowSet only for a follow_set circle.
type ListingFields struct {
	Order   *nipCO.OrderConnection
	Circle  *nipcw.CircleHubConnection
	Network string
	Summary []string
	// Title and Location are plain text; Location is one line of at most
	// MaxTitle grapheme clusters with no link. Image is an https URL.
	Title, Image, Content string
	Location              string
	Operator              *Ref
	Status                Status
	Expiration            int64
	Hints                 []Hint
	FollowSet             string
	// Languages are ISO-639-1 codes; Geohashes have 3 or 4 characters.
	Languages, Geohashes []string
}

// NewListing builds and signs a kind-31190 listing (NIP-CASH §Offer Listing,
// §Hub Rules), tags in the NIP example's order. The connection must verify
// (nipcash.ErrConnUnverified otherwise) and sign must sign with its TLV 4,
// which becomes the event's pubkey; d is TLV 0 and n TLV 6. createdAt after now
// is ErrPostDated. sign receives the event with PubKey set to TLV 4 and sets
// its id and signature.
func NewListing(f ListingFields, createdAt, now int64, sign func(*nip01.Event) error) (*nip01.Event, error) {
	if (f.Order == nil) == (f.Circle == nil) {
		return nil, ErrNotListable
	}
	if createdAt > now {
		return nil, ErrPostDated
	}
	var (
		typ                         Type
		d, identity, chain, encoded string
		err                         error
	)
	if f.Order != nil {
		if err = f.Order.Verify(); err != nil {
			return nil, fmt.Errorf("listing: Order connection: %w", err)
		}
		typ, d, identity, chain = TypeCashOrder, f.Order.Pubkey, f.Order.HubIdentity, f.Order.Chain
		encoded, err = nipCO.EncodeOrderConnection(*f.Order)
	} else {
		if err = f.Circle.Verify(); err != nil {
			return nil, fmt.Errorf("listing: Circle Wallet Hub connection: %w", err)
		}
		typ, d, identity, chain = TypeCircleWallet, f.Circle.Pubkey, f.Circle.HubIdentity, f.Circle.Chain
		encoded, err = nipcw.EncodeCircleHubConnection(*f.Circle)
	}
	if err != nil {
		return nil, fmt.Errorf("listing: encode the connection: %w", err)
	}
	if !nip47.ValidNetwork(f.Network) {
		return nil, fmt.Errorf("%w: network %q", ErrListingField, f.Network)
	}
	status := f.Status
	if status == "" {
		status = StatusOpen
	}
	if status != StatusOpen && status != StatusPaused && status != StatusClosed {
		return nil, fmt.Errorf("%w: status %q", ErrListingField, status)
	}
	expiration := f.Expiration
	if expiration == 0 {
		expiration = createdAt + MaxExpirySecs
	}
	if expiration > createdAt+MaxExpirySecs {
		return nil, ErrExpiryTooFar
	}
	if expiration <= createdAt {
		return nil, fmt.Errorf("%w: expiration %d is not after created_at", ErrListingField, expiration)
	}

	tags := [][]string{{"d", d}, {"t", string(typ)}}
	for i, s := range f.Summary {
		if !typeTakes(typ, s) || slices.Contains(f.Summary[:i], s) {
			return nil, fmt.Errorf("%w: summary %q for %s", ErrListingField, s, typ)
		}
		tags = append(tags, []string{"t", s})
	}
	tags = append(tags, []string{"n", chain}, []string{"network", f.Network}, []string{"connection", encoded})
	if f.Title != "" {
		tags = append(tags, []string{"title", f.Title})
	}
	if f.Image != "" {
		if !httpsURL(f.Image) {
			return nil, fmt.Errorf("%w: image is not an https URL", ErrListingField)
		}
		tags = append(tags, []string{"image", f.Image})
	}
	if f.Operator != nil {
		if !isHex64(f.Operator.Pubkey) {
			return nil, fmt.Errorf("%w: operator pubkey", ErrListingField)
		}
		tags = append(tags, refTag("p", *f.Operator))
	}
	tags = append(tags, []string{"status", string(status)},
		[]string{"expiration", strconv.FormatInt(expiration, 10)})
	if len(f.Hints) > 0 && typ != TypeCashOrder {
		return nil, fmt.Errorf("%w: hint on a %s listing", ErrListingField, typ)
	}
	for i, h := range f.Hints {
		if !knownPayment(h.Payment) || slices.ContainsFunc(f.Hints[:i], func(o Hint) bool { return o.Payment == h.Payment }) {
			return nil, fmt.Errorf("%w: hint %q", ErrListingField, h.Payment)
		}
		tags = append(tags, []string{"hint", h.Payment, u(h.MinMillis), u(h.MaxMillis), u(h.FeeBase), u(h.FeePpm)})
	}
	if len(f.Languages) > 0 {
		tags = append(tags, []string{"L", languageNamespace})
		for _, l := range f.Languages {
			if !isLanguage(l) {
				return nil, fmt.Errorf("%w: language %q", ErrListingField, l)
			}
			tags = append(tags, []string{"l", l, languageNamespace})
		}
	}
	for _, g := range f.Geohashes {
		if len(g) != 3 && len(g) != 4 {
			return nil, ErrGeohashPrecision
		}
		if !isGeohash(g) {
			return nil, fmt.Errorf("%w: geohash %q", ErrListingField, g)
		}
		tags = append(tags, []string{"g", g})
	}
	if f.Location != "" {
		if strings.ContainsAny(f.Location, "\r\n\t\u0085\u2028\u2029") || uniseg.GraphemeClusterCount(f.Location) > MaxTitle ||
			strings.Contains(f.Location, "://") {
			return nil, fmt.Errorf("%w: location must be one line of at most %d characters with no link", ErrListingField, MaxTitle)
		}
		tags = append(tags, []string{"location", f.Location})
	}
	if f.FollowSet != "" {
		if typ != TypeCircleWallet || !slices.Contains(f.Summary, SummaryFollowSet) {
			return nil, fmt.Errorf("%w: an a tag is for a follow_set circle only", ErrListingField)
		}
		if k, _, _, ok := ParseAddress(f.FollowSet); !ok || k != CuratorSetKind {
			return nil, fmt.Errorf("%w: follow set address", ErrListingField)
		}
		tags = append(tags, []string{"a", f.FollowSet})
	}
	alt := "Cash offer"
	if f.Title != "" {
		alt += ": " + f.Title
	}
	tags = append(tags, []string{"alt", alt})

	ev := &nip01.Event{Kind: KindListing, PubKey: identity, CreatedAt: uint64(createdAt), Tags: tags, Content: f.Content}
	return signAs(ev, identity, sign)
}

// ClosedListing republishes prev with status closed at createdAt, every other
// tag and the content kept (§Hub Rules, retirement step 2). createdAt must be
// after prev's.
func ClosedListing(prev *Listing, createdAt int64, sign func(*nip01.Event) error) (*nip01.Event, error) {
	if prev == nil || prev.Event == nil {
		return nil, fmt.Errorf("%w: no listing", ErrListingField)
	}
	if createdAt <= prev.CreatedAt() {
		return nil, fmt.Errorf("%w: created_at must be after the listing's", ErrListingField)
	}
	ev := prev.Event.Copy()
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "status" {
			t[1] = string(StatusClosed)
		}
	}
	ev.CreatedAt, ev.ID, ev.Sig = uint64(createdAt), "", ""
	return signAs(ev, prev.NodeIdentity, sign)
}

// NewListingDeletion builds and signs the NIP-09 deletion of a listing address
// (§Hub Rules, retirement step 3): ["a", addr], ["k", "31190"], signed by the
// address's node identity.
func NewListingDeletion(addr string, createdAt int64, sign func(*nip01.Event) error) (*nip01.Event, error) {
	k, pubkey, _, ok := ParseAddress(addr)
	if !ok || k != KindListing {
		return nil, fmt.Errorf("%w: listing address", ErrListingField)
	}
	ev := &nip01.Event{Kind: kindDeletion, PubKey: pubkey, CreatedAt: uint64(createdAt),
		Tags: [][]string{{"a", addr}, {"k", strconv.Itoa(KindListing)}}}
	return signAs(ev, pubkey, sign)
}

func signAs(ev *nip01.Event, want string, sign func(*nip01.Event) error) (*nip01.Event, error) {
	if sign == nil {
		return nil, fmt.Errorf("listing: no signer")
	}
	if err := sign(ev); err != nil {
		return nil, fmt.Errorf("listing: sign: %w", err)
	}
	if ev.PubKey != want {
		return nil, fmt.Errorf("%w: %s, want %s", ErrWrongSigner, ev.PubKey, want)
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("listing: signed event: %w", err)
	}
	return ev, nil
}

func refTag(name string, r Ref) []string {
	if r.Relay == "" {
		return []string{name, r.Pubkey}
	}
	return []string{name, r.Pubkey, r.Relay}
}

func u(v uint64) string { return strconv.FormatUint(v, 10) }

func httpsURL(s string) bool {
	p, err := url.Parse(s)
	return err == nil && p.Scheme == "https" && p.Host != ""
}

func isLanguage(s string) bool {
	return len(s) == 2 && s[0] >= 'a' && s[0] <= 'z' && s[1] >= 'a' && s[1] <= 'z'
}

const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

func isGeohash(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(geohashAlphabet, s[i]) < 0 {
			return false
		}
	}
	return s != ""
}
