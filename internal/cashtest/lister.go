package cashtest

import (
	"maps"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/listing"
)

// Lister is the fake Hub's offer listings (NIP-CASH §Listing Offers): a listing
// of its Order connection and, with WithCircleHub, one of its circle, each built
// with listing.NewListing from the fake's own connection records and signed by
// the node identity. It retires in the §Hub Rules order: the get_info closed
// signal first, then a closed version, and a NIP-09 deletion only once the
// last open version has expired (PublishDeletions).
type Lister struct {
	h    *FakeHub
	book *OrderBook

	mu       sync.Mutex
	events   []*nip01.Event
	current  map[string]*listing.Listing
	retired  map[string]bool
	lastOpen map[string]int64
}

// ListedTitle is the title of every listing the fake publishes.
const ListedTitle = "Fake cash counter"

// ServeListings lists book's Order connection (when book is set) and the
// circle (when the fake has one), dated a minute before the clock's now.
func (h *FakeHub) ServeListings(t testing.TB, book *OrderBook) *Lister {
	t.Helper()
	l := &Lister{h: h, book: book, current: map[string]*listing.Listing{}, retired: map[string]bool{},
		lastOpen: map[string]int64{}}
	now := h.Clock.Now().Unix()
	if book != nil {
		oc := book.SignedOrderConnection(t)
		l.publish(t, listing.ListingFields{Order: &oc, Network: FakeNetwork, Summary: []string{listing.SummaryLightning},
			Title: ListedTitle, Content: "cash for tests"}, now-60, now)
	}
	if h.circle != nil {
		cc := h.SignedCircleHubConnection()
		l.publish(t, listing.ListingFields{Circle: &cc, Network: FakeNetwork, Summary: []string{listing.SummaryAllowlist},
			Title: "Fake circle"}, now-60, now)
	}
	return l
}

func (l *Lister) sign(ev *nip01.Event) error { return ev.Sign(l.h.NodePriv) }

func (l *Lister) publish(t testing.TB, f listing.ListingFields, createdAt, now int64) {
	t.Helper()
	ev, err := listing.NewListing(f, createdAt, now, l.sign)
	if err != nil {
		t.Fatalf("cashtest: list an offer: %v", err)
	}
	l.keep(t, ev)
}

func (l *Lister) keep(t testing.TB, ev *nip01.Event) {
	t.Helper()
	parsed, err := listing.ParseListing(ev, listing.CheckOptions{Chains: []string{FakeChain}, TestNetworks: true})
	if err != nil {
		t.Fatalf("cashtest: own listing does not parse: %v", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
	addr := parsed.Address()
	l.current[addr] = parsed
	if parsed.Status != listing.StatusClosed {
		l.lastOpen[addr] = parsed.ExpiresAt()
	}
}

// Listings returns every listing and deletion the fake published, in order.
func (l *Lister) Listings(_ testing.TB) []*nip01.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*nip01.Event(nil), l.events...)
}

// Retire retires the listed Order connection behind addr: get_info answers
// "cash_order": {} at once, then a closed version is published.
func (l *Lister) Retire(t testing.TB, addr string) {
	t.Helper()
	if l.book == nil {
		t.Fatalf("cashtest: no listed Order connection")
	}
	l.book.Retire()
	l.close(t, addr)
}

// CloseCircle closes the listed circle d: get_info's accepting turns false at
// once, then a closed version is published.
func (l *Lister) CloseCircle(t testing.TB, d string) {
	t.Helper()
	if l.h.circle == nil || d != l.h.circle.xonly {
		t.Fatalf("cashtest: no listed circle %s", d)
	}
	l.h.mu.Lock()
	w := maps.Clone(l.h.circle.wallet)
	l.h.mu.Unlock()
	w["accepting"] = false
	l.h.SetCircleWallet(w)
	l.close(t, listing.Address(l.h.nodeXOnly, d))
}

func (l *Lister) close(t testing.TB, addr string) {
	t.Helper()
	l.mu.Lock()
	prev, ok := l.current[addr]
	l.retired[addr] = true
	l.mu.Unlock()
	if !ok {
		t.Fatalf("cashtest: %s is not listed", addr)
	}
	ev, err := listing.ClosedListing(prev, min(prev.CreatedAt()+30, l.h.Clock.Now().Unix()), l.sign)
	if err != nil {
		t.Fatalf("cashtest: close %s: %v", addr, err)
	}
	l.keep(t, ev)
}

// PublishDeletions publishes the NIP-09 deletion of every retired address whose
// last open version has expired by the fake's clock (retirement step 3).
func (l *Lister) PublishDeletions(t testing.TB) {
	t.Helper()
	now := l.h.Clock.Now().Unix()
	l.mu.Lock()
	var due []string
	for addr := range l.retired {
		if now > l.lastOpen[addr] {
			due = append(due, addr)
			delete(l.retired, addr)
		}
	}
	l.mu.Unlock()
	for _, addr := range due {
		ev, err := listing.NewListingDeletion(addr, now, l.sign)
		if err != nil {
			t.Fatalf("cashtest: delete %s: %v", addr, err)
		}
		l.mu.Lock()
		l.events = append(l.events, ev)
		l.mu.Unlock()
	}
}
