package cashtest_test

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash/listing"
)

// T02-13: the fake lists from its own records and deletes a retired listing
// only after its last open version expired.
func TestListerRetireThenDelete(t *testing.T) {
	clock := cashtest.NewManualClock(time.Now())
	hub := cashtest.NewFakeHub(t, cashtest.WithClock(clock), cashtest.WithCircleHub())
	book := hub.ServeOrders(t, `{}`)
	l := hub.ServeListings(t, book)
	evs := l.Listings(t)
	if len(evs) != 2 {
		t.Fatalf("%d listings", len(evs))
	}
	opts := listing.CheckOptions{Chains: []string{cashtest.FakeChain}, TestNetworks: true}
	first, err := listing.ParseListing(evs[0], opts)
	if err != nil || first.Type != listing.TypeCashOrder || first.Title != cashtest.ListedTitle {
		t.Fatalf("order listing = %+v (%v)", first, err)
	}
	l.Retire(t, first.Address())
	l.PublishDeletions(t)
	if n := len(l.Listings(t)); n != 3 {
		t.Fatalf("%d events after retiring, want the closed version only", n)
	}
	clock.Advance(31 * 24 * time.Hour)
	l.PublishDeletions(t)
	evs = l.Listings(t)
	del := evs[len(evs)-1]
	if del.Kind != 5 || int64(del.CreatedAt) <= first.ExpiresAt() {
		t.Fatalf("deletion = %+v", del)
	}
	book2 := listing.NewVersionBook()
	book2.ApplyDeletion(del)
	if book2.Offer(first, int64(del.CreatedAt)) {
		t.Fatal("the deleted listing is offered")
	}
}
