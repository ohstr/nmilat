package client

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

// verificationCost is what one consolidate item of n sources costs the Hub.
func verificationCost(t *testing.T, n int) int {
	t.Helper()
	it := consolidateItem(t, "x", make([]bool, n)...)
	rid, err := nipcash.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	it.Params.RequestID = rid
	item, err := it.Params.Item("x", it.Bill.target, it.Bill.connSecret, nipcash.ItemBinding{HubXOnly: it.Bill.target, Nonce: it.Bill.target, NotAfter: 1})
	if err != nil {
		t.Fatal(err)
	}
	return item.VerificationCost()
}

// T11 (Consolidate across envelopes): an item over the announced
// max_consolidate_sources, or one that fits no envelope, is refused before
// anything is written or sent, wherever it sits in the batch.
func TestConsolidateMany_PerItemCap(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()

	t.Run("over max_consolidate_sources", func(t *testing.T) {
		hub := newTestHub(t, consolidateOK)
		hub.limits.MaxConsolidateSources = 2
		s, relay := openTestSession(t, hub)
		j := newTestJournal()
		_, err := s.ConsolidateMany(ctx, []BatchConsolidate{consolidateItem(t, "ok", false, false), consolidateItem(t, "big", false, false, false)}, j, "d")
		if !errors.Is(err, ErrTooManySources) || !errors.Is(err, ErrItemTooLarge) {
			t.Fatalf("err = %v, want ErrTooManySources wrapped with ErrItemTooLarge", err)
		}
		if len(j.all()) != 0 || len(requestsOn(relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("fits no envelope", func(t *testing.T) {
		hub := newTestHub(t, consolidateOK)
		hub.limits.MaxVerifyBudget = verificationCost(t, 2) // a 3-source item never fits
		s, relay := openTestSession(t, hub)
		j := newTestJournal()
		_, err := s.ConsolidateMany(ctx, []BatchConsolidate{consolidateItem(t, "ok", false, false), consolidateItem(t, "big", false, false, false)}, j, "d")
		if !errors.Is(err, ErrItemTooLarge) || errors.Is(err, ErrTooManySources) {
			t.Fatalf("err = %v, want ErrItemTooLarge alone", err)
		}
		if len(j.all()) != 0 || len(requestsOn(relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("items that fit alone still split", func(t *testing.T) {
		hub := newTestHub(t, consolidateOK)
		hub.limits.MaxVerifyBudget = verificationCost(t, 2)
		s, _ := openTestSession(t, hub)
		out, err := s.ConsolidateMany(ctx, []BatchConsolidate{consolidateItem(t, "a", false, false), consolidateItem(t, "b", false, false)}, newTestJournal(), "d")
		if err != nil || len(out) != 2 || !out[0].Succeeded() || !out[1].Succeeded() {
			t.Fatalf("(%+v, %v)", out, err)
		}
		if n := len(hub.envelopes()); n != 2 {
			t.Fatalf("%d envelopes, want 2", n)
		}
	})
}
