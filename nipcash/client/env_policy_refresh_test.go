package client

import (
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// staleAnnouncement is hub's announcement with limits, signed by its node key.
func staleAnnouncement(t *testing.T, hub *fakeHub, limits transport.Limits, relays []string) *transport.Announcement {
	t.Helper()
	ev, err := transport.NewAnnouncement(hub.hubXOnly, hub.inboxXOnly, limits, relays)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Sign(hub.hubPriv); err != nil {
		t.Fatal(err)
	}
	a, err := transport.ParseAnnouncement(ev, hub.hubXOnly)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func withMaxItems(n int) transport.Limits {
	l := transport.DefaultLimits()
	l.MaxItems = n
	return l
}

func statusItems(t *testing.T, n int) []BatchStatus {
	t.Helper()
	items := make([]BatchStatus, n)
	for i := range items {
		priv, target := sessionKeypair(t)
		items[i] = BatchStatus{Bill: mustBill(t, target), Credential: nipcash.BySigning(priv)}
	}
	return items
}

// E-ENV-04, T11-20 (S-CASH-134): the client holds a stale copy announcing
// max_items 20 while the Hub announces and enforces 10. Fifteen items packed
// as one envelope are refused whole with QUOTA_EXCEEDED (nothing ran); the
// client re-reads the announcement and sends them as two envelopes, once.
func TestEENV04_PolicyRefusalRefreshesAndRepacks(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.limits = withMaxItems(10)
	s, relay := openTestSession(t, hub)
	s.mu.Lock()
	s.announcement = staleAnnouncement(t, hub, withMaxItems(20), []string{relay.URL()})
	s.mu.Unlock()

	ctx, cancel := e2eContext(t)
	defer cancel()
	out, err := s.StatusMany(ctx, statusItems(t, 15))
	if err != nil || len(out) != 15 {
		t.Fatalf("StatusMany: %d outcomes, %v", len(out), err)
	}
	for _, o := range out {
		if o.State != OutcomeResult {
			t.Fatalf("item %s: %v %+v", o.ID, o.State, o.Error)
		}
	}
	envs := hub.envelopes()
	if len(envs) != 2 || len(envs[0].Items) != 10 || len(envs[1].Items) != 5 {
		t.Fatalf("served envelopes %d, want two of 10 and 5", len(envs))
	}
	if s.Limits().MaxItems != 10 {
		t.Fatalf("cached max_items %d after refresh, want 10", s.Limits().MaxItems)
	}
}

// T11-20: a policy refusal the Hub's current announcement does not explain
// (the refreshed copy is the one already held) is not resent: every item
// carries the refusal.
func TestT11_20_UnchangedPolicyIsNotResent(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.limits = withMaxItems(10)
	s, relay := openTestSession(t, hub)
	// The relay now serves a newer copy announcing 20, which the Hub does not
	// enforce: a refresh learns nothing new.
	stale := staleAnnouncement(t, hub, withMaxItems(20), []string{relay.URL()})
	ev, err := transport.NewAnnouncement(hub.hubXOnly, hub.inboxXOnly, withMaxItems(20), []string{relay.URL()})
	if err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt++
	if err := ev.Sign(hub.hubPriv); err != nil {
		t.Fatal(err)
	}
	if ok, msg := relay.Publish(ev); !ok {
		t.Fatal(msg)
	}
	s.mu.Lock()
	s.announcement = stale
	s.mu.Unlock()

	ctx, cancel := e2eContext(t)
	defer cancel()
	out, _ := s.StatusMany(ctx, statusItems(t, 15))
	if len(out) != 15 {
		t.Fatalf("%d outcomes", len(out))
	}
	for _, o := range out {
		if o.State != OutcomeError || o.Error == nil || o.Error.Code != nipcash.ErrCodeQuotaExceeded {
			t.Fatalf("item %s: %v %+v, want QUOTA_EXCEEDED", o.ID, o.State, o.Error)
		}
	}
	if n := len(hub.envelopes()); n != 0 {
		t.Fatalf("the Hub served %d envelopes, want none", n)
	}
}

// T11-20, M4: calls carrying a request_id refused whole are never resent under
// the same ids (NIP-CASH §Errors), even when a refresh shows a changed policy:
// each keeps the envelope's refusal as its outcome, written ahead once.
func TestT11_20_RefusedRequestIDsAreNotResent(t *testing.T) {
	hub := newTestHub(t, alwaysSucceed)
	hub.limits = withMaxItems(2)
	s, relay := openTestSession(t, hub)
	s.mu.Lock()
	s.announcement = staleAnnouncement(t, hub, withMaxItems(20), []string{relay.URL()})
	s.mu.Unlock()

	items := make([]BatchTransfer, 3)
	for i := range items {
		priv, target := sessionKeypair(t)
		items[i] = BatchTransfer{Bill: mustBill(t, target), Params: nipcash.CashTransferParams{
			Credential: nipcash.BySigning(priv), To: mustCashTarget(t), CurrentAmount: 1000}}
	}
	j := newTestJournal()
	ctx, cancel := e2eContext(t)
	defer cancel()
	out, _ := s.TransferMany(ctx, items, j, "dev")
	if len(out) != 3 {
		t.Fatalf("%d outcomes", len(out))
	}
	if n := len(hub.envelopes()); n != 0 {
		t.Fatalf("the Hub served %d envelopes, want none", n)
	}
	for _, o := range out {
		if o.State != OutcomeError || o.Error == nil || o.Error.Code != nipcash.ErrCodeQuotaExceeded {
			t.Fatalf("item %s: %v %+v, want QUOTA_EXCEEDED", o.ID, o.State, o.Error)
		}
		if j.writes[o.RequestID] != 1 {
			t.Errorf("%s written ahead %d times, want 1 (never resent under its id)", o.RequestID, j.writes[o.RequestID])
		}
	}
}
