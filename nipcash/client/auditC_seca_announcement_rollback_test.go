package client

// Session C, Security Auditor A — forged discovery, the freshness half.
//
// ParseAnnouncement verifies the AUTHOR and the SIGNATURE and stops there. It never
// looks at created_at, and BatchSession.Refresh takes the first event that parses in
// whatever order the relay served them. Kind 11190 is replaceable, so a hub has
// exactly one CURRENT announcement — but every announcement it has ever published
// stays a valid signed event forever, and a relay chooses which one a client sees.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// datedAnnouncement builds a real, signed kind-11190 with a chosen created_at.
// Sign recomputes the id from the serialization, so backdating is genuine rather
// than a tampered field.
func datedAnnouncement(t *testing.T, hubPriv, hubXOnly, inbox string, at time.Time) *nip01.Event {
	t.Helper()
	ev, err := transport.NewAnnouncement(hubXOnly, inbox, transport.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt = uint64(at.Unix())
	if err := ev.Sign(hubPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ParseAnnouncement(ev, hubXOnly); err != nil {
		t.Fatalf("backdated announcement must still be valid: %v", err)
	}
	return ev
}

// TestAuditC_SecA_StaleAnnouncementWinsOnRelayOrder: both announcements are
// genuinely the hub's. The relay serves the retired one first, and the client
// adopts the retired inbox key.
func TestAuditC_SecA_StaleAnnouncementWinsOnRelayOrder(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, retiredInbox := sessionKeypair(t)
	_, currentInbox := sessionKeypair(t)

	old := datedAnnouncement(t, hubPriv, hubXOnly, retiredInbox, time.Now().Add(-90*24*time.Hour))
	cur := datedAnnouncement(t, hubPriv, hubXOnly, currentInbox, time.Now())

	// A hostile relay's freedom is entirely in this ordering.
	relay := newAnnouncementRelay(t, func() []*nip01.Event {
		return []*nip01.Event{old, cur}
	})

	c := &Client{}
	s, err := c.NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}
	t.Logf("adopted inbox=%s (retired=%s current=%s)", s.Inbox(), retiredInbox, currentInbox)
	t.Logf("old created_at=%d, current created_at=%d", old.CreatedAt, cur.CreatedAt)

	if s.Inbox() == retiredInbox {
		t.Errorf("AUDITC-SECA-F1 BUG PRESENT: the relay served a 90-day-old announcement "+
			"before the current one and the client adopted the RETIRED inbox key. "+
			"ParseAnnouncement takes no created_at into account and Refresh returns on the "+
			"first event that parses, so ordering is the relay's choice. Whoever holds the "+
			"retired inbox private key decrypts every envelope this session sends.")
	}
	if s.Inbox() != currentInbox {
		t.Errorf("Inbox() = %q, want the newest announcement's inbox %q", s.Inbox(), currentInbox)
	}
}

// TestAuditC_SecA_RefreshRollsBackToARetiredAnnouncement is the attack rather than
// the race: a session that ALREADY holds the current announcement is walked
// backwards onto a retired one.
//
// Refresh is triggered by isStalePolicy — an over-limit or over-budget rejection,
// which is itself something a hub can provoke by announcing tighter limits. So the
// attacker does not need to win a startup race; it needs the client to refresh once.
func TestAuditC_SecA_RefreshRollsBackToARetiredAnnouncement(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, retiredInbox := sessionKeypair(t)
	_, currentInbox := sessionKeypair(t)

	old := datedAnnouncement(t, hubPriv, hubXOnly, retiredInbox, time.Now().Add(-90*24*time.Hour))
	cur := datedAnnouncement(t, hubPriv, hubXOnly, currentInbox, time.Now())

	var mu sync.Mutex
	serving := []*nip01.Event{cur}
	relay := newAnnouncementRelay(t, func() []*nip01.Event {
		mu.Lock()
		defer mu.Unlock()
		return serving
	})

	c := &Client{}
	s, err := c.NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}
	if s.Inbox() != currentInbox {
		t.Fatalf("setup: Inbox() = %q, want %q", s.Inbox(), currentInbox)
	}

	// The relay now withholds the current announcement and offers only the retired
	// one. Nothing was forged: it is the hub's own signature over the hub's own
	// earlier policy.
	mu.Lock()
	serving = []*nip01.Event{old}
	mu.Unlock()

	if err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	t.Logf("after refresh: inbox=%s", s.Inbox())

	if s.Inbox() == retiredInbox {
		t.Errorf("AUDITC-SECA-F1 BUG PRESENT: Refresh walked a session that held the CURRENT "+
			"announcement (created_at %d) back onto one from 90 days earlier (created_at %d). "+
			"There is no monotonicity check: batch_session.go:117-125 adopts any announcement "+
			"that parses. keys.go documents inbox rotation as the only remedy for a leaked "+
			"inbox key — this is why that remedy cannot work against a relay.",
			cur.CreatedAt, old.CreatedAt)
	}
}
