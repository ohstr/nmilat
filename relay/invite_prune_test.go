package relay

import (
	"strings"
	"testing"
	"time"
)

func TestMembershipService_IssueInvitePrunesExpiredClaims(t *testing.T) {
	store := newStore(t)
	now := time.Now().Unix()
	if err := store.PutInviteClaim(&InviteClaim{Code: "old", ExpiresAt: now - 10}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}
	if err := store.PutInviteClaim(&InviteClaim{Code: "forever"}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}
	m := NewMembershipService(store)
	rec, err := m.IssueInvite(time.Hour, 0, nil)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	for code, want := range map[string]bool{"old": false, "forever": true, rec.Code: true} {
		got, err := store.GetInviteClaim(code)
		if err != nil {
			t.Fatalf("GetInviteClaim(%q): %v", code, err)
		}
		if (got != nil) != want {
			t.Fatalf("claim %q present = %v, want %v", code, got != nil, want)
		}
	}
}

// A sweep that finds nothing expired writes nothing, so issuing a code
// costs one write transaction, not two.
func TestEventStore_PruneExpiredInviteClaimsWritesOnlyWhenExpired(t *testing.T) {
	store := newStore(t)
	now := time.Now().Unix()
	for _, c := range []*InviteClaim{{Code: "live", ExpiresAt: now + 100}, {Code: "never"}} {
		if err := store.PutInviteClaim(c); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
	}
	writes := func() int64 { s := store.db.Stats(); return s.TxStats.GetWrite() }

	before := writes()
	if removed, _, err := store.PruneExpiredInviteClaims(now, "", 0); err != nil || removed != 0 {
		t.Fatalf("sweep = %d, %v; want 0", removed, err)
	}
	if got := writes(); got != before {
		t.Fatalf("a sweep with nothing expired wrote %d times", got-before)
	}

	m := NewMembershipService(store)
	before = writes()
	if _, err := m.IssueInvite(time.Hour, 0, nil); err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	issued := writes() - before
	if err := store.PutInviteClaim(&InviteClaim{Code: "baseline", ExpiresAt: time.Now().Unix() + 3600}); err != nil {
		t.Fatal(err)
	}
	if one := writes() - before - issued; issued != one {
		t.Fatalf("IssueInvite with nothing expired cost %d writes, one PutInviteClaim %d", issued, one)
	}

	if err := store.PutInviteClaim(&InviteClaim{Code: "old", ExpiresAt: now - 1}); err != nil {
		t.Fatal(err)
	}
	before = writes()
	if removed, _, err := store.PruneExpiredInviteClaims(now, "", 0); err != nil || removed != 1 {
		t.Fatalf("sweep = %d, %v; want 1", removed, err)
	}
	if writes() == before {
		t.Fatal("a sweep that deleted a claim wrote nothing")
	}
}

func TestEventStore_PruneExpiredInviteClaims(t *testing.T) {
	store := newStore(t)
	const now = 1000
	for _, c := range []*InviteClaim{
		{Code: "a-expired", ExpiresAt: now - 1},
		{Code: "b-live", ExpiresAt: now + 100},
		{Code: "c-expired", ExpiresAt: now - 500},
		{Code: "d-never", ExpiresAt: 0},
		{Code: "e-expired", ExpiresAt: 1},
	} {
		if err := store.PutInviteClaim(c); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
	}

	// Two claims per call: the cursor walks the bucket, then comes back "".
	removed, next, err := store.PruneExpiredInviteClaims(now, "", 2)
	if err != nil || removed != 1 || next != "b-live" {
		t.Fatalf("first sweep = %d, %q, %v; want 1, b-live", removed, next, err)
	}
	removed, next, err = store.PruneExpiredInviteClaims(now, next, 2)
	if err != nil || removed != 1 || next != "d-never" {
		t.Fatalf("second sweep = %d, %q, %v; want 1, d-never", removed, next, err)
	}
	removed, next, err = store.PruneExpiredInviteClaims(now, next, 2)
	if err != nil || removed != 1 || next != "" {
		t.Fatalf("third sweep = %d, %q, %v; want 1, \"\"", removed, next, err)
	}

	claims, err := store.ListInviteClaims()
	if err != nil {
		t.Fatalf("ListInviteClaims: %v", err)
	}
	var codes []string
	for _, c := range claims {
		codes = append(codes, c.Code)
	}
	if strings.Join(codes, ",") != "b-live,d-never" {
		t.Fatalf("claims left = %v, want [b-live d-never]", codes)
	}

	if removed, next, err := store.PruneExpiredInviteClaims(now, "", 0); err != nil || removed != 0 || next != "" {
		t.Fatalf("unbounded sweep = %d, %q, %v; want 0, \"\"", removed, next, err)
	}
}
