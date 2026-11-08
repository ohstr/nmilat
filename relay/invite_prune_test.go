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
