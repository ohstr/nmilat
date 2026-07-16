package relay

import (
	"errors"
	"testing"
)

func TestEventStore_MemberCRUD(t *testing.T) {
	store := newStore(t)

	rec, err := store.GetMember(memberA)
	if err != nil {
		t.Fatalf("GetMember() on empty store: %v", err)
	}
	if rec != nil {
		t.Fatalf("GetMember() on empty store = %+v, want nil", rec)
	}

	if err := store.PutMember(&MemberRecord{Pubkey: memberA, Roles: []string{"r1"}, JoinedAt: 100}); err != nil {
		t.Fatalf("PutMember: %v", err)
	}

	rec, err = store.GetMember(memberA)
	if err != nil {
		t.Fatalf("GetMember() after put: %v", err)
	}
	if rec == nil || rec.Pubkey != memberA || len(rec.Roles) != 1 || rec.Roles[0] != "r1" {
		t.Fatalf("GetMember() = %+v, want Pubkey=%s Roles=[r1]", rec, memberA)
	}

	pubkeys, err := store.ListMembers()
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(pubkeys) != 1 || pubkeys[0] != memberA {
		t.Fatalf("ListMembers() = %v, want [%s]", pubkeys, memberA)
	}

	if err := store.RemoveMember(memberA); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	rec, err = store.GetMember(memberA)
	if err != nil {
		t.Fatalf("GetMember() after remove: %v", err)
	}
	if rec != nil {
		t.Fatalf("GetMember() after remove = %+v, want nil", rec)
	}

	// Removing an already-absent member, or getting one that never
	// existed, is a no-op/nil-nil, not an error.
	if err := store.RemoveMember(memberB); err != nil {
		t.Fatalf("RemoveMember() on a non-member: %v", err)
	}
}

func TestEventStore_ListMembers_Multiple(t *testing.T) {
	store := newStore(t)
	for _, pk := range []string{memberA, memberB, memberC} {
		if err := store.PutMember(&MemberRecord{Pubkey: pk}); err != nil {
			t.Fatalf("PutMember(%s): %v", pk, err)
		}
	}
	got, err := store.ListMembers()
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListMembers() = %v, want 3 entries", got)
	}
}

func TestEventStore_ListMemberRecords(t *testing.T) {
	store := newStore(t)

	got, err := store.ListMemberRecords()
	if err != nil {
		t.Fatalf("ListMemberRecords() on empty store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListMemberRecords() on empty store = %+v, want empty", got)
	}

	want := map[string]*MemberRecord{
		memberA: {Pubkey: memberA, Roles: []string{"r1"}, JoinedAt: 100},
		memberB: {Pubkey: memberB, JoinedAt: 200},
	}
	for _, rec := range want {
		if err := store.PutMember(rec); err != nil {
			t.Fatalf("PutMember(%s): %v", rec.Pubkey, err)
		}
	}

	got, err = store.ListMemberRecords()
	if err != nil {
		t.Fatalf("ListMemberRecords(): %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ListMemberRecords() = %d records, want %d", len(got), len(want))
	}
	for _, rec := range got {
		w, ok := want[rec.Pubkey]
		if !ok {
			t.Fatalf("ListMemberRecords() returned unexpected pubkey %s", rec.Pubkey)
		}
		if rec.JoinedAt != w.JoinedAt || len(rec.Roles) != len(w.Roles) {
			t.Fatalf("ListMemberRecords() record for %s = %+v, want %+v", rec.Pubkey, rec, w)
		}
	}
}

func TestEventStore_InviteClaim_CRUD(t *testing.T) {
	store := newStore(t)

	claim, err := store.GetInviteClaim("unknown-code")
	if err != nil {
		t.Fatalf("GetInviteClaim() unknown: %v", err)
	}
	if claim != nil {
		t.Fatalf("GetInviteClaim() unknown = %+v, want nil", claim)
	}

	rec := &InviteClaim{Code: "abc123", CreatedAt: 100, MaxUses: 2}
	if err := store.PutInviteClaim(rec); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}

	got, err := store.GetInviteClaim("abc123")
	if err != nil {
		t.Fatalf("GetInviteClaim(): %v", err)
	}
	if got == nil || got.Code != "abc123" || got.MaxUses != 2 || got.Uses != 0 {
		t.Fatalf("GetInviteClaim() = %+v, want Code=abc123 MaxUses=2 Uses=0", got)
	}
}

func TestEventStore_ListInviteClaims(t *testing.T) {
	store := newStore(t)

	got, err := store.ListInviteClaims()
	if err != nil {
		t.Fatalf("ListInviteClaims() on empty store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListInviteClaims() on empty store = %+v, want empty", got)
	}

	for _, code := range []string{"code-a", "code-b", "code-c"} {
		if err := store.PutInviteClaim(&InviteClaim{Code: code}); err != nil {
			t.Fatalf("PutInviteClaim(%s): %v", code, err)
		}
	}

	got, err = store.ListInviteClaims()
	if err != nil {
		t.Fatalf("ListInviteClaims(): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListInviteClaims() = %v, want 3 entries", got)
	}
}

func TestEventStore_DeleteInviteClaim(t *testing.T) {
	store := newStore(t)

	// Deleting an unknown code is a no-op, not an error.
	if err := store.DeleteInviteClaim("unknown-code"); err != nil {
		t.Fatalf("DeleteInviteClaim() on unknown code: %v", err)
	}

	if err := store.PutInviteClaim(&InviteClaim{Code: "abc123"}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}
	if err := store.DeleteInviteClaim("abc123"); err != nil {
		t.Fatalf("DeleteInviteClaim: %v", err)
	}

	got, err := store.GetInviteClaim("abc123")
	if err != nil {
		t.Fatalf("GetInviteClaim() after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("GetInviteClaim() after delete = %+v, want nil", got)
	}
}

func TestEventStore_ConsumeInviteClaim(t *testing.T) {
	store := newStore(t)

	t.Run("not found", func(t *testing.T) {
		_, err := store.ConsumeInviteClaim("nope", 1000)
		if !errors.Is(err, ErrInviteClaimNotFound) {
			t.Fatalf("err = %v, want errors.Is(_, ErrInviteClaimNotFound)", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		if err := store.PutInviteClaim(&InviteClaim{Code: "expired-code", ExpiresAt: 500}); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
		_, err := store.ConsumeInviteClaim("expired-code", 1000)
		if !errors.Is(err, ErrInviteClaimExpired) {
			t.Fatalf("err = %v, want errors.Is(_, ErrInviteClaimExpired)", err)
		}
	})

	t.Run("single use, then exhausted", func(t *testing.T) {
		if err := store.PutInviteClaim(&InviteClaim{Code: "single-use", MaxUses: 1}); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
		claim, err := store.ConsumeInviteClaim("single-use", 1000)
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if claim.Uses != 1 {
			t.Fatalf("Uses = %d, want 1", claim.Uses)
		}

		_, err = store.ConsumeInviteClaim("single-use", 1000)
		if !errors.Is(err, ErrInviteClaimExhausted) {
			t.Fatalf("second consume err = %v, want errors.Is(_, ErrInviteClaimExhausted)", err)
		}
	})

	t.Run("unlimited uses", func(t *testing.T) {
		if err := store.PutInviteClaim(&InviteClaim{Code: "unlimited"}); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
		for i := range 5 {
			if _, err := store.ConsumeInviteClaim("unlimited", 1000); err != nil {
				t.Fatalf("consume #%d: %v", i, err)
			}
		}
	})

	t.Run("no expiry never expires", func(t *testing.T) {
		if err := store.PutInviteClaim(&InviteClaim{Code: "no-expiry"}); err != nil {
			t.Fatalf("PutInviteClaim: %v", err)
		}
		if _, err := store.ConsumeInviteClaim("no-expiry", 99999999999); err != nil {
			t.Fatalf("consume with no ExpiresAt set: %v", err)
		}
	})
}
