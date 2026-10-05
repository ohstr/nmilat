package relay

import (
	"errors"
	"testing"
)

const (
	groupA = "group-a"
	groupB = "group-b"
	groupC = "group-c"
)

func TestEventStore_GroupCRUD(t *testing.T) {
	store := newStore(t)

	rec, err := store.GetGroup(groupA)
	if err != nil {
		t.Fatalf("GetGroup() on empty store: %v", err)
	}
	if rec != nil {
		t.Fatalf("GetGroup() on empty store = %+v, want nil", rec)
	}

	want := &GroupRecord{
		ID:        groupA,
		Metadata:  GroupMetadataFields{Private: true, Closed: true},
		Members:   []GroupMember{{Pubkey: memberA, Roles: []string{"admin"}}},
		CreatedAt: 100,
	}
	if err := store.PutGroup(want); err != nil {
		t.Fatalf("PutGroup: %v", err)
	}

	rec, err = store.GetGroup(groupA)
	if err != nil {
		t.Fatalf("GetGroup() after put: %v", err)
	}
	if rec == nil || rec.ID != groupA || !rec.Metadata.Private || len(rec.Members) != 1 || rec.Members[0].Pubkey != memberA {
		t.Fatalf("GetGroup() = %+v, want %+v", rec, want)
	}

	records, err := store.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(records) != 1 || records[0].ID != groupA {
		t.Fatalf("ListGroups() = %+v, want [%s]", records, groupA)
	}

	if err := store.DeleteGroup(groupA); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	rec, err = store.GetGroup(groupA)
	if err != nil {
		t.Fatalf("GetGroup() after delete: %v", err)
	}
	if rec != nil {
		t.Fatalf("GetGroup() after delete = %+v, want nil", rec)
	}

	// Deleting an already-absent group, or getting one that never existed,
	// is a no-op/nil-nil, not an error.
	if err := store.DeleteGroup(groupB); err != nil {
		t.Fatalf("DeleteGroup() on a non-existent group: %v", err)
	}
}

func TestEventStore_ListGroups_Multiple(t *testing.T) {
	store := newStore(t)
	for _, id := range []string{groupA, groupB, groupC} {
		if err := store.PutGroup(&GroupRecord{ID: id}); err != nil {
			t.Fatalf("PutGroup(%s): %v", id, err)
		}
	}
	got, err := store.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListGroups() = %+v, want 3 entries", got)
	}
}

func TestGroupRecord_IsAdminIsMember(t *testing.T) {
	rec := &GroupRecord{Members: []GroupMember{
		{Pubkey: memberA, Roles: []string{"admin"}},
		{Pubkey: memberB},
	}}

	if !rec.IsAdmin(memberA) {
		t.Fatal("IsAdmin(memberA) = false, want true")
	}
	if rec.IsAdmin(memberB) {
		t.Fatal("IsAdmin(memberB) = true, want false (member but holds no role)")
	}
	if !rec.IsMember(memberB) {
		t.Fatal("IsMember(memberB) = false, want true")
	}
	if rec.IsMember(memberC) {
		t.Fatal("IsMember(memberC) = true, want false")
	}
	if rec.RolesFor(memberC) != nil {
		t.Fatal("RolesFor(memberC) = non-nil for a non-member, want nil")
	}
}

func TestGroupRecord_WithMember(t *testing.T) {
	rec := &GroupRecord{Members: []GroupMember{{Pubkey: memberA, Roles: []string{"admin"}}}}

	added := rec.withMember(GroupMember{Pubkey: memberB})
	if added == rec {
		t.Fatal("withMember() returned the same pointer, want a fresh copy")
	}
	if len(rec.Members) != 1 {
		t.Fatal("withMember() mutated the receiver in place, want it untouched")
	}
	if len(added.Members) != 2 || !added.IsMember(memberA) || !added.IsMember(memberB) {
		t.Fatalf("withMember() = %+v, want both memberA and memberB", added.Members)
	}

	// Upserting an existing pubkey replaces its entry rather than
	// duplicating it.
	replaced := added.withMember(GroupMember{Pubkey: memberB, Roles: []string{"admin"}})
	if len(replaced.Members) != 2 {
		t.Fatalf("withMember() on an existing pubkey = %d members, want 2 (replace, not append)", len(replaced.Members))
	}
	if !replaced.IsAdmin(memberB) {
		t.Fatal("withMember() should have replaced memberB's entry with the new roles")
	}
}

func TestGroupRecord_WithoutMember(t *testing.T) {
	rec := &GroupRecord{Members: []GroupMember{{Pubkey: memberA}, {Pubkey: memberB}}}

	removed := rec.withoutMember(memberA)
	if len(rec.Members) != 2 {
		t.Fatal("withoutMember() mutated the receiver in place, want it untouched")
	}
	if removed.IsMember(memberA) {
		t.Fatal("withoutMember(memberA) should have dropped memberA")
	}
	if !removed.IsMember(memberB) {
		t.Fatal("withoutMember(memberA) should not affect memberB")
	}

	// Removing a non-member is a harmless no-op.
	noop := removed.withoutMember(memberC)
	if len(noop.Members) != 1 {
		t.Fatalf("withoutMember() on a non-member = %d members, want 1 (no-op)", len(noop.Members))
	}
}

/////////////////////////////////////////////////////////////////////
// Group-scoped invites
/////////////////////////////////////////////////////////////////////

func TestEventStore_GroupInvite_CRUD(t *testing.T) {
	store := newStore(t)

	inv, err := store.GetGroupInvite(groupA, "unknown-code")
	if err != nil {
		t.Fatalf("GetGroupInvite() unknown: %v", err)
	}
	if inv != nil {
		t.Fatalf("GetGroupInvite() unknown = %+v, want nil", inv)
	}

	want := &GroupInvite{GroupID: groupA, Code: "abc123", CreatedAt: 100}
	if err := store.PutGroupInvite(want); err != nil {
		t.Fatalf("PutGroupInvite: %v", err)
	}

	got, err := store.GetGroupInvite(groupA, "abc123")
	if err != nil {
		t.Fatalf("GetGroupInvite(): %v", err)
	}
	if got == nil || got.Code != "abc123" || got.Used {
		t.Fatalf("GetGroupInvite() = %+v, want Code=abc123 Used=false", got)
	}

	// The same code is scoped to its own group -- another group's lookup
	// for the identical code string finds nothing.
	other, err := store.GetGroupInvite(groupB, "abc123")
	if err != nil {
		t.Fatalf("GetGroupInvite() for a different group: %v", err)
	}
	if other != nil {
		t.Fatalf("GetGroupInvite() for a different group = %+v, want nil", other)
	}
}

func TestEventStore_ConsumeGroupInvite(t *testing.T) {
	store := newStore(t)

	t.Run("not found", func(t *testing.T) {
		_, err := store.ConsumeGroupInvite(groupA, "nope")
		if !errors.Is(err, ErrGroupInviteNotFound) {
			t.Fatalf("err = %v, want errors.Is(_, ErrGroupInviteNotFound)", err)
		}
	})

	t.Run("single use, then exhausted", func(t *testing.T) {
		if err := store.PutGroupInvite(&GroupInvite{GroupID: groupA, Code: "single-use"}); err != nil {
			t.Fatalf("PutGroupInvite: %v", err)
		}
		inv, err := store.ConsumeGroupInvite(groupA, "single-use")
		if err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if !inv.Used {
			t.Fatal("Used = false after a successful consume, want true")
		}

		_, err = store.ConsumeGroupInvite(groupA, "single-use")
		if !errors.Is(err, ErrGroupInviteExhausted) {
			t.Fatalf("second consume err = %v, want errors.Is(_, ErrGroupInviteExhausted)", err)
		}
	})

	t.Run("scoped per group", func(t *testing.T) {
		if err := store.PutGroupInvite(&GroupInvite{GroupID: groupA, Code: "shared-code"}); err != nil {
			t.Fatalf("PutGroupInvite: %v", err)
		}
		// groupB never had this code created for it.
		_, err := store.ConsumeGroupInvite(groupB, "shared-code")
		if !errors.Is(err, ErrGroupInviteNotFound) {
			t.Fatalf("err = %v, want errors.Is(_, ErrGroupInviteNotFound) for a different group's lookup", err)
		}
		// groupA's own code still works.
		if _, err := store.ConsumeGroupInvite(groupA, "shared-code"); err != nil {
			t.Fatalf("consume for the owning group: %v", err)
		}
	})
}
