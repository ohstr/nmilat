package relay

import "testing"

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

	want := &GroupRecord{ID: groupA, Admins: []string{memberA}, Members: []string{memberA}, Private: true, CreatedAt: 100}
	if err := store.PutGroup(want); err != nil {
		t.Fatalf("PutGroup: %v", err)
	}

	rec, err = store.GetGroup(groupA)
	if err != nil {
		t.Fatalf("GetGroup() after put: %v", err)
	}
	if rec == nil || rec.ID != groupA || !rec.Private || len(rec.Admins) != 1 || rec.Admins[0] != memberA {
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
	rec := &GroupRecord{ID: groupA, Admins: []string{memberA}, Members: []string{memberA, memberB}}

	if !rec.IsAdmin(memberA) {
		t.Fatal("IsAdmin(memberA) = false, want true")
	}
	if rec.IsAdmin(memberB) {
		t.Fatal("IsAdmin(memberB) = true, want false (member but not admin)")
	}
	if !rec.IsMember(memberB) {
		t.Fatal("IsMember(memberB) = false, want true")
	}
	if rec.IsMember(memberC) {
		t.Fatal("IsMember(memberC) = true, want false")
	}
}
