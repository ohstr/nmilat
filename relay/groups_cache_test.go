package relay

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ohstr/nmilat/nip29"
)

func TestGroupsCache_Get_EmptyCache(t *testing.T) {
	var c groupsCache
	if c.Get(groupA) != nil {
		t.Fatal("Get() on an empty cache = non-nil, want nil")
	}
}

func TestGroupsCache_Replace(t *testing.T) {
	var c groupsCache
	recA := &GroupRecord{ID: groupA}
	recB := &GroupRecord{ID: groupB}
	c.replace([]*GroupRecord{recA, recB})

	if c.Get(groupA) != recA || c.Get(groupB) != recB {
		t.Fatal("replace() did not add groups")
	}
	if c.Get(groupC) != nil {
		t.Fatal("replace() unexpectedly added groupC")
	}

	// A second replace fully supersedes the first -- groupA drops out.
	recC := &GroupRecord{ID: groupC}
	c.replace([]*GroupRecord{recB, recC})
	if c.Get(groupA) != nil {
		t.Fatal("replace() should have dropped groupA")
	}
	if c.Get(groupB) != recB || c.Get(groupC) != recC {
		t.Fatal("replace() should carry forward groupB and add groupC")
	}
}

func TestGroupsCache_PutRemove(t *testing.T) {
	var c groupsCache

	recA := &GroupRecord{ID: groupA}
	c.put(recA)
	if c.Get(groupA) != recA {
		t.Fatal("put() did not add groupA")
	}

	recB := &GroupRecord{ID: groupB}
	c.put(recB)
	if c.Get(groupA) != recA || c.Get(groupB) != recB {
		t.Fatal("put() should be additive, not replace the existing set")
	}

	// put() also overwrites an existing entry for the same id.
	recA2 := &GroupRecord{ID: groupA, Metadata: GroupMetadataFields{Private: true}}
	c.put(recA2)
	if c.Get(groupA) != recA2 {
		t.Fatal("put() did not overwrite the existing groupA record")
	}

	c.remove(groupA)
	if c.Get(groupA) != nil {
		t.Fatal("remove() did not remove groupA")
	}
	if c.Get(groupB) != recB {
		t.Fatal("remove() should not affect groupB")
	}

	// Removing a non-existent group is a harmless no-op.
	c.remove(groupA)
	if c.Get(groupA) != nil {
		t.Fatal("no-op remove should not have added anything")
	}
}

// TestGroupsCache_ConcurrentReadersAndWriter exercises the atomic.Pointer
// swap under real concurrency: many goroutines reading Get while one
// goroutine repeatedly put/removes a group. Run with -race, this must never
// report a data race, and readers must never observe a torn/partial map.
func TestGroupsCache_ConcurrentReadersAndWriter(t *testing.T) {
	var c groupsCache
	stable := &GroupRecord{ID: groupB} // never touched by the writer
	c.replace([]*GroupRecord{stable})

	const readers = 16
	const iterations = 2000

	var wg sync.WaitGroup
	var stop atomic.Bool

	for range readers {
		wg.Go(func() {
			for !stop.Load() {
				if c.Get(groupB) != stable {
					t.Error("Get(groupB) changed during concurrent writes, want stable")
					return
				}
				c.Get(groupA) // exercised for -race, result not asserted (toggles)
			}
		})
	}

	for range iterations {
		c.put(&GroupRecord{ID: groupA})
		c.remove(groupA)
	}
	stop.Store(true)
	wg.Wait()
}

func TestGroupsService_NilIsSafe(t *testing.T) {
	var svc *GroupsService
	if svc.Exists(groupA) {
		t.Fatal("nil *GroupsService.Exists() = true, want false")
	}
	if svc.IsAdmin(groupA, memberA) {
		t.Fatal("nil *GroupsService.IsAdmin() = true, want false")
	}
	if svc.IsMember(groupA, memberA) {
		t.Fatal("nil *GroupsService.IsMember() = true, want false")
	}
	if svc.IsPrivate(groupA) {
		t.Fatal("nil *GroupsService.IsPrivate() = true, want false")
	}
	if svc.IsClosed(groupA) {
		t.Fatal("nil *GroupsService.IsClosed() = true, want false")
	}
	if svc.CanPerform(groupA, memberA, nip29.KindPutUser) {
		t.Fatal("nil *GroupsService.CanPerform() = true, want false")
	}
	if err := svc.Create(&GroupRecord{ID: groupA}); err != nil {
		t.Fatalf("nil *GroupsService.Create() = %v, want nil", err)
	}
	if rec, err := svc.Delete(groupA); rec != nil || err != nil {
		t.Fatalf("nil *GroupsService.Delete() = (%v, %v), want (nil, nil)", rec, err)
	}
	if got, err := svc.Get(groupA); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.Get() = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := svc.List(); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.List() = (%v, %v), want (nil, nil)", got, err)
	}
	if err := svc.LoadFromStore(); err != nil {
		t.Fatalf("nil *GroupsService.LoadFromStore() = %v, want nil", err)
	}
	if got, err := svc.UpsertMember(groupA, GroupMember{Pubkey: memberA}); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.UpsertMember() = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := svc.RemoveMember(groupA, memberA); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.RemoveMember() = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := svc.SetMetadata(groupA, GroupMetadataFields{}); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.SetMetadata() = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := svc.SetPins(groupA, GroupPins{}); got != nil || err != nil {
		t.Fatalf("nil *GroupsService.SetPins() = (%v, %v), want (nil, nil)", got, err)
	}
	svc.SetModerationPolicy(nip29.ModerationPolicy{}) // must not panic
}

func TestGroupsService_CreateAndDelegation(t *testing.T) {
	svc := NewGroupsService(newStore(t))

	rec := newGroupRecord(groupA, memberA)
	if err := svc.Create(rec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !svc.Exists(groupA) {
		t.Fatal("Exists(groupA) = false after Create, want true")
	}
	if !svc.IsAdmin(groupA, memberA) {
		t.Fatal("IsAdmin(groupA, memberA) = false after Create, want true (creator is sole admin)")
	}
	if !svc.IsMember(groupA, memberA) {
		t.Fatal("IsMember(groupA, memberA) = false after Create, want true")
	}
	if !svc.IsPrivate(groupA) {
		t.Fatal("IsPrivate(groupA) = false after Create, want true (decision 2 default)")
	}
	if !svc.IsClosed(groupA) {
		t.Fatal("IsClosed(groupA) = false after Create, want true (decision 2 default)")
	}
	if svc.IsAdmin(groupA, memberB) || svc.IsMember(groupA, memberB) {
		t.Fatal("memberB should hold no role in a group it was never added to")
	}

	// Persisted too, not just cached.
	persisted, err := svc.Get(groupA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if persisted == nil || persisted.ID != groupA {
		t.Fatalf("Get() = %+v, want a persisted record for %s", persisted, groupA)
	}

	deleted, err := svc.Delete(groupA)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if deleted == nil || deleted.ID != groupA {
		t.Fatalf("Delete() record = %+v, want the just-deleted record for %s", deleted, groupA)
	}
	if svc.Exists(groupA) {
		t.Fatal("Exists(groupA) = true after Delete, want false")
	}
	if svc.IsPrivate(groupA) {
		t.Fatal("IsPrivate() on a deleted group = true, want false -- nothing left to protect")
	}
}

func TestGroupsService_IsPrivate_UnknownGroup(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	if svc.IsPrivate("no-such-group") {
		t.Fatal("IsPrivate() on an unknown group id = true, want false")
	}
}

func TestGroupsService_LoadFromStore(t *testing.T) {
	store := newStore(t)
	if err := store.PutGroup(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatalf("PutGroup: %v", err)
	}

	svc := NewGroupsService(store)
	if svc.Exists(groupA) {
		t.Fatal("Exists() before LoadFromStore = true, want false (cache not warmed yet)")
	}

	if err := svc.LoadFromStore(); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}
	if !svc.Exists(groupA) {
		t.Fatal("Exists() after LoadFromStore = false, want true")
	}
	if !svc.IsAdmin(groupA, memberA) {
		t.Fatal("IsAdmin() after LoadFromStore = false, want true")
	}
}

func TestGroupsService_UpsertRemoveMember(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	if err := svc.Create(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec, err := svc.UpsertMember(groupA, GroupMember{Pubkey: memberB})
	if err != nil {
		t.Fatalf("UpsertMember: %v", err)
	}
	if rec == nil || !rec.IsMember(memberB) {
		t.Fatalf("UpsertMember() = %+v, want memberB added", rec)
	}
	if !svc.IsMember(groupA, memberB) {
		t.Fatal("IsMember(memberB) = false after UpsertMember, want true (cache not updated)")
	}
	persisted, err := svc.Get(groupA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !persisted.IsMember(memberB) {
		t.Fatal("UpsertMember() did not persist to the store")
	}

	rec, err = svc.RemoveMember(groupA, memberB)
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if rec.IsMember(memberB) {
		t.Fatal("RemoveMember() should have dropped memberB")
	}
	if svc.IsMember(groupA, memberB) {
		t.Fatal("IsMember(memberB) = true after RemoveMember, want false")
	}

	// Mutating an unknown group is a (nil, nil) no-op.
	rec, err = svc.UpsertMember("no-such-group", GroupMember{Pubkey: memberA})
	if rec != nil || err != nil {
		t.Fatalf("UpsertMember() on an unknown group = (%v, %v), want (nil, nil)", rec, err)
	}
}

func TestGroupsService_SetMetadataSetPins(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	if err := svc.Create(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec, err := svc.SetMetadata(groupA, GroupMetadataFields{Name: "renamed", Private: false, Closed: false})
	if err != nil {
		t.Fatalf("SetMetadata: %v", err)
	}
	if rec.Metadata.Name != "renamed" || rec.Metadata.Private || rec.Metadata.Closed {
		t.Fatalf("SetMetadata() = %+v, want Name=renamed Private=false Closed=false", rec.Metadata)
	}
	if svc.IsPrivate(groupA) {
		t.Fatal("IsPrivate() after SetMetadata(Private: false) = true, want false")
	}
	if svc.IsClosed(groupA) {
		t.Fatal("IsClosed() after SetMetadata(Closed: false) = true, want false")
	}

	rec, err = svc.SetPins(groupA, GroupPins{Events: []string{"e1"}, Addresses: []string{"30000:abc:def"}})
	if err != nil {
		t.Fatalf("SetPins: %v", err)
	}
	if len(rec.Pins.Events) != 1 || len(rec.Pins.Addresses) != 1 {
		t.Fatalf("SetPins() = %+v, want 1 event and 1 address", rec.Pins)
	}
}

func TestGroupsService_CanPerform(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	if err := svc.Create(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !svc.CanPerform(groupA, memberA, nip29.KindPutUser) {
		t.Fatal("CanPerform(creator, KindPutUser) = false, want true under defaultGroupModerationPolicy")
	}
	if svc.CanPerform(groupA, memberB, nip29.KindPutUser) {
		t.Fatal("CanPerform(non-member, KindPutUser) = true, want false")
	}

	if _, err := svc.UpsertMember(groupA, GroupMember{Pubkey: memberB}); err != nil {
		t.Fatalf("UpsertMember: %v", err)
	}
	if svc.CanPerform(groupA, memberB, nip29.KindPutUser) {
		t.Fatal("CanPerform(regular member, KindPutUser) = true, want false (holds no role)")
	}

	// A custom policy is consulted instead, once set.
	svc.SetModerationPolicy(nip29.ModerationPolicy{"admin": {nip29.KindDeleteGroup}})
	if svc.CanPerform(groupA, memberA, nip29.KindPutUser) {
		t.Fatal("CanPerform() after SetModerationPolicy should stop allowing a kind the new policy omits")
	}
	if !svc.CanPerform(groupA, memberA, nip29.KindDeleteGroup) {
		t.Fatal("CanPerform() after SetModerationPolicy should allow the kind the new policy grants")
	}
}
