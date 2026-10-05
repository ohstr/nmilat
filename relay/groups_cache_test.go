package relay

import (
	"sync"
	"sync/atomic"
	"testing"
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
	recA2 := &GroupRecord{ID: groupA, Private: true}
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
	if err := svc.Create(&GroupRecord{ID: groupA}); err != nil {
		t.Fatalf("nil *GroupsService.Create() = %v, want nil", err)
	}
	if err := svc.Delete(groupA); err != nil {
		t.Fatalf("nil *GroupsService.Delete() = %v, want nil", err)
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

	if err := svc.Delete(groupA); err != nil {
		t.Fatalf("Delete: %v", err)
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
	if err := store.PutGroup(&GroupRecord{ID: groupA, Admins: []string{memberA}, Private: true}); err != nil {
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
