package relay

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	memberA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	memberB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	memberC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestMembershipCache_IsMember_EmptyCache(t *testing.T) {
	var c membershipCache
	if c.IsMember(memberA) {
		t.Fatal("IsMember() on an empty cache = true, want false")
	}
}

func TestMembershipCache_IsMember_MalformedNeverPanics(t *testing.T) {
	var c membershipCache
	c.replace([]string{memberA})

	tests := []string{"", "not-hex", memberA[:63], memberA + "0", "zz" + memberA[2:]}
	for _, in := range tests {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("IsMember(%q) panicked: %v", in, r)
				}
			}()
			if c.IsMember(in) {
				t.Fatalf("IsMember(%q) = true, want false", in)
			}
		}()
	}
}

func TestMembershipCache_Replace(t *testing.T) {
	var c membershipCache
	c.replace([]string{memberA, memberB})

	if !c.IsMember(memberA) || !c.IsMember(memberB) {
		t.Fatal("replace() did not add members")
	}
	if c.IsMember(memberC) {
		t.Fatal("replace() unexpectedly added memberC")
	}

	// A second replace fully supersedes the first -- memberA drops out.
	c.replace([]string{memberB, memberC})
	if c.IsMember(memberA) {
		t.Fatal("replace() should have dropped memberA")
	}
	if !c.IsMember(memberB) || !c.IsMember(memberC) {
		t.Fatal("replace() should carry forward memberB and add memberC")
	}
}

func TestMembershipCache_AddRemove(t *testing.T) {
	var c membershipCache

	c.add(memberA)
	if !c.IsMember(memberA) {
		t.Fatal("add() did not add memberA")
	}

	c.add(memberB)
	if !c.IsMember(memberA) || !c.IsMember(memberB) {
		t.Fatal("add() should be additive, not replace the existing set")
	}

	c.remove(memberA)
	if c.IsMember(memberA) {
		t.Fatal("remove() did not remove memberA")
	}
	if !c.IsMember(memberB) {
		t.Fatal("remove() should not affect memberB")
	}

	// Removing a non-member, or adding/removing malformed input, is a
	// harmless no-op.
	c.remove(memberA)
	c.add("not-hex")
	c.remove("not-hex")
	if c.IsMember(memberA) || c.IsMember("not-hex") {
		t.Fatal("no-op add/remove should not have added anything")
	}
}

func TestMembershipCache_ColdStart(t *testing.T) {
	var c membershipCache
	c.replace([]string{memberA, memberB, memberC})

	for _, m := range []string{memberA, memberB, memberC} {
		if !c.IsMember(m) {
			t.Fatalf("cold-start replace() should have loaded %s", m)
		}
	}
}

// TestMembershipCache_ConcurrentReadersAndWriter exercises the
// atomic.Pointer swap under real concurrency: many goroutines reading
// IsMember while one goroutine repeatedly add/removes a member. Run with
// -race, this must never report a data race, and readers must never
// observe a torn/partial map (IsMember either fully sees a snapshot or
// doesn't -- there is no way to observe an in-between state, since
// snapshots are only ever replaced wholesale, never mutated in place).
func TestMembershipCache_ConcurrentReadersAndWriter(t *testing.T) {
	var c membershipCache
	c.replace([]string{memberB}) // a member that's never touched by the writer

	const readers = 16
	const iterations = 2000

	var wg sync.WaitGroup
	var stop atomic.Bool

	for range readers {
		wg.Go(func() {
			for !stop.Load() {
				// memberB must remain a member throughout -- it is never
				// added or removed by the writer below.
				if !c.IsMember(memberB) {
					t.Error("IsMember(memberB) = false during concurrent writes, want true")
					return
				}
				c.IsMember(memberA) // exercised for -race, result not asserted (toggles)
			}
		})
	}

	for range iterations {
		c.add(memberA)
		c.remove(memberA)
	}
	stop.Store(true)
	wg.Wait()
}

func TestMembershipService_NilIsSafeAndReportsNotAMember(t *testing.T) {
	var svc *MembershipService
	if svc.IsMember(memberA) {
		t.Fatal("nil *MembershipService.IsMember() = true, want false")
	}
}

func TestMembershipService_DelegatesToCache(t *testing.T) {
	svc := NewMembershipService()
	svc.cache.replace([]string{memberA})

	if !svc.IsMember(memberA) {
		t.Fatal("IsMember(memberA) = false, want true")
	}
	if svc.IsMember(memberB) {
		t.Fatal("IsMember(memberB) = true, want false")
	}
}

func BenchmarkMembershipCache_IsMember(b *testing.B) {
	var c membershipCache
	members := make([]string, 1000)
	for i := range members {
		members[i] = fmt.Sprintf("%064x", i+1)
	}
	c.replace(members)

	target := members[len(members)/2]

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !c.IsMember(target) {
				b.Fatal("expected target to be a member")
			}
		}
	})
}
