package relay

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
)

func concurrentPubkey(i int) string { return fmt.Sprintf("%064x", i+1) }

// wantRoster checks group id has n members in both the cache and the store.
func wantRoster(t *testing.T, g *GroupsService, id string, n int) {
	t.Helper()
	if rec := g.cache.Get(id); rec == nil || len(rec.Members) != n {
		t.Fatalf("cached roster of %s: %v, want %d members", id, rec, n)
	}
	rec, err := g.Get(id)
	if err != nil || rec == nil || len(rec.Members) != n {
		t.Fatalf("stored roster of %s: %v (%v), want %d members", id, rec, err, n)
	}
}

// Concurrent roster changes through the exported mutators all land.
func TestGroupsService_ConcurrentUpsertMember(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	if err := svc.Create(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatal(err)
	}
	const n = 50
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.UpsertMember(groupA, GroupMember{Pubkey: concurrentPubkey(i)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	wantRoster(t, svc, groupA, n+1)

	for i := range n / 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.RemoveMember(groupA, concurrentPubkey(i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	wantRoster(t, svc, groupA, n/2+1)
}

// Concurrent kind 9000s from the group's admin all land.
func TestGroupsService_ConcurrentPutUserEvents(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	const n = 50
	evs := make([]*nip01.Event, n)
	for i := range evs {
		evs[i] = putUserEvent(t, groupA, concurrentPubkey(i), authTestPrivKey)
	}
	var wg sync.WaitGroup
	for _, ev := range evs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := sess.groups.handle(context.Background(), sess, ev); !resp.Accepted {
				t.Errorf("put-user: %s", resp.Message)
			}
		}()
	}
	wg.Wait()
	wantRoster(t, sess.groups, groupA, n+1)
}

// A group deleted while members are being added stays deleted: no write
// that read it before the delete stores it again afterwards.
func TestGroupsService_DeleteRacingWritesStaysDeleted(t *testing.T) {
	svc := NewGroupsService(newStore(t))
	for round := range 10 {
		id := fmt.Sprintf("race-%d", round)
		if err := svc.Create(newGroupRecord(id, memberA)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := svc.UpsertMember(id, GroupMember{Pubkey: concurrentPubkey(i)}); err != nil {
					t.Error(err)
				}
				if _, err := svc.SetPins(id, GroupPins{Events: []string{concurrentPubkey(i)}}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Delete(id); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if svc.Exists(id) {
			t.Fatalf("round %d: the deleted group is back in the cache", round)
		}
		if rec, err := svc.Get(id); err != nil || rec != nil {
			t.Fatalf("round %d: the deleted group is back in the store: %v (%v)", round, rec, err)
		}
		if rec, err := svc.UpsertMember(id, GroupMember{Pubkey: memberB}); err != nil || rec != nil {
			t.Fatalf("round %d: a write after the delete returned %v (%v), want nothing", round, rec, err)
		}
	}
}

// A kind 9008 racing kind 9000s leaves the group deleted, and every
// put-user after it is refused.
func TestGroupsService_DeleteGroupEventRacingPutUser(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	evs := make([]*nip01.Event, 20)
	for i := range evs {
		evs[i] = putUserEvent(t, groupA, concurrentPubkey(i), authTestPrivKey)
	}
	del := deleteGroupEvent(t, groupA, authTestPrivKey)
	var wg sync.WaitGroup
	for _, ev := range evs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess.groups.handle(context.Background(), sess, ev)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if resp := sess.groups.handle(context.Background(), sess, del); !resp.Accepted {
			t.Errorf("delete: %s", resp.Message)
		}
	}()
	wg.Wait()
	if sess.groups.Exists(groupA) {
		t.Fatal("the deleted group is back")
	}
	if rec, err := sess.groups.Get(groupA); err != nil || rec != nil {
		t.Fatalf("the deleted group is back in the store: %v (%v)", rec, err)
	}
	late := putUserEvent(t, groupA, memberB, authTestPrivKey)
	if resp := sess.groups.handle(context.Background(), sess, late); resp.Accepted {
		t.Fatal("a put-user to the deleted group was accepted")
	}
	if n := len(storedKinds(t, sess, nip29.KindGroupMembers)); n != 0 {
		t.Fatalf("%d member lists left for the deleted group", n)
	}
}
