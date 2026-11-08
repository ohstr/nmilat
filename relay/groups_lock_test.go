package relay

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

// putUsersOnGroups creates n groups and returns one kind 9000 for each.
func putUsersOnGroups(tb testing.TB, sess *Session, n, round int) []*nip01.Event {
	tb.Helper()
	creates := make([]*nip01.Event, n)
	evs := make([]*nip01.Event, n)
	for i := range n {
		id := fmt.Sprintf("lock-%d-%d", round, i)
		creates[i] = createGroupEvent(tb, id)
		evs[i] = putUserEvent(tb, id, concurrentPubkey(i), authTestPrivKey)
	}
	handleAll(tb, sess, creates)
	return evs
}

// handleAll sends every event at once and returns how long the last took.
func handleAll(tb testing.TB, sess *Session, evs []*nip01.Event) time.Duration {
	tb.Helper()
	start := time.Now()
	var wg sync.WaitGroup
	for _, ev := range evs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := sess.groups.handle(context.Background(), sess, ev); !resp.Accepted {
				tb.Errorf("kind %d: %s", ev.Kind, resp.Message)
			}
		}()
	}
	wg.Wait()
	return time.Since(start)
}

// Writes to different groups do not queue behind each other: 20 put-users
// on 20 groups at once take about as long as one. A 50ms store batch makes
// each put-user's store writes, not signing (slow under -race), what it
// waits on, as on a relay whose store fsyncs.
func TestGroupsService_WritesToDifferentGroupsRunConcurrently(t *testing.T) {
	sess := newGroupsEnabledTestSession(t, WithEventStoreBatchConfig(500, 50*time.Millisecond))
	sess.groups.SetModerationLog(true)

	single := time.Duration(1<<63 - 1)
	for round := range 3 {
		evs := putUsersOnGroups(t, sess, 1, round)
		single = min(single, handleAll(t, sess, evs))
	}
	concurrent := time.Duration(1<<63 - 1)
	for round := range 3 {
		evs := putUsersOnGroups(t, sess, 20, 10+round)
		concurrent = min(concurrent, handleAll(t, sess, evs))
	}
	t.Logf("one put-user: %v; 20 on 20 groups at once: %v", single, concurrent)
	if concurrent > 3*single {
		t.Fatalf("20 put-users on 20 groups took %v, more than 3x one (%v)", concurrent, single)
	}
}

func BenchmarkGroupsService_PutUserOn20Groups(b *testing.B) {
	sess := newGroupsEnabledTestSession(b)
	sess.groups.SetModerationLog(true)
	b.StopTimer()
	for i := range b.N {
		evs := putUsersOnGroups(b, sess, 20, i)
		b.StartTimer()
		handleAll(b, sess, evs)
		b.StopTimer()
	}
}

// Reparents, which change two groups, interleave safely with writes to
// one: every child lands in its parent's list and every member in its
// roster.
func TestGroupsService_ReparentsRacingSingleGroupWrites(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	const n = 10
	creates := []*nip01.Event{createGroupEvent(t, groupA)}
	for i := range n {
		creates = append(creates, createGroupEvent(t, fmt.Sprintf("child-%d", i)))
	}
	handleAll(t, sess, creates)

	var evs []*nip01.Event
	for i := range n {
		child := fmt.Sprintf("child-%d", i)
		evs = append(evs,
			editMetadataEvent(t, child, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true}),
			putUserEvent(t, groupA, concurrentPubkey(i), authTestPrivKey),
			putUserEvent(t, child, concurrentPubkey(i), authTestPrivKey))
	}
	handleAll(t, sess, evs)

	if parent := sess.groups.cache.Get(groupA); len(parent.Metadata.Children) != n {
		t.Fatalf("parent lists %d children, want %d: %v", len(parent.Metadata.Children), n, parent.Metadata.Children)
	}
	wantRoster(t, sess.groups, groupA, n+1)
	for i := range n {
		child := fmt.Sprintf("child-%d", i)
		if rec := sess.groups.cache.Get(child); rec.Metadata.Parent != groupA {
			t.Fatalf("%s has parent %q, want %q", child, rec.Metadata.Parent, groupA)
		}
		wantRoster(t, sess.groups, child, 2)
	}

	// Deleting the parent while its children are written to promotes
	// every child to root and keeps their rosters.
	evs = []*nip01.Event{deleteGroupEvent(t, groupA, authTestPrivKey)}
	for i := range n {
		evs = append(evs, putUserEvent(t, fmt.Sprintf("child-%d", i), concurrentPubkey(n+i), authTestPrivKey))
	}
	handleAll(t, sess, evs)
	for i := range n {
		child := fmt.Sprintf("child-%d", i)
		if rec := sess.groups.cache.Get(child); rec.Metadata.Parent != "" {
			t.Fatalf("%s still has parent %q after it was deleted", child, rec.Metadata.Parent)
		}
		wantRoster(t, sess.groups, child, 3)
	}
}

// A kind:9008 or kind:9002 that would change other groups too is refused
// under its own group's lock when the sender may not make it, never
// waiting for (or taking) every group's lock: with another group's lock
// held, which lockAll would wait on, each refusal still comes back at once.
func TestGroupsService_RefusedCrossGroupWritesDoNotLockAll(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	handleAll(t, sess, []*nip01.Event{createGroupEvent(t, groupA), createGroupEvent(t, "linked"), createGroupEvent(t, "loose")})
	handleAll(t, sess, []*nip01.Event{editMetadataEvent(t, "linked", authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true})})

	unlockBusy := sess.groups.lockGroup("busy")
	refused := []struct {
		ev   *nip01.Event
		want string
	}{
		{editMetadataEvent(t, "loose", strangerPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true}), msgNotGroupAdminEdit},
		{editMetadataEvent(t, "missing", strangerPrivKey, nip29.GroupMetadataParams{Parent: groupA}), "restricted: no such group."},
		{editMetadataEvent(t, "linked", strangerPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true}), msgNotGroupAdminEdit},
		{deleteGroupEvent(t, "linked", strangerPrivKey), msgNotGroupAdminDelete},
	}
	for _, r := range refused {
		done := make(chan string, 1)
		go func() { done <- sess.groups.handle(context.Background(), sess, r.ev).Message }()
		select {
		case got := <-done:
			if got != r.want {
				t.Errorf("kind %d: got %q, want %q", r.ev.Kind, got, r.want)
			}
		case <-time.After(5 * time.Second):
			unlockBusy()
			t.Fatalf("kind %d from a non-admin waited on another group's lock", r.ev.Kind)
		}
	}

	// An admin's deletion of the linked group does take every group's
	// lock: it waits until the other group's is released, then succeeds.
	del := deleteGroupEvent(t, "linked", authTestPrivKey)
	resp := make(chan *wire.OkSubscriptionResponse, 1)
	go func() { resp <- sess.groups.handle(context.Background(), sess, del) }()
	select {
	case r := <-resp:
		unlockBusy()
		t.Fatalf("admin's deletion of a linked group returned (%q) while another group was locked", r.Message)
	case <-time.After(100 * time.Millisecond):
	}
	unlockBusy()
	if r := <-resp; !r.Accepted {
		t.Fatalf("admin's deletion refused: %s", r.Message)
	}
	if sess.groups.Exists("linked") {
		t.Fatal("linked group still exists after its admin deleted it")
	}
}
