package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/testlogger"
)

// storedRoles returns group id's stored kind:39003, or nil.
func storedRoles(t *testing.T, store *EventStore, id string) *nip01.Event {
	t.Helper()
	evs, err := store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupRoles}, Tags: map[string][]string{"d": {id}}, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) > 1 {
		t.Fatalf("%d kind:39003 events stored for %s, want at most 1", len(evs), id)
	}
	if len(evs) == 0 {
		return nil
	}
	return evs[0]
}

func roleNames(t *testing.T, ev *nip01.Event) map[string]string {
	t.Helper()
	if err := ev.Verify(); err != nil {
		t.Fatalf("kind:39003 doesn't verify: %v", err)
	}
	parsed, err := nip29.ParseGroupRoles(ev)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range parsed.Roles {
		out[r.Name] = r.Description
	}
	return out
}

// A new group gets a relay-signed kind:39003 listing the policy's roles.
func TestHandleEvent_CreateGroup_PublishesRoles(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	ev := storedRoles(t, sess.store, groupA)
	if ev == nil {
		t.Fatal("no kind:39003 after create")
	}
	if ev.PubKey != authTestPubKey {
		t.Fatalf("kind:39003 signed by %s, want the relay", ev.PubKey)
	}
	if roles := roleNames(t, ev); len(roles) != 1 || roles["admin"] == "" {
		t.Fatalf("roles = %v, want only a described admin", roles)
	}
}

// Changing the policy or the descriptions republishes every group's
// kind:39003; an unchanged policy writes nothing.
func TestSetModerationPolicy_RepublishesRoles(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	sess.groups.setSigner(authTestPubKey, authTestPrivKey)

	before := storedRoles(t, sess.store, groupA)
	sess.groups.publishAllRoles(context.Background())
	if after := storedRoles(t, sess.store, groupA); after.ID != before.ID {
		t.Fatal("an unchanged policy republished kind:39003")
	}

	sess.groups.SetModerationPolicy(nip29.ModerationPolicy{
		"admin":     {nip29.KindPutUser, nip29.KindRemoveUser, nip29.KindEditMetadata},
		"moderator": {nip29.KindDeleteEvent},
	})
	sess.groups.SetRoleDescriptions(map[string]string{"moderator": "keeps the peace"})
	for _, id := range []string{groupA, groupB} {
		roles := roleNames(t, storedRoles(t, sess.store, id))
		if roles["moderator"] != "keeps the peace" || roles["admin"] == "" || len(roles) != 2 {
			t.Fatalf("%s roles = %v", id, roles)
		}
	}
}

// At startup, a hosted group without a kind:39003 gets one.
func TestNewSessionHandler_PublishesMissingRoles(t *testing.T) {
	store := newStore(t)
	g := NewGroupsService(store)
	if err := g.Create(newGroupRecord(groupA, authTestPubKey)); err != nil {
		t.Fatal(err)
	}
	if storedRoles(t, store, groupA) != nil {
		t.Fatal("kind:39003 exists before startup")
	}

	NewSessionHandler(store, &nip11.Metadata{Self: authTestPubKey}, nil,
		WithSessionConfig(SessionConfig{PrivKey: authTestPrivKey}), WithLogger(testlogger.New(t)))

	ev := storedRoles(t, store, groupA)
	if ev == nil || ev.PubKey != authTestPubKey {
		t.Fatalf("startup kind:39003 = %+v", ev)
	}
}
