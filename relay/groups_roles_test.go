package relay

import (
	"context"
	"slices"
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

// SetModerationPolicy keeps its own copy: changing the caller's map or
// slices afterwards changes nothing CanPerform allows. (The startup
// option, WithGroupsModerationPolicy, stores through the same setPolicy.)
func TestSetModerationPolicy_CopiesThePolicy(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if _, err := sess.groups.UpsertMember(groupA, GroupMember{Pubkey: memberA, Roles: []string{"moderator"}}); err != nil {
		t.Fatal(err)
	}
	policy := nip29.ModerationPolicy{
		"admin":     slices.Clone(defaultGroupModerationPolicy["admin"]),
		"moderator": {nip29.KindDeleteEvent},
	}
	sess.groups.SetModerationPolicy(policy)

	policy["moderator"][0] = nip29.KindPutUser
	policy["moderator"] = append(policy["moderator"], nip29.KindRemoveUser)
	delete(policy, "admin")

	g := sess.groups
	if !g.CanPerform(groupA, memberA, nip29.KindDeleteEvent) {
		t.Fatal("changing the caller's slice took the moderator's kind 9005 away")
	}
	if g.CanPerform(groupA, memberA, nip29.KindPutUser) || g.CanPerform(groupA, memberA, nip29.KindRemoveUser) {
		t.Fatal("changing the caller's policy gave the moderator kind 9000 or 9001")
	}
	if !g.CanPerform(groupA, authTestPubKey, nip29.KindDeleteGroup) {
		t.Fatal("deleting the caller's admin role took the creator's kind 9008 away")
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

// With WithGroupsModerationPolicy, startup publishes kind:39001 and
// kind:39003 under that policy only: a group whose stored ones already
// follow it gets nothing new, never a default-policy 39001 dropping its
// moderator.
func TestNewSessionHandler_WithGroupsModerationPolicy(t *testing.T) {
	policy := nip29.ModerationPolicy{
		"admin":     defaultGroupModerationPolicy["admin"],
		"moderator": {nip29.KindDeleteEvent},
	}
	descriptions := map[string]string{"moderator": "keeps the peace"}
	store := newStore(t)
	g := NewGroupsService(store)
	g.setPolicy(policy)
	g.setRoleDescriptions(descriptions)
	g.setSigner(authTestPubKey, authTestPrivKey)
	if err := g.Create(newGroupRecord(groupA, authTestPubKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.UpsertMember(groupA, GroupMember{Pubkey: memberA, Roles: []string{"moderator"}}); err != nil {
		t.Fatal(err)
	}
	g.publishAllAdmins(context.Background())
	g.publishAllRoles(context.Background())
	admins, roles := storedAdmins(t, store, groupA), storedRoles(t, store, groupA)
	if admins == nil || roles == nil {
		t.Fatal("no kind:39001 or kind:39003 before startup")
	}

	NewSessionHandler(store, &nip11.Metadata{Self: authTestPubKey}, nil,
		WithSessionPrivKey(authTestPrivKey), WithLogger(testlogger.New(t)),
		WithGroupsModerationPolicy(policy), WithGroupsRoleDescriptions(descriptions))

	if after := storedAdmins(t, store, groupA); after.ID != admins.ID {
		t.Fatalf("startup republished kind:39001: %v", after.Tags)
	}
	if after := storedRoles(t, store, groupA); after.ID != roles.ID {
		t.Fatalf("startup republished kind:39003: %v", after.Tags)
	}

	// Without the option, startup's default policy drops the moderator.
	NewSessionHandler(store, &nip11.Metadata{Self: authTestPubKey}, nil,
		WithSessionPrivKey(authTestPrivKey), WithLogger(testlogger.New(t)))
	if after := storedAdmins(t, store, groupA); after.ID == admins.ID {
		t.Fatal("startup under the default policy kept the moderator's kind:39001")
	}
}

// storedAdmins returns group id's stored kind:39001, or nil.
func storedAdmins(t *testing.T, store *EventStore, id string) *nip01.Event {
	t.Helper()
	evs, err := store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupAdmins}, Tags: map[string][]string{"d": {id}}, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) > 1 {
		t.Fatalf("%d kind:39001 events stored for %s, want at most 1", len(evs), id)
	}
	if len(evs) == 0 {
		return nil
	}
	return evs[0]
}
