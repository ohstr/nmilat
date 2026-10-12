package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

func storedKinds(t *testing.T, sess *Session, kinds ...int) []*nip01.Event {
	t.Helper()
	evs, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: kinds, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// Off by default: moderation events stay commands and nothing is kept.
func TestModerationLog_OffByDefault(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, secondTestPubKey(t), authTestPrivKey))
	if evs := storedKinds(t, sess, nip29.KindCreateGroup, nip29.KindPutUser); len(evs) != 0 {
		t.Fatalf("%d moderation events stored with the log off", len(evs))
	}
}

// On, accepted moderation events are stored and readable by members only;
// an invite only by admins. A refused one is not stored.
func TestModerationLog_StoresAndGates(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetModerationLog(true)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	member := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, authTestPrivKey))
	sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "secret-code", authTestPrivKey))
	if resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, secondTestPrivKey)); resp.Accepted {
		t.Fatal("a non-admin put-user was accepted")
	}

	if n := len(storedKinds(t, sess, nip29.KindCreateGroup)); n != 1 {
		t.Fatalf("stored 9007 = %d, want 1", n)
	}
	puts := storedKinds(t, sess, nip29.KindPutUser)
	if len(puts) != 1 || puts[0].PubKey != authTestPubKey {
		t.Fatalf("stored 9000 = %d, want only the admin's accepted one", len(puts))
	}
	invites := storedKinds(t, sess, nip29.KindCreateInvite)
	if len(invites) != 1 {
		t.Fatalf("stored 9009 = %d, want 1", len(invites))
	}

	anon := newGroupsEnabledTestSession(t)
	anon.groups = sess.groups
	if !anon.groups.deniedPrivateGroupEvent(anon, puts[0]) {
		t.Error("an anonymous reader saw the moderation log")
	}

	asMember := newGroupsEnabledTestSession(t)
	asMember.groups = sess.groups
	asMember.addIdentity(AuthedIdentity{Pubkey: member, Membership: MembershipNone})
	if asMember.groups.deniedPrivateGroupEvent(asMember, puts[0]) {
		t.Error("a member was refused the moderation log")
	}
	if !asMember.groups.deniedPrivateGroupEvent(asMember, invites[0]) {
		t.Error("a non-admin member saw an invite code")
	}

	sess.addIdentity(AuthedIdentity{Pubkey: authTestPubKey, Membership: MembershipNone})
	if sess.groups.deniedPrivateGroupEvent(sess, invites[0]) {
		t.Error("an admin was refused an invite")
	}
}

// COUNT runs the per-event gate on moderation kinds even when no group is
// private, so a non-member can't count a public group's log.
func TestModerationLog_CountGated(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetModerationLog(true)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{})); !resp.Accepted {
		t.Fatalf("make groupA public: %s", resp.Message)
	}

	cp := &wire.CountPacket{
		SubscriptionID: "sub-1",
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{nip29.KindCreateGroup, nip29.KindEditMetadata}}),
	}
	if err := sess.processCount(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	resp, ok := (<-sess.incoming).(*wire.CountSubscriptionResponse)
	if !ok {
		t.Fatal("reply was not a count")
	}
	if resp.Count != 0 {
		t.Fatalf("anonymous Count = %d, want 0", resp.Count)
	}
}
