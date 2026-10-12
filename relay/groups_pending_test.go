package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

func pendingJoins(t *testing.T, sess *Session) []*nip01.Event {
	t.Helper()
	return storedKinds(t, sess, nip29.KindJoinRequest)
}

// Off by default: a closed group refuses a join without a code.
func TestPendingJoins_OffRefuses(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // closed by default
	resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("codeless join to a closed group accepted with pending joins off")
	}
	if n := len(pendingJoins(t, sess)); n != 0 {
		t.Fatalf("%d join requests stored", n)
	}
}

// On, a codeless join waits: one per requester, visible to admins and the
// requester, cleared by the admin's put-user.
func TestPendingJoins_StoredUntilAccepted(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetPendingJoins(true)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	requester := secondTestPubKey(t)

	first := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", secondTestPrivKey))
	if !first.Accepted || first.Message != "info: your join request is pending admin approval." {
		t.Fatalf("join: accepted=%v %q", first.Accepted, first.Message)
	}
	if sess.groups.IsMember(groupA, requester) {
		t.Fatal("a pending requester became a member")
	}
	again := groupJoinRequestEvent(t, groupA, "", secondTestPrivKey)
	again.CreatedAt++
	if err := again.Sign(secondTestPrivKey); err != nil {
		t.Fatal(err)
	}
	sendEventAndAwaitOKForSession(t, sess, again)
	reqs := pendingJoins(t, sess)
	if len(reqs) != 1 || reqs[0].ID != again.ID {
		t.Fatalf("pending requests = %d, want only the latest", len(reqs))
	}

	outsider := newGroupsEnabledTestSession(t)
	outsider.groups = sess.groups
	if !outsider.groups.deniedPrivateGroupEvent(outsider, reqs[0]) {
		t.Error("an outsider saw a pending join request")
	}
	self := newGroupsEnabledTestSession(t)
	self.groups = sess.groups
	self.addIdentity(AuthedIdentity{Pubkey: requester, Membership: MembershipNone})
	if self.groups.deniedPrivateGroupEvent(self, reqs[0]) {
		t.Error("the requester was refused their own request")
	}
	sess.addIdentity(AuthedIdentity{Pubkey: authTestPubKey, Membership: MembershipNone})
	if sess.groups.deniedPrivateGroupEvent(sess, reqs[0]) {
		t.Error("an admin was refused a pending join request")
	}

	if resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, requester, authTestPrivKey)); !resp.Accepted {
		t.Fatalf("accept: %s", resp.Message)
	}
	if n := len(pendingJoins(t, sess)); n != 0 {
		t.Fatalf("%d pending requests left after put-user", n)
	}
}

// A remove-user declines a pending request; a member who isn't an admin
// can't see one.
func TestPendingJoins_DeclinedAndHiddenFromMembers(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetPendingJoins(true)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	plainMember := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, plainMember, authTestPrivKey))

	sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", thirdTestPrivKey))
	reqs := pendingJoins(t, sess)
	if len(reqs) != 1 {
		t.Fatalf("pending requests = %d, want 1", len(reqs))
	}
	member := newGroupsEnabledTestSession(t)
	member.groups = sess.groups
	member.addIdentity(AuthedIdentity{Pubkey: plainMember, Membership: MembershipNone})
	if !member.groups.deniedPrivateGroupEvent(member, reqs[0]) {
		t.Error("a non-admin member saw a pending join request")
	}

	if resp := sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, reqs[0].PubKey, authTestPrivKey)); !resp.Accepted {
		t.Fatalf("decline: %s", resp.Message)
	}
	if n := len(pendingJoins(t, sess)); n != 0 {
		t.Fatalf("%d pending requests left after remove-user", n)
	}
}

// COUNT runs the gate on kind 9021, so an outsider can't count requests.
func TestPendingJoins_CountGated(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetPendingJoins(true)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Closed: true})); !resp.Accepted {
		t.Fatalf("make groupA public and closed: %s", resp.Message)
	}
	sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", secondTestPrivKey))

	cp := &wire.CountPacket{
		SubscriptionID: "sub-1",
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{nip29.KindJoinRequest}}),
	}
	if err := sess.processCount(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	resp, ok := (<-sess.incoming).(*wire.CountSubscriptionResponse)
	if !ok || resp.Count != 0 {
		t.Fatalf("anonymous count = %+v, want 0", resp)
	}
}
