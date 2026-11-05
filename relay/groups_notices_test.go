package relay

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// storedNotices returns the stored events of kind about member.
func storedNotices(t *testing.T, sess *Session, kind int, member string) []*nip01.Event {
	t.Helper()
	evs, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{kind},
		Tags:  map[string][]string{"p": {member}},
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	return evs
}

func newNoticeSession(t *testing.T) *Session {
	t.Helper()
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetMemberNotices(DefaultMemberNoticeKinds)
	return sess
}

func TestMemberNotices_OffByDefault(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	member := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, authTestPrivKey))

	if got := storedNotices(t, sess, 44100, member); len(got) != 0 {
		t.Fatalf("stored %d notices with notices off, want 0", len(got))
	}
}

func TestMemberNotices_PutAndRemoveUser(t *testing.T) {
	sess := newNoticeSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	member := secondTestPubKey(t)

	put := putUserEvent(t, groupA, member, authTestPrivKey)
	sendEventAndAwaitOKForSession(t, sess, put)
	added := storedNotices(t, sess, 44100, member)
	if len(added) != 1 {
		t.Fatalf("added notices = %d, want 1", len(added))
	}
	n := added[0]
	if n.PubKey != authTestPubKey {
		t.Fatalf("notice signed by %s, want the relay %s", n.PubKey, authTestPubKey)
	}
	if err := n.Verify(); err != nil {
		t.Fatalf("notice signature: %v", err)
	}
	if tagValue(n, "h") != groupA || tagValue(n, "e") != put.ID {
		t.Fatalf("notice tags = %v, want h=%s e=%s", n.Tags, groupA, put.ID)
	}
	var content struct{ Type, Actor string }
	if err := json.Unmarshal([]byte(n.Content), &content); err != nil || content.Type != "member_added" || content.Actor != authTestPubKey {
		t.Fatalf("notice content = %s (%v)", n.Content, err)
	}

	// A role change on an existing member is not a new seat.
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, authTestPrivKey, "moderator"))
	if got := storedNotices(t, sess, 44100, member); len(got) != 1 {
		t.Fatalf("added notices after a role change = %d, want still 1", len(got))
	}

	sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, member, authTestPrivKey))
	if got := storedNotices(t, sess, 44101, member); len(got) != 1 {
		t.Fatalf("removed notices = %d, want 1", len(got))
	}
	// Removing a non-member changes nothing.
	sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, member, authTestPrivKey))
	if got := storedNotices(t, sess, 44101, member); len(got) != 1 {
		t.Fatalf("removed notices after removing a non-member = %d, want still 1", len(got))
	}
}

func TestMemberNotices_CreateJoinLeaveDelete(t *testing.T) {
	sess := newNoticeSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if got := storedNotices(t, sess, 44100, authTestPubKey); len(got) != 1 {
		t.Fatalf("creator's added notices = %d, want 1", len(got))
	}

	member := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "code-1", authTestPrivKey))
	if resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "code-1", secondTestPrivKey)); !resp.Accepted {
		t.Fatalf("join refused: %s", resp.Message)
	}
	if got := storedNotices(t, sess, 44100, member); len(got) != 1 {
		t.Fatalf("joiner's added notices = %d, want 1", len(got))
	}

	sendEventAndAwaitOKForSession(t, sess, groupLeaveRequestEvent(t, groupA, secondTestPrivKey))
	if got := storedNotices(t, sess, 44101, member); len(got) != 1 {
		t.Fatalf("leaver's removed notices = %d, want 1", len(got))
	}

	sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, groupA, authTestPrivKey))
	if got := storedNotices(t, sess, 44101, authTestPubKey); len(got) != 1 {
		t.Fatalf("creator's removed notices after delete = %d, want 1", len(got))
	}
}

func TestMemberNotices_OnlyTheMemberAndRelayAdminsRead(t *testing.T) {
	sess := newNoticeSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	member := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, authTestPrivKey))
	n := storedNotices(t, sess, 44100, member)[0]

	const adminPub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	const strangerPub = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	sess.groups.SetRelayAdmins(adminPub)

	if sess.groups.deniedPrivateGroupEvent(pubkeyReader{member}, n) {
		t.Fatal("the member named in p was denied its notice")
	}
	if sess.groups.deniedPrivateGroupEvent(pubkeyReader{adminPub}, n) {
		t.Fatal("a relay admin was denied the notice")
	}
	if !sess.groups.deniedPrivateGroupEvent(pubkeyReader{strangerPub}, n) {
		t.Fatal("another pubkey was served the notice")
	}
	if !sess.groups.deniedPrivateGroupEvent(nil, n) {
		t.Fatal("an anonymous reader was served the notice")
	}
	filters := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{44100}})
	if !sess.groups.needsPrivacyCheck(filters) {
		t.Fatal("a filter for notices skips the per-event check")
	}
}

func TestCheckSelfAuthored_ExtraKinds(t *testing.T) {
	forged := &nip01.Event{Kind: 44100, PubKey: secondTestPubKey(t)}
	if ok, _ := CheckSelfAuthored(forged, authTestPubKey); !ok {
		t.Fatal("44100 refused without being listed")
	}
	if ok, _ := CheckSelfAuthored(forged, authTestPubKey, 44100, 44101); ok {
		t.Fatal("a client-signed 44100 passed while listed as relay-authored")
	}
	own := &nip01.Event{Kind: 44100, PubKey: authTestPubKey}
	if ok, _ := CheckSelfAuthored(own, authTestPubKey, 44100); !ok {
		t.Fatal("the relay's own 44100 was refused")
	}
}
