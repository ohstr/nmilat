package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/wire"
)

// newGroupsEnabledTestSession builds a Session with a real, store-backed
// GroupsService wired in, the relay's own selfPubkey set to authTestPubKey
// (so relay-authored mirror events can be signed with authTestPrivKey), and
// PrivKey configured for the same reason.
func newGroupsEnabledTestSession(t *testing.T) *Session {
	t.Helper()
	store := newStore(t)
	cfg := defaultSessionConfig()
	cfg.PrivKey = authTestPrivKey
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{
		Self: authTestPubKey,
	}, nil, nil, cfg)
	sc.groups = NewGroupsService(store)
	return &Session{SessionContext: sc}
}

func createGroupEvent(t *testing.T, groupID string) *nip01.Event {
	t.Helper()
	ev := nip29.NewCreateGroup("", groupID)
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign create-group: %v", err)
	}
	return ev
}

func deleteGroupEvent(t *testing.T, groupID, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewDeleteGroup("", groupID)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign delete-group: %v", err)
	}
	return ev
}

/////////////////////////////////////////////////////////////////////
// kind:9007 create
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_CreateGroup_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	resp := sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}
	wantMsg := "info: group " + groupA + " created."
	if resp.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", resp.Message, wantMsg)
	}

	if !sess.groups.Exists(groupA) {
		t.Fatal("Exists() = false after a successful create, want true")
	}
	if !sess.groups.IsAdmin(groupA, authTestPubKey) {
		t.Fatal("IsAdmin(creator) = false after create, want true")
	}
	if !sess.groups.IsMember(groupA, authTestPubKey) {
		t.Fatal("IsMember(creator) = false after create, want true")
	}
	if !sess.groups.IsPrivate(groupA) {
		t.Fatal("IsPrivate() = false after create, want true (decision 2 default)")
	}

	ctx := context.Background()

	metaEvents, err := sess.store.QueryEvents(ctx, &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMetadata}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(metadata): %v", err)
	}
	if len(metaEvents) != 1 {
		t.Fatalf("stored kind:39000 events = %d, want 1", len(metaEvents))
	}
	if metaEvents[0].PubKey != authTestPubKey {
		t.Fatalf("kind:39000 PubKey = %s, want the relay's own self pubkey %s", metaEvents[0].PubKey, authTestPubKey)
	}
	meta, err := nip29.ParseGroupMetadata(metaEvents[0])
	if err != nil {
		t.Fatalf("ParseGroupMetadata: %v", err)
	}
	if meta.ID != groupA || !meta.Private || !meta.Closed {
		t.Fatalf("GroupMetadata = %+v, want ID=%s Private=true Closed=true", meta, groupA)
	}

	adminEvents, err := sess.store.QueryEvents(ctx, &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupAdmins}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(admins): %v", err)
	}
	if len(adminEvents) != 1 {
		t.Fatalf("stored kind:39001 events = %d, want 1", len(adminEvents))
	}
	admins, err := nip29.ParseGroupAdmins(adminEvents[0])
	if err != nil {
		t.Fatalf("ParseGroupAdmins: %v", err)
	}
	if len(admins.Admins) != 1 || admins.Admins[0].Pubkey != authTestPubKey {
		t.Fatalf("GroupAdmins = %+v, want just the creator (%s)", admins, authTestPubKey)
	}

	memberEvents, err := sess.store.QueryEvents(ctx, &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMembers}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(members): %v", err)
	}
	if len(memberEvents) != 1 {
		t.Fatalf("stored kind:39002 events = %d, want 1", len(memberEvents))
	}
	members, err := nip29.ParseGroupMembers(memberEvents[0])
	if err != nil {
		t.Fatalf("ParseGroupMembers: %v", err)
	}
	if !members.Contains(authTestPubKey) {
		t.Fatalf("GroupMembers = %+v, want to contain the creator (%s)", members, authTestPubKey)
	}
}

func TestHandleEvent_CreateGroup_Duplicate(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	otherPrivKey := "0000000000000000000000000000000000000000000000000000000000000001"
	ev := nip29.NewCreateGroup("", groupA)
	if err := ev.Sign(otherPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a duplicate create (message: %s)", resp.Message)
	}
	if resp.Message != "duplicate: a group with that id already exists." {
		t.Fatalf("Message = %q, want the spec's exact duplicate wording", resp.Message)
	}
	if !sess.groups.IsAdmin(groupA, authTestPubKey) {
		t.Fatal("the original creator should still be sole admin after a rejected duplicate create")
	}
	if sess.groups.IsAdmin(groupA, ev.PubKey) {
		t.Fatal("the duplicate attempt's signer should not have become admin")
	}
}

func TestHandleEvent_CreateGroup_MissingHTag(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	ev := &nip01.Event{Kind: nip29.KindCreateGroup}
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true for a create-group event with no h tag, want false")
	}
	wantMsg := "restricted: " + nip29.ErrMissingHTag.Error()
	if resp.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", resp.Message, wantMsg)
	}
}

func TestHandleEvent_NilGroups_RejectsCreateAndDelete(t *testing.T) {
	// No groups service wired in at all -- distinct from
	// newGroupsEnabledTestSession, which always sets one.
	sess := newSelfAuthTestSession(t, authTestPubKey)

	for _, ev := range []*nip01.Event{createGroupEvent(t, groupA), deleteGroupEvent(t, groupA, authTestPrivKey)} {
		resp := sendEventAndAwaitOKForSession(t, sess, ev)
		if resp.Accepted {
			t.Fatalf("Accepted = true for kind %d with no groups service configured, want false", ev.Kind)
		}
		if resp.Message != "restricted: NIP-29 group hosting is not enabled on this relay" {
			t.Fatalf("Message = %q, want the not-enabled wording", resp.Message)
		}
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9008 delete
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_DeleteGroup_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, groupA, authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a successful delete (message: %s)", resp.Message)
	}
	wantMsg := "info: group " + groupA + " deleted."
	if resp.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", resp.Message, wantMsg)
	}
	if sess.groups.Exists(groupA) {
		t.Fatal("Exists() = true after a successful delete, want false")
	}
}

func TestHandleEvent_DeleteGroup_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	otherPrivKey := "0000000000000000000000000000000000000000000000000000000000000001"
	resp := sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, groupA, otherPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for a delete signed by a non-admin, want false")
	}
	if resp.Message != "restricted: only a group admin may delete this group." {
		t.Fatalf("Message = %q, want the not-admin wording", resp.Message)
	}
	if !sess.groups.Exists(groupA) {
		t.Fatal("Exists() = false after a rejected delete, want true (group should survive)")
	}
}

func TestHandleEvent_DeleteGroup_NoSuchGroup(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	resp := sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, "no-such-group", authTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for deleting a non-existent group, want false")
	}
	if resp.Message != "restricted: no such group." {
		t.Fatalf("Message = %q, want the no-such-group wording", resp.Message)
	}
}

/////////////////////////////////////////////////////////////////////
// Visibility gating (REQ/COUNT)
/////////////////////////////////////////////////////////////////////

func groupDTagFilter(groupID string) *wire.RequestPacket {
	filter := &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupMetadata},
		Tags:  map[string][]string{"d": {groupID}},
		Limit: 10,
	}
	return &wire.RequestPacket{SubscriptionID: "sub-1", Filters: nip01.NewSubscriptionFilterGroup(filter)}
}

func TestProcessRequest_PrivateGroupVisibilityGate_DeniesNonMember(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	if err := sess.groups.Create(newGroupRecord(groupA, authTestPubKey)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := sess.processRequest(context.Background(), groupDTagFilter(groupA)); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	wantMsg := "restricted: valid membership in group " + groupA + " is required"

	notice, ok := (<-sess.incoming).(*wire.NoticeSubscriptionResponse)
	if !ok {
		t.Fatal("first reply was not a *wire.NoticeSubscriptionResponse")
	}
	if notice.Message != wantMsg {
		t.Fatalf("Notice.Message = %q, want %q", notice.Message, wantMsg)
	}

	closed, ok := (<-sess.incoming).(*wire.ClosedSubscriptionResponse)
	if !ok {
		t.Fatal("second reply was not a *wire.ClosedSubscriptionResponse")
	}
	if closed.Message != wantMsg {
		t.Fatalf("Closed.Message = %q, want %q", closed.Message, wantMsg)
	}
}

func TestProcessRequest_PrivateGroupVisibilityGate_AllowsMember(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	if err := sess.groups.Create(newGroupRecord(groupA, authTestPubKey)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.addIdentity(AuthedIdentity{Pubkey: authTestPubKey, Membership: MembershipNone})

	if err := sess.processRequest(context.Background(), groupDTagFilter(groupA)); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	if reply := <-sess.incoming; true {
		if notice, denied := reply.(*wire.NoticeSubscriptionResponse); denied {
			t.Fatalf("a member's REQ against its own private group was denied: %+v", notice)
		}
	}
}

func TestProcessRequest_PrivateGroupVisibilityGate_PublicGroupUnaffected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	rec := newGroupRecord(groupA, authTestPubKey)
	rec.Private = false
	if err := sess.groups.Create(rec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Deliberately no authenticated identity -- a public group must still
	// be reachable by a fully anonymous REQ.

	if err := sess.processRequest(context.Background(), groupDTagFilter(groupA)); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	if reply := <-sess.incoming; true {
		if notice, denied := reply.(*wire.NoticeSubscriptionResponse); denied {
			t.Fatalf("a public group's REQ was denied: %+v", notice)
		}
	}
}

func TestProcessRequest_PrivateGroupVisibilityGate_UnknownGroupUnaffected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	// No group created at all -- an id naming nothing has nothing to gate.

	if err := sess.processRequest(context.Background(), groupDTagFilter("no-such-group")); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	if reply := <-sess.incoming; true {
		if notice, denied := reply.(*wire.NoticeSubscriptionResponse); denied {
			t.Fatalf("a REQ for an unknown group id was denied: %+v", notice)
		}
	}
}

func TestProcessCount_PrivateGroupVisibilityGate_DeniesNonMember(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	if err := sess.groups.Create(newGroupRecord(groupA, authTestPubKey)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	filter := &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupMetadata},
		Tags:  map[string][]string{"d": {groupA}},
		Limit: 10,
	}
	cp := &wire.CountPacket{SubscriptionID: "sub-1", Filters: nip01.NewSubscriptionFilterGroup(filter)}

	if err := sess.processCount(context.Background(), cp); err != nil {
		t.Fatalf("processCount: %v", err)
	}

	notice, ok := (<-sess.incoming).(*wire.NoticeSubscriptionResponse)
	if !ok {
		t.Fatal("reply was not a *wire.NoticeSubscriptionResponse")
	}
	wantMsg := "restricted: valid membership in group " + groupA + " is required"
	if notice.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", notice.Message, wantMsg)
	}
}

func TestGroupIDsInFilter(t *testing.T) {
	filter := &nip01.SubscriptionFilter{Tags: map[string][]string{"d": {groupA}, "h": {groupB}}}
	got := groupIDsInFilter(filter)
	want := map[string]bool{groupA: true, groupB: true}
	if len(got) != 2 {
		t.Fatalf("groupIDsInFilter() = %v, want 2 entries", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("groupIDsInFilter() returned unexpected id %q", id)
		}
	}
}

func TestGroupIDsInFilter_NilFilter(t *testing.T) {
	if got := groupIDsInFilter(nil); got != nil {
		t.Fatalf("groupIDsInFilter(nil) = %v, want nil", got)
	}
}

func TestDeniedPrivateGroupFilter_NilSafety(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	var nilGroups *GroupsService
	if _, denied := nilGroups.deniedPrivateGroupFilter(sess, groupDTagFilter(groupA).Filters); denied {
		t.Fatal("nil *GroupsService.deniedPrivateGroupFilter() denied = true, want false")
	}

	if _, denied := sess.groups.deniedPrivateGroupFilter(sess, nil); denied {
		t.Fatal("deniedPrivateGroupFilter(nil filters) denied = true, want false")
	}
}
