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
	rec.Metadata.Private = false
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

/////////////////////////////////////////////////////////////////////
// Phase 2 + Phase 3 event builders
/////////////////////////////////////////////////////////////////////

// secondTestPrivKey is a second, distinct keypair from authTestPrivKey's,
// used across these tests for "signed by someone who isn't the group's
// creator/admin."
const secondTestPrivKey = "0000000000000000000000000000000000000000000000000000000000000001"

func secondTestPubKey(t *testing.T) string {
	t.Helper()
	ev := &nip01.Event{Kind: 1}
	if err := ev.Sign(secondTestPrivKey); err != nil {
		t.Fatalf("derive secondTestPrivKey's pubkey: %v", err)
	}
	return ev.PubKey
}

func putUserEvent(t *testing.T, groupID, memberPubkey, privKey string, roles ...string) *nip01.Event {
	t.Helper()
	ev := nip29.NewPutUser("", groupID, memberPubkey, roles...)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign put-user: %v", err)
	}
	return ev
}

func removeUserEvent(t *testing.T, groupID, memberPubkey, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewRemoveUser("", groupID, memberPubkey)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign remove-user: %v", err)
	}
	return ev
}

func editMetadataEvent(t *testing.T, groupID, privKey string, p nip29.GroupMetadataParams) *nip01.Event {
	t.Helper()
	ev := nip29.NewEditMetadata("", groupID, p)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign edit-metadata: %v", err)
	}
	return ev
}

func deleteEventEvent(t *testing.T, groupID, eventID, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewDeleteEvent("", groupID, eventID)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign moderator delete-event: %v", err)
	}
	return ev
}

func createInviteEvent(t *testing.T, groupID, code, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewCreateInvite("", groupID, code)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign create-invite: %v", err)
	}
	return ev
}

func updatePinListEvent(t *testing.T, groupID, privKey string, events, addresses []string) *nip01.Event {
	t.Helper()
	ev := nip29.NewUpdatePinList("", groupID, events, addresses)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign update-pin-list: %v", err)
	}
	return ev
}

func groupJoinRequestEvent(t *testing.T, groupID, code, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewJoinRequest("", groupID, code, "")
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign group join-request: %v", err)
	}
	return ev
}

func groupLeaveRequestEvent(t *testing.T, groupID, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewLeaveRequest("", groupID, "")
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign group leave-request: %v", err)
	}
	return ev
}

/////////////////////////////////////////////////////////////////////
// kind:9000 put-user / kind:9001 remove-user
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_PutUser_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	newMember := secondTestPubKey(t)

	resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, newMember, authTestPrivKey, "moderator"))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}
	if !sess.groups.IsMember(groupA, newMember) {
		t.Fatal("IsMember(newMember) = false after put-user, want true")
	}
	rec, err := sess.groups.Get(groupA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if roles := rec.RolesFor(newMember); len(roles) != 1 || roles[0] != "moderator" {
		t.Fatalf("RolesFor(newMember) = %v, want [moderator]", roles)
	}

	members, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMembers}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(members): %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("stored kind:39002 events = %d, want 1 (republished after put-user)", len(members))
	}
	parsed, err := nip29.ParseGroupMembers(members[0])
	if err != nil {
		t.Fatalf("ParseGroupMembers: %v", err)
	}
	if !parsed.Contains(newMember) {
		t.Fatalf("republished GroupMembers = %+v, want to contain %s", parsed, newMember)
	}
}

func TestHandleEvent_PutUser_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	newMember := secondTestPubKey(t)

	resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, newMember, secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for a put-user signed by a non-admin, want false")
	}
	if resp.Message != "restricted: you may not add members to this group." {
		t.Fatalf("Message = %q, want the not-admin wording", resp.Message)
	}
	if sess.groups.IsMember(groupA, newMember) {
		t.Fatal("IsMember(newMember) = true after a rejected put-user, want false")
	}
}

func TestHandleEvent_PutUser_NoSuchGroup(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, "no-such-group", secondTestPubKey(t), authTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for put-user on a non-existent group, want false")
	}
	if resp.Message != "restricted: no such group." {
		t.Fatalf("Message = %q, want the no-such-group wording", resp.Message)
	}
}

func TestHandleEvent_RemoveUser_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	newMember := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, newMember, authTestPrivKey))

	resp := sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, newMember, authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}
	if sess.groups.IsMember(groupA, newMember) {
		t.Fatal("IsMember(newMember) = true after remove-user, want false")
	}
}

func TestHandleEvent_RemoveUser_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, authTestPubKey, secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for a remove-user signed by a non-admin, want false")
	}
	if resp.Message != "restricted: you may not remove members from this group." {
		t.Fatalf("Message = %q, want the not-admin wording", resp.Message)
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9002 edit-metadata
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_EditMetadata_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{
		Name: "renamed", Private: false, Closed: false,
	}))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}
	if sess.groups.IsPrivate(groupA) {
		t.Fatal("IsPrivate() after edit-metadata(Private: false) = true, want false")
	}
	if sess.groups.IsClosed(groupA) {
		t.Fatal("IsClosed() after edit-metadata(Closed: false) = true, want false")
	}

	metaEvents, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMetadata}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(metadata): %v", err)
	}
	if len(metaEvents) != 1 {
		t.Fatalf("stored kind:39000 events = %d, want 1 (republished after edit-metadata)", len(metaEvents))
	}
	meta, err := nip29.ParseGroupMetadata(metaEvents[0])
	if err != nil {
		t.Fatalf("ParseGroupMetadata: %v", err)
	}
	if meta.Name != "renamed" || meta.Private || meta.Closed {
		t.Fatalf("republished GroupMetadata = %+v, want Name=renamed Private=false Closed=false", meta)
	}
}

func TestHandleEvent_EditMetadata_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, secondTestPrivKey, nip29.GroupMetadataParams{Private: false}))
	if resp.Accepted {
		t.Fatal("Accepted = true for edit-metadata signed by a non-admin, want false")
	}
	if !sess.groups.IsPrivate(groupA) {
		t.Fatal("a rejected edit-metadata should not have changed Private")
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9005 moderator delete-event
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_DeleteEvent_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	target := CreateEvent(t, 1, []string{"h", groupA})
	if err := sess.store.InsertEvents(context.Background(), []*nip01.Event{target}); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, deleteEventEvent(t, groupA, target.ID, authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}

	got, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{IDs: []string{target.ID}, Limit: 1})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 0 {
		t.Fatal("target event still present after a successful moderator delete, want gone")
	}
}

func TestHandleEvent_DeleteEvent_WrongGroup(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))

	target := CreateEvent(t, 1, []string{"h", groupB})
	if err := sess.store.InsertEvents(context.Background(), []*nip01.Event{target}); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	// groupA's admin tries to delete an event that belongs to groupB.
	resp := sendEventAndAwaitOKForSession(t, sess, deleteEventEvent(t, groupA, target.ID, authTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for deleting an event that belongs to a different group, want false")
	}
	if resp.Message != "restricted: that event does not belong to this group." {
		t.Fatalf("Message = %q, want the wrong-group wording", resp.Message)
	}

	got, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{IDs: []string{target.ID}, Limit: 1})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatal("target event should survive a rejected cross-group delete")
	}
}

func TestHandleEvent_DeleteEvent_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	target := CreateEvent(t, 1, []string{"h", groupA})
	if err := sess.store.InsertEvents(context.Background(), []*nip01.Event{target}); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, deleteEventEvent(t, groupA, target.ID, secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for a moderator delete signed by a non-admin, want false")
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9009 create-invite
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_CreateInvite_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "my-code", authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}

	inv, err := sess.store.GetGroupInvite(groupA, "my-code")
	if err != nil {
		t.Fatalf("GetGroupInvite: %v", err)
	}
	if inv == nil || inv.Used {
		t.Fatalf("GetGroupInvite() = %+v, want a fresh, unused invite", inv)
	}
}

func TestHandleEvent_CreateInvite_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "my-code", secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for create-invite signed by a non-admin, want false")
	}
	if inv, _ := sess.store.GetGroupInvite(groupA, "my-code"); inv != nil {
		t.Fatal("a rejected create-invite should not have persisted anything")
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9010 update-pin-list
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_UpdatePinList_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, updatePinListEvent(t, groupA, authTestPrivKey, []string{authTestPubKey}, nil))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}

	pinEvents, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupPinnedEvents}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents(pins): %v", err)
	}
	if len(pinEvents) != 1 {
		t.Fatalf("stored kind:39005 events = %d, want 1", len(pinEvents))
	}
}

func TestHandleEvent_UpdatePinList_NotAdmin(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, updatePinListEvent(t, groupA, secondTestPrivKey, nil, nil))
	if resp.Accepted {
		t.Fatal("Accepted = true for update-pin-list signed by a non-admin, want false")
	}
}

/////////////////////////////////////////////////////////////////////
// kind:9021 group join / kind:9022 group leave
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_GroupJoin_OpenGroup(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Closed: false}))

	joiner := secondTestPubKey(t)
	resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", secondTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for joining an open group (message: %s)", resp.Message)
	}
	if !sess.groups.IsMember(groupA, joiner) {
		t.Fatal("IsMember(joiner) = false after a successful open-group join, want true")
	}
}

func TestHandleEvent_GroupJoin_ClosedGroup_NoCode(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // closed by default

	resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", secondTestPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for joining a closed group with no code, want false")
	}
	if sess.groups.IsMember(groupA, secondTestPubKey(t)) {
		t.Fatal("a rejected join should not have added a member")
	}
}

func TestHandleEvent_GroupJoin_ClosedGroup_ValidCode(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "secret", authTestPrivKey))

	joiner := secondTestPubKey(t)
	resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "secret", secondTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a closed group with a valid code (message: %s)", resp.Message)
	}
	if !sess.groups.IsMember(groupA, joiner) {
		t.Fatal("IsMember(joiner) = false after a successful invite-code join, want true")
	}

	// The code is single-use -- a second join attempt with the same code,
	// from a different pubkey, must fail.
	thirdPrivKey := "0000000000000000000000000000000000000000000000000000000000000002"
	resp = sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "secret", thirdPrivKey))
	if resp.Accepted {
		t.Fatal("Accepted = true for reusing an already-consumed invite code, want false")
	}
}

func TestHandleEvent_GroupJoin_AlreadyMember(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for an already-member duplicate join (message: %s)", resp.Message)
	}
	if resp.Message != nip29.DuplicateErrorPrefix+"you are already a member of this group." {
		t.Fatalf("Message = %q, want the duplicate wording", resp.Message)
	}
}

func TestHandleEvent_GroupLeave_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	member := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, member, authTestPrivKey))

	resp := sendEventAndAwaitOKForSession(t, sess, groupLeaveRequestEvent(t, groupA, secondTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}
	if sess.groups.IsMember(groupA, member) {
		t.Fatal("IsMember(member) = true after a successful leave, want false")
	}
}

func TestHandleEvent_GroupLeave_NotAMember(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, groupLeaveRequestEvent(t, groupA, secondTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a non-member leave (message: %s)", resp.Message)
	}
	if resp.Message != nip29.DuplicateErrorPrefix+"you are not a member of this group." {
		t.Fatalf("Message = %q, want the non-member-leave wording", resp.Message)
	}
}

/////////////////////////////////////////////////////////////////////
// Unsupported moderation kind (default case)
/////////////////////////////////////////////////////////////////////

func TestHandleEvent_UnsupportedModerationKind(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	ev := &nip01.Event{Kind: 9011, Tags: [][]string{{"h", groupA}}}
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true for an unsupported moderation kind, want false")
	}
	if resp.Message != "restricted: unsupported NIP-29 event kind" {
		t.Fatalf("Message = %q, want the unsupported-kind wording", resp.Message)
	}
}
