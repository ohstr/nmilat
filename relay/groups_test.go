package relay

import (
	"context"
	"fmt"
	"sync"
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

func TestProcessRequest_PrivateGroupVisibilityGate_UnknownGroupDeniedLikePrivate(t *testing.T) {
	// A REQ naming a group that doesn't exist at all must get the exact
	// same restricted response a private-no-access group gets -- not a
	// distinct "(nothing found)" success. Otherwise an unauthenticated
	// prober could brute-force group ids and learn, from the response
	// shape alone, which ones exist and are private (attack-surface
	// finding 2). See deniedPrivateGroupFilter's own doc comment.
	sess := newGroupsEnabledTestSession(t)
	// No group created at all.

	if err := sess.processRequest(context.Background(), groupDTagFilter("no-such-group")); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	wantMsg := "restricted: valid membership in group no-such-group is required"

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

func TestProcessCount_PrivateGroupVisibilityGate_UnknownGroupDeniedLikePrivate(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)

	filter := &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupMetadata},
		Tags:  map[string][]string{"d": {"no-such-group"}},
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
	wantMsg := "restricted: valid membership in group no-such-group is required"
	if notice.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", notice.Message, wantMsg)
	}
}

// TestProcessCount_UntaggedGroupMetadataQuery_ExcludesPrivateGroups is the
// COUNT-side counterpart of the #66/#67 REQ fix: an untagged
// {"kinds":[39000]} filter names no group, so deniedPrivateGroupFilter
// has nothing to key off and never fires -- but a raw CountEvents would
// then report every group on the relay, private ones included, a number
// the equivalent REQ could never actually deliver that many events for
// (attack-surface finding 1). Written failing-first against the
// unfixed processCount, confirmed green only once CountEventsFiltered is
// wired in.
func TestProcessCount_UntaggedGroupMetadataQuery_ExcludesPrivateGroups(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	// Must go through the real event-processing path (not
	// GroupsService.Create directly) so an actual signed kind:39000
	// lands in the general event store CountEvents scans -- Create alone
	// only touches the groups-specific cache/bbolt store the tag-based
	// filter gate reads, never publishing a mirror event.
	if resp := sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)); !resp.Accepted {
		t.Fatalf("create groupA: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB)); !resp.Accepted {
		t.Fatalf("create groupB: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Private: false, Closed: false})); !resp.Accepted {
		t.Fatalf("make groupB public: %s", resp.Message)
	}

	cp := &wire.CountPacket{
		SubscriptionID: "sub-1",
		Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{nip29.KindGroupMetadata}}),
	}

	// Anonymous session: no identity authenticated on it at all.
	if err := sess.processCount(context.Background(), cp); err != nil {
		t.Fatalf("processCount: %v", err)
	}

	resp, ok := (<-sess.incoming).(*wire.CountSubscriptionResponse)
	if !ok {
		t.Fatal("reply was not a *wire.CountSubscriptionResponse (expected a count, not a denial, for an untagged query)")
	}
	if resp.Count != 1 {
		t.Fatalf("Count = %d, want 1 (only the public group -- groupA is private and this session has no identity)", resp.Count)
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
// NIP-29 "Subgroups" (parent/child linkage)
/////////////////////////////////////////////////////////////////////

// thirdTestPrivKey is a third, distinct keypair from authTestPrivKey's and
// secondTestPrivKey's -- used where a test needs two groups with two
// genuinely different admins (e.g. the cross-group admin check).
const thirdTestPrivKey = "0000000000000000000000000000000000000000000000000000000000000002"

// createGroupEventSignedBy is createGroupEvent with an explicit signer,
// for tests that need two groups owned by two different admins.
func createGroupEventSignedBy(t *testing.T, groupID, privKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewCreateGroup("", groupID)
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign create-group: %v", err)
	}
	return ev
}

// groupMetadata fetches id's current kind:39000 mirror and parses it,
// failing the test on any error -- used throughout these tests instead
// of reaching into sess.groups directly, so assertions reflect exactly
// what a reader of the republished event would see.
func groupMetadata(t *testing.T, sess *Session, id string) *nip29.GroupMetadata {
	t.Helper()
	events, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupMetadata},
		Tags:  map[string][]string{"d": {id}},
		Limit: 1,
	})
	if err != nil {
		t.Fatalf("QueryEvents(metadata for %s): %v", id, err)
	}
	if len(events) == 0 {
		t.Fatalf("group %q has no kind:39000 mirror", id)
	}
	meta, err := nip29.ParseGroupMetadata(events[0])
	if err != nil {
		t.Fatalf("ParseGroupMetadata(%s): %v", id, err)
	}
	return meta
}

func TestHandleEvent_EditMetadata_SetParent_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA}))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}

	if child := groupMetadata(t, sess, groupB); child.Parent != groupA {
		t.Fatalf("groupB's own Parent = %q, want %q", child.Parent, groupA)
	}
	parent := groupMetadata(t, sess, groupA)
	if len(parent.Children) != 1 || parent.Children[0] != groupB {
		t.Fatalf("groupA's Children = %v, want [%s]", parent.Children, groupB)
	}
}

func TestHandleEvent_EditMetadata_SetParent_SelfReference_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a group naming itself as its own parent, want false")
	}
	if resp.Message != "restricted: a group cannot be its own parent." {
		t.Fatalf("Message = %q, want the self-reference wording", resp.Message)
	}
}

func TestHandleEvent_EditMetadata_SetParent_NonexistentParent_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Parent: "no-such-group"}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a parent that doesn't exist, want false")
	}
	if resp.Message != "restricted: the named parent group does not exist." {
		t.Fatalf("Message = %q, want the nonexistent-parent wording", resp.Message)
	}
}

func TestHandleEvent_EditMetadata_SetParent_Cycle_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))

	// groupB's parent is groupA.
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA})); !resp.Accepted {
		t.Fatalf("set groupB's parent to groupA: %s", resp.Message)
	}

	// groupA's parent -> groupB would close the loop A -> B -> A.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupB}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a parent assignment that creates a cycle, want false")
	}
	if resp.Message != "restricted: that parent assignment would create a cycle." {
		t.Fatalf("Message = %q, want the cycle wording", resp.Message)
	}
}

func TestHandleEvent_EditMetadata_SetParent_NotAdminOfNewParent_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))                           // admin: authTestPubKey
	sendEventAndAwaitOKForSession(t, sess, createGroupEventSignedBy(t, groupC, thirdTestPrivKey)) // admin: thirdTestPubKey

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupC}))
	if resp.Accepted {
		t.Fatal("Accepted = true when the submitter isn't an admin of the new parent, want false")
	}
	if resp.Message != "restricted: you must also be an admin of the new parent group." {
		t.Fatalf("Message = %q, want the cross-admin wording", resp.Message)
	}
}

func TestHandleEvent_EditMetadata_SetParent_PrivacyBoundary_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // private+closed by default
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Private: false})); !resp.Accepted {
		t.Fatalf("make groupB public: %s", resp.Message)
	}

	// groupA (private) linking to groupB (public) would let every viewer
	// of groupB's public child tag learn groupA's id regardless of
	// membership.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true, Parent: groupB}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a reparent crossing the public/private boundary, want false")
	}
	if resp.Message != "restricted: cannot link groups with different privacy settings." {
		t.Fatalf("Message = %q, want the privacy-boundary wording", resp.Message)
	}
}

func TestHandleEvent_EditMetadata_Reparent_OldParentLosesChild_NewParentGainsChild(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	for _, id := range []string{groupA, groupB, groupC} {
		sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, id))
	}

	// Private/Closed set explicitly on every edit below: kind:9002 is a
	// full replace (the already-documented footgun), so an edit that
	// only names Parent would otherwise flip the group public+open as a
	// side effect -- which would then trip the privacy-boundary check
	// against a still-private sibling for an unrelated reason.
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true})); !resp.Accepted {
		t.Fatalf("set groupC's parent to groupA: %s", resp.Message)
	}
	if parent := groupMetadata(t, sess, groupA); len(parent.Children) != 1 || parent.Children[0] != groupC {
		t.Fatalf("groupA's Children after first parent = %v, want [%s]", parent.Children, groupC)
	}

	// groupC switches from groupA to groupB. groupC currently has no
	// children of its own, so the completeness check doesn't apply to
	// groupC's own edit -- only to groupA/groupB, updated as a
	// consequence, never through this same kind:9002 event.
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupB, Private: true, Closed: true})); !resp.Accepted {
		t.Fatalf("reparent groupC to groupB: %s", resp.Message)
	}

	if parent := groupMetadata(t, sess, groupA); len(parent.Children) != 0 {
		t.Fatalf("groupA's Children after losing groupC = %v, want none", parent.Children)
	}
	if parent := groupMetadata(t, sess, groupB); len(parent.Children) != 1 || parent.Children[0] != groupC {
		t.Fatalf("groupB's Children after gaining groupC = %v, want [%s]", parent.Children, groupC)
	}
	if child := groupMetadata(t, sess, groupC); child.Parent != groupB {
		t.Fatalf("groupC's own Parent = %q, want %q", child.Parent, groupB)
	}
}

func TestHandleEvent_EditMetadata_ChildrenList_OmittedOnUnrelatedEdit_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA})); !resp.Accepted {
		t.Fatalf("set groupB's parent to groupA: %s", resp.Message)
	}

	// A plain rename of groupA, with no Children field at all -- must not
	// silently detach groupB.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Name: "renamed"}))
	if resp.Accepted {
		t.Fatal("Accepted = true for an edit that silently omits an existing child, want false")
	}
	if resp.Message != "restricted: this edit must re-list every current subgroup; none may be added or omitted here." {
		t.Fatalf("Message = %q, want the children-completeness wording", resp.Message)
	}
	if parent := groupMetadata(t, sess, groupA); len(parent.Children) != 1 || parent.Children[0] != groupB {
		t.Fatalf("groupA's Children after the rejected edit = %v, want unchanged [%s]", parent.Children, groupB)
	}
}

func TestHandleEvent_EditMetadata_ChildrenList_UnilateralAnnex_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // no children yet
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupC)) // never named groupA as its parent

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Children: []string{groupC}}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a parent unilaterally annexing a non-consenting group, want false")
	}
	if resp.Message != "restricted: this edit must re-list every current subgroup; none may be added or omitted here." {
		t.Fatalf("Message = %q, want the children-completeness wording", resp.Message)
	}
	if child := groupMetadata(t, sess, groupC); child.Parent != "" {
		t.Fatalf("groupC's own Parent = %q, want still unset", child.Parent)
	}
}

func TestHandleEvent_EditMetadata_ChildrenList_ValidReorder_Success(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	for _, id := range []string{groupA, groupB, groupC} {
		sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, id))
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA})); !resp.Accepted {
		t.Fatalf("set groupB's parent: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA})); !resp.Accepted {
		t.Fatalf("set groupC's parent: %s", resp.Message)
	}

	// groupA's admin reorders its own children, listing every one of
	// them (just in a different order) -- allowed.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Children: []string{groupC, groupB}}))
	if !resp.Accepted {
		t.Fatalf("Accepted = false for a valid reorder, want true (message: %s)", resp.Message)
	}
	parent := groupMetadata(t, sess, groupA)
	if len(parent.Children) != 2 || parent.Children[0] != groupC || parent.Children[1] != groupB {
		t.Fatalf("groupA's Children after reorder = %v, want [%s %s]", parent.Children, groupC, groupB)
	}
}

func TestHandleEvent_DeleteGroup_CascadesChildrenToRoot(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	for _, id := range []string{groupA, groupB, groupC} {
		sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, id))
	}
	sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA}))
	sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA}))

	resp := sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, groupA, authTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("delete groupA: %s", resp.Message)
	}

	if child := groupMetadata(t, sess, groupB); child.Parent != "" {
		t.Fatalf("groupB's Parent after its parent was deleted = %q, want root (empty)", child.Parent)
	}
	if child := groupMetadata(t, sess, groupC); child.Parent != "" {
		t.Fatalf("groupC's Parent after its parent was deleted = %q, want root (empty)", child.Parent)
	}
}

func TestHandleEvent_EditMetadata_EmptyParent_MeansDetachToRoot(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true})); !resp.Accepted {
		t.Fatalf("set groupB's parent: %s", resp.Message)
	}

	// Omitting Parent entirely (the Go zero value) on a group that
	// currently has one is exactly how NIP-29 detaches to root -- there
	// is no separate "explicit empty" tag form, absence is the signal.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true}))
	if !resp.Accepted {
		t.Fatalf("Accepted = false for detaching to root, want true (message: %s)", resp.Message)
	}
	if child := groupMetadata(t, sess, groupB); child.Parent != "" {
		t.Fatalf("groupB's Parent after detaching = %q, want root (empty)", child.Parent)
	}
	if parent := groupMetadata(t, sess, groupA); len(parent.Children) != 0 {
		t.Fatalf("groupA's Children after groupB detached = %v, want none", parent.Children)
	}
}

func TestHandleEvent_EditMetadata_RevokedAdminReplay_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	secondPubkey := secondTestPubKey(t)

	if resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, secondPubkey, authTestPrivKey, "admin")); !resp.Accepted {
		t.Fatalf("grant admin: %s", resp.Message)
	}
	// Build (but don't yet submit) an edit signed by the now-admin --
	// mirrors a client that pre-signs and holds an event for later.
	pendingEdit := editMetadataEvent(t, groupA, secondTestPrivKey, nip29.GroupMetadataParams{Name: "renamed-by-second", Private: true, Closed: true})

	if resp := sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, secondPubkey, authTestPrivKey)); !resp.Accepted {
		t.Fatalf("revoke admin: %s", resp.Message)
	}

	// The event's signature is still perfectly valid -- CanPerform must
	// check the group's *current* roster at processing time, not
	// whatever was true when the event was signed.
	resp := sendEventAndAwaitOKForSession(t, sess, pendingEdit)
	if resp.Accepted {
		t.Fatal("Accepted = true for an edit signed by an admin since revoked, want false")
	}
	if meta := groupMetadata(t, sess, groupA); meta.Name == "renamed-by-second" {
		t.Fatal("the revoked admin's edit should not have taken effect")
	}
}

func TestHandleEvent_EditMetadata_ConcurrentReparent_SameChildTwoNewParents_RaceSafe(t *testing.T) {
	store := newStore(t)
	groups := NewGroupsService(store)
	newSess := func() *Session {
		cfg := defaultSessionConfig()
		cfg.PrivKey = authTestPrivKey
		sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{Self: authTestPubKey}, nil, nil, cfg)
		sc.groups = groups
		return &Session{SessionContext: sc}
	}
	setup := newSess()
	for _, id := range []string{groupA, groupB, groupC} {
		sendEventAndAwaitOKForSession(t, setup, createGroupEvent(t, id))
	}

	sess1, sess2 := newSess(), newSess()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sendEventAndAwaitOKForSession(t, sess1, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA, Private: true, Closed: true}))
	}()
	go func() {
		defer wg.Done()
		sendEventAndAwaitOKForSession(t, sess2, editMetadataEvent(t, groupC, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupB, Private: true, Closed: true}))
	}()
	wg.Wait()

	child := groupMetadata(t, setup, groupC)
	if child.Parent != groupA && child.Parent != groupB {
		t.Fatalf("groupC's final Parent = %q, want groupA or groupB (one consistent winner)", child.Parent)
	}
	aHasC := contains(groupMetadata(t, setup, groupA).Children, groupC)
	bHasC := contains(groupMetadata(t, setup, groupB).Children, groupC)
	if aHasC == bHasC {
		t.Fatalf("groupA has groupC = %v, groupB has groupC = %v -- want exactly one true, matching groupC's own Parent (%q)", aHasC, bHasC, child.Parent)
	}
	winnerHasC := aHasC
	if child.Parent == groupB {
		winnerHasC = bHasC
	}
	if !winnerHasC {
		t.Fatalf("groupC's Parent (%q) does not match which group's Children lists it -- inconsistent cross-reference", child.Parent)
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func TestHandleEvent_EditMetadata_DeepAncestorChain_CycleCheckTerminatesAndIsCorrect(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	const chainLength = 40
	ids := make([]string, chainLength)
	for i := range ids {
		ids[i] = fmt.Sprintf("chain-%d", i)
		sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, ids[i]))
	}
	// Link ids[1]->ids[0], ids[2]->ids[1], ..., a chainLength-deep chain,
	// none of it a cycle.
	for i := 1; i < chainLength; i++ {
		resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, ids[i], authTestPrivKey, nip29.GroupMetadataParams{Parent: ids[i-1], Private: true, Closed: true}))
		if !resp.Accepted {
			t.Fatalf("link %s -> %s: %s", ids[i], ids[i-1], resp.Message)
		}
	}

	// The root (ids[0]) attempting to adopt the tail as its own parent
	// would close a chainLength-deep loop -- must still be caught, not
	// time out or silently succeed.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, ids[0], authTestPrivKey, nip29.GroupMetadataParams{Parent: ids[chainLength-1], Private: true, Closed: true}))
	if resp.Accepted {
		t.Fatal("Accepted = true for a parent assignment closing a long chain into a cycle, want false")
	}
	if resp.Message != "restricted: that parent assignment would create a cycle." {
		t.Fatalf("Message = %q, want the cycle wording", resp.Message)
	}

	// A legitimate, non-cyclic extension of the same long chain must
	// still resolve correctly (the walk terminates on reaching the root,
	// not just on rejecting a cycle).
	extra := "chain-extra"
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, extra))
	resp = sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, extra, authTestPrivKey, nip29.GroupMetadataParams{Parent: ids[chainLength-1], Private: true, Closed: true}))
	if !resp.Accepted {
		t.Fatalf("Accepted = false for extending the chain one further, want true (message: %s)", resp.Message)
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
