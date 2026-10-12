package relay

import (
	"testing"

	"github.com/ohstr/nmilat/nip29"
)

// A privacy flip on a linked group is refused: it would leave the group
// and its parent, or a subgroup, on opposite sides of the public/private
// line the link check exists to keep together.
func TestHandleEvent_EditMetadata_PrivacyFlipOnLinkedGroup_Rejected(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // private parent
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB)) // private child
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true, Parent: groupA})); !resp.Accepted {
		t.Fatalf("link groupB under groupA: %s", resp.Message)
	}
	want := "restricted: cannot change the privacy of a linked group; its parent and subgroups must share the same setting, so detach it first."

	// The child goes public while keeping its private parent.
	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupA}))
	if resp.Accepted || resp.Message != want {
		t.Fatalf("child flip: accepted=%v %q", resp.Accepted, resp.Message)
	}
	// The parent goes public while keeping its private child.
	resp = sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Children: []string{groupB}}))
	if resp.Accepted || resp.Message != want {
		t.Fatalf("parent flip: accepted=%v %q", resp.Accepted, resp.Message)
	}
	if !sess.groups.IsPrivate(groupA) || !sess.groups.IsPrivate(groupB) {
		t.Fatal("a refused flip still changed a group's privacy")
	}

	// Detached, the child may flip.
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true})); !resp.Accepted {
		t.Fatalf("detach groupB: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{})); !resp.Accepted {
		t.Fatalf("flip detached groupB: %s", resp.Message)
	}
}

// An edit that reparents and flips privacy at once is judged by the new
// setting: a private group may go public and move under a public parent
// in one step, and back.
func TestHandleEvent_EditMetadata_ReparentWithPrivacyFlip_JudgedByNewSetting(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA)) // private
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, authTestPrivKey, nip29.GroupMetadataParams{})); !resp.Accepted {
		t.Fatalf("make groupB public: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Parent: groupB})); !resp.Accepted {
		t.Fatalf("go public under a public parent: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupA, authTestPrivKey, nip29.GroupMetadataParams{Private: true})); !resp.Accepted {
		t.Fatalf("detach and go private: %s", resp.Message)
	}
}
