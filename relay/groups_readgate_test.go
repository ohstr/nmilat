package relay

import (
	"testing"

	"github.com/ohstr/nmilat/nip29"
)

// readerFor returns a session sharing sess's groups, authenticated as pk.
func readerFor(t *testing.T, sess *Session, pk string) *Session {
	t.Helper()
	r := newGroupsEnabledTestSession(t)
	r.groups = sess.groups
	r.addIdentity(AuthedIdentity{Pubkey: pk, Membership: MembershipNone})
	return r
}

// Invite codes and pending join requests follow CanPerform, not "holds a
// role": a member whose only role carries no moderation kind reads
// neither, a moderator allowed 9000/9001 reads pending joins but not
// invites, and a key the host's authorizer allows 9009 reads invites.
func TestGroupReadGates_FollowCanPerform(t *testing.T) {
	sess := newCeilingSession(t, true)
	sess.groups.SetModerationLog(true)
	sess.groups.SetPendingJoins(true)
	vip := pubkeyOfPrivKey(t, thirdTestPrivKey)
	moderator := secondTestPubKey(t)
	// Under the grant ceiling, a moderator may give a role with no powers.
	if resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, vip, secondTestPrivKey, "vip")); !resp.Accepted {
		t.Fatalf("moderator granting vip: %s", resp.Message)
	}
	if !sess.groups.IsAdmin(groupA, vip) {
		t.Fatal("precondition: a vip holds a role")
	}
	sendEventAndAwaitOKForSession(t, sess, createInviteEvent(t, groupA, "secret-code", authTestPrivKey))
	invites := storedKinds(t, sess, nip29.KindCreateInvite)
	if len(invites) != 1 {
		t.Fatalf("stored 9009 = %d, want 1", len(invites))
	}
	sendEventAndAwaitOKForSession(t, sess, groupJoinRequestEvent(t, groupA, "", wrapperPrivKey))
	reqs := pendingJoins(t, sess)
	if len(reqs) != 1 {
		t.Fatalf("pending requests = %d, want 1", len(reqs))
	}

	for _, c := range []struct {
		name                string
		pk                  string
		invite, pendingJoin bool
	}{
		{"admin", authTestPubKey, true, true},
		{"moderator", moderator, false, true},
		{"vip", vip, false, false},
	} {
		r := readerFor(t, sess, c.pk)
		if got := !sess.groups.deniedPrivateGroupEvent(r, invites[0]); got != c.invite {
			t.Errorf("%s reads the invite: %v, want %v", c.name, got, c.invite)
		}
		if got := !sess.groups.deniedPrivateGroupEvent(r, reqs[0]); got != c.pendingJoin {
			t.Errorf("%s reads the pending join: %v, want %v", c.name, got, c.pendingJoin)
		}
	}

	// The host's authorizer widens both reads with the powers it grants.
	sess.groups.SetAuthorizer(func(_, pk string, kind int) bool {
		return pk == vip && (kind == nip29.KindCreateInvite || kind == nip29.KindPutUser)
	})
	r := readerFor(t, sess, vip)
	if sess.groups.deniedPrivateGroupEvent(r, invites[0]) {
		t.Error("a vip the authorizer allows 9009 was refused the invite")
	}
	if sess.groups.deniedPrivateGroupEvent(r, reqs[0]) {
		t.Error("a vip the authorizer allows 9000 was refused the pending join")
	}
}
