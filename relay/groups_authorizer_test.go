package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
)

// ceilingPolicy has a full admin, a moderator that can add, remove and
// delete events, and a helper that can only delete events.
var ceilingPolicy = nip29.ModerationPolicy{
	"admin":     defaultGroupModerationPolicy["admin"],
	"moderator": {nip29.KindPutUser, nip29.KindRemoveUser, nip29.KindDeleteEvent},
	"helper":    {nip29.KindDeleteEvent},
}

// newCeilingSession returns a session hosting groupA, created by
// authTestPubKey (admin), with secondTestPrivKey's key as its moderator.
func newCeilingSession(t *testing.T, ceiling bool) *Session {
	t.Helper()
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetModerationPolicy(ceilingPolicy)
	sess.groups.SetGrantCeiling(ceiling)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, secondTestPubKey(t), authTestPrivKey, "moderator"))
	if !resp.Accepted {
		t.Fatalf("admin adding a moderator: %s", resp.Message)
	}
	return sess
}

func rolesOf(t *testing.T, sess *Session, pubkey string) []string {
	t.Helper()
	rec, err := sess.groups.Get(groupA)
	if err != nil || rec == nil {
		t.Fatalf("Get(%s): %v", groupA, err)
	}
	return rec.RolesFor(pubkey)
}

func TestGroupsService_SetAuthorizer(t *testing.T) {
	var nilSvc *GroupsService
	nilSvc.SetAuthorizer(func(string, string, int) bool { return true })
	nilSvc.SetGrantCeiling(true)

	svc := NewGroupsService(newStore(t))
	if err := svc.Create(newGroupRecord(groupA, memberA)); err != nil {
		t.Fatal(err)
	}
	if svc.CanPerform(groupA, memberB, nip29.KindDeleteEvent) {
		t.Fatal("a non-member may delete events before any authorizer is set")
	}

	type call struct {
		group, pubkey string
		kind          int
	}
	var calls []call
	svc.SetAuthorizer(func(groupID, pubkey string, kind int) bool {
		calls = append(calls, call{groupID, pubkey, kind})
		return pubkey == memberB && kind == nip29.KindDeleteEvent
	})
	if !svc.CanPerform(groupA, memberB, nip29.KindDeleteEvent) {
		t.Fatal("the authorizer's grant is not honoured")
	}
	if want := (call{groupA, memberB, nip29.KindDeleteEvent}); len(calls) != 1 || calls[0] != want {
		t.Fatalf("authorizer calls = %+v, want [%+v]", calls, want)
	}
	if svc.CanPerform(groupA, memberB, nip29.KindDeleteGroup) {
		t.Fatal("a kind the authorizer refuses is allowed")
	}
	if svc.CanPerform("no-such-group", memberB, nip29.KindDeleteEvent) {
		t.Fatal("the authorizer is consulted for a group that isn't hosted")
	}
	// The policy still answers first: the creator is never asked about.
	calls = nil
	if !svc.CanPerform(groupA, memberA, nip29.KindPutUser) || len(calls) != 0 {
		t.Fatalf("policy-allowed CanPerform consulted the authorizer: %+v", calls)
	}

	svc.SetAuthorizer(nil)
	if svc.CanPerform(groupA, memberB, nip29.KindDeleteEvent) {
		t.Fatal("SetAuthorizer(nil) left the old authorizer in place")
	}
}

// Every moderation path asks CanPerform, so a key the authorizer allows
// can act in a group it holds no seat in -- and only for the kinds allowed.
func TestHandleEvent_AuthorizerModerates(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	mod := secondTestPubKey(t)
	sess.groups.SetAuthorizer(func(_, pubkey string, kind int) bool {
		return pubkey == mod && kind != nip29.KindDeleteGroup
	})

	third := pubkeyOfPrivKey(t, thirdTestPrivKey)
	for name, ev := range map[string]*nip01.Event{
		"put-user":    putUserEvent(t, groupA, third, secondTestPrivKey),
		"invite":      createInviteEvent(t, groupA, "code-1", secondTestPrivKey),
		"pins":        updatePinListEvent(t, groupA, secondTestPrivKey, nil, nil),
		"edit+parent": editMetadataEvent(t, groupB, secondTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true, Parent: groupA}),
	} {
		if resp := sendEventAndAwaitOKForSession(t, sess, ev); !resp.Accepted {
			t.Fatalf("%s by an authorized key refused: %s", name, resp.Message)
		}
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, third, secondTestPrivKey)); !resp.Accepted {
		t.Fatalf("remove-user by an authorized key refused: %s", resp.Message)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, deleteGroupEvent(t, groupA, secondTestPrivKey)); resp.Accepted {
		t.Fatal("delete-group allowed although the authorizer refuses kind 9008")
	}
}

// Linking under a parent needs kind 9002 in the parent, not just a role.
func TestHandleEvent_EditMetadata_ParentNeedsEditRight(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.groups.SetModerationPolicy(ceilingPolicy)
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupA))
	sendEventAndAwaitOKForSession(t, sess, createGroupEvent(t, groupB))
	mod := secondTestPubKey(t)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, mod, authTestPrivKey, "moderator"))
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupB, mod, authTestPrivKey, "admin"))

	resp := sendEventAndAwaitOKForSession(t, sess, editMetadataEvent(t, groupB, secondTestPrivKey, nip29.GroupMetadataParams{Private: true, Closed: true, Parent: groupA}))
	if resp.Accepted || resp.Message != "restricted: you must also be an admin of the new parent group." {
		t.Fatalf("link under a parent the sender holds no 9002 in: accepted=%v %q", resp.Accepted, resp.Message)
	}
}

// Off, the default, a moderator allowed kind:9000 may still give itself
// any role -- today's behaviour, unchanged.
func TestGrantCeiling_OffByDefault(t *testing.T) {
	sess := newCeilingSession(t, false)
	mod := secondTestPubKey(t)
	resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, mod, secondTestPrivKey, "admin"))
	if !resp.Accepted {
		t.Fatalf("self-grant with the ceiling off refused: %s", resp.Message)
	}
	resp = sendEventAndAwaitOKForSession(t, sess, removeUserEvent(t, groupA, authTestPubKey, secondTestPrivKey))
	if !resp.Accepted {
		t.Fatalf("removing the creator with the ceiling off refused: %s", resp.Message)
	}
}

func TestGrantCeiling(t *testing.T) {
	mod := func(t *testing.T) string { return secondTestPubKey(t) }
	third := func(t *testing.T) string { return pubkeyOfPrivKey(t, thirdTestPrivKey) }

	cases := []struct {
		name    string
		setup   func(t *testing.T, sess *Session)
		ev      func(t *testing.T) *nip01.Event
		wantOK  bool
		wantMsg string
	}{
		{
			name: "moderator granting itself admin",
			ev: func(t *testing.T) *nip01.Event {
				return putUserEvent(t, groupA, mod(t), secondTestPrivKey, "moderator", "admin")
			},
			wantMsg: "restricted: you may not grant a role with powers you do not hold.",
		},
		{
			name:    "moderator granting admin to another member",
			ev:      func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, third(t), secondTestPrivKey, "admin") },
			wantMsg: "restricted: you may not grant a role with powers you do not hold.",
		},
		{
			name: "admin granting moderator",
			ev: func(t *testing.T) *nip01.Event {
				return putUserEvent(t, groupA, third(t), authTestPrivKey, "moderator")
			},
			wantOK: true,
		},
		{
			name:   "moderator granting a role within its powers",
			ev:     func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, third(t), secondTestPrivKey, "helper") },
			wantOK: true,
		},
		{
			name:   "moderator granting a role the policy gives nothing",
			ev:     func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, third(t), secondTestPrivKey, "vip") },
			wantOK: true,
		},
		{
			name: "moderator re-listing itself unchanged",
			ev: func(t *testing.T) *nip01.Event {
				return putUserEvent(t, groupA, mod(t), secondTestPrivKey, "moderator")
			},
			wantOK: true,
		},
		{
			name:    "moderator removing the admin",
			ev:      func(t *testing.T) *nip01.Event { return removeUserEvent(t, groupA, authTestPubKey, secondTestPrivKey) },
			wantMsg: "restricted: you may not remove a member with powers you do not hold.",
		},
		{
			name:    "moderator stripping the admin's role",
			ev:      func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, authTestPubKey, secondTestPrivKey) },
			wantMsg: "restricted: you may not take roles from a member with powers you do not hold.",
		},
		{
			name: "moderator removing a helper",
			setup: func(t *testing.T, sess *Session) {
				sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, third(t), authTestPrivKey, "helper"))
			},
			ev:     func(t *testing.T) *nip01.Event { return removeUserEvent(t, groupA, third(t), secondTestPrivKey) },
			wantOK: true,
		},
		{
			name: "moderator stripping a helper",
			setup: func(t *testing.T, sess *Session) {
				sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, third(t), authTestPrivKey, "helper"))
			},
			ev:     func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, third(t), secondTestPrivKey) },
			wantOK: true,
		},
		{
			name:   "admin stripping the moderator",
			ev:     func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, mod(t), authTestPrivKey) },
			wantOK: true,
		},
		{
			name: "relay admin removing the creator",
			setup: func(t *testing.T, sess *Session) {
				sess.groups.SetRelayAdmins(third(t))
			},
			ev:     func(t *testing.T) *nip01.Event { return removeUserEvent(t, groupA, authTestPubKey, thirdTestPrivKey) },
			wantOK: true,
		},
		{
			name: "key the authorizer gives every kind granting admin",
			setup: func(t *testing.T, sess *Session) {
				m := mod(t)
				sess.groups.SetAuthorizer(func(_, pubkey string, _ int) bool { return pubkey == m })
			},
			ev:     func(t *testing.T) *nip01.Event { return putUserEvent(t, groupA, mod(t), secondTestPrivKey, "admin") },
			wantOK: true,
		},
		{
			name: "member the authorizer empowers is protected from a moderator",
			setup: func(t *testing.T, sess *Session) {
				th := third(t)
				sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, th, authTestPrivKey))
				sess.groups.SetAuthorizer(func(_, pubkey string, kind int) bool {
					return pubkey == th && kind == nip29.KindEditMetadata
				})
			},
			ev:      func(t *testing.T) *nip01.Event { return removeUserEvent(t, groupA, third(t), secondTestPrivKey) },
			wantMsg: "restricted: you may not remove a member with powers you do not hold.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newCeilingSession(t, true)
			if tc.setup != nil {
				tc.setup(t, sess)
			}
			before, _ := sess.groups.Get(groupA)
			resp := sendEventAndAwaitOKForSession(t, sess, tc.ev(t))
			if resp.Accepted != tc.wantOK {
				t.Fatalf("Accepted = %v, want %v (message %q)", resp.Accepted, tc.wantOK, resp.Message)
			}
			if !tc.wantOK {
				if resp.Message != tc.wantMsg {
					t.Fatalf("Message = %q, want %q", resp.Message, tc.wantMsg)
				}
				after, _ := sess.groups.Get(groupA)
				if len(after.Members) != len(before.Members) {
					t.Fatalf("a refused change altered the roster: %+v -> %+v", before.Members, after.Members)
				}
				for _, m := range before.Members {
					if got := after.RolesFor(m.Pubkey); len(got) != len(m.Roles) {
						t.Fatalf("a refused change altered %s's roles: %v -> %v", m.Pubkey, m.Roles, got)
					}
				}
			}
		})
	}

	// The self-escalation refusal leaves the moderator a moderator.
	sess := newCeilingSession(t, true)
	sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, mod(t), secondTestPrivKey, "admin"))
	if roles := rolesOf(t, sess, mod(t)); len(roles) != 1 || roles[0] != "moderator" {
		t.Fatalf("moderator's roles after a refused self-grant = %v", roles)
	}
}

// kind:39001 lists the members whose roles carry a moderation kind, not
// one holding only a role the policy gives nothing.
func TestGroupAdmins_ListsOnlyPrivilegedRoles(t *testing.T) {
	sess := newCeilingSession(t, false)
	vip := pubkeyOfPrivKey(t, thirdTestPrivKey)
	if resp := sendEventAndAwaitOKForSession(t, sess, putUserEvent(t, groupA, vip, authTestPrivKey, "vip")); !resp.Accepted {
		t.Fatal(resp.Message)
	}

	evs, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{
		Kinds: []int{nip29.KindGroupAdmins}, Tags: map[string][]string{"d": {groupA}}, Limit: 1,
	})
	if err != nil || len(evs) != 1 {
		t.Fatalf("kind:39001 = %d events, err %v", len(evs), err)
	}
	admins, err := nip29.ParseGroupAdmins(evs[0])
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range admins.Admins {
		got[a.Pubkey] = true
	}
	if !got[authTestPubKey] || !got[secondTestPubKey(t)] || got[vip] || len(got) != 2 {
		t.Fatalf("kind:39001 lists %v, want the admin and the moderator only", got)
	}
}
