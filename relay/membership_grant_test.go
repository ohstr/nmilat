package relay

import (
	"context"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
)

// A join reaches sessions that authenticated before it: a connection that
// claimed an invite was refused until it reconnected.
func TestMembershipJoin_GrantsLiveSessions(t *testing.T) {
	newbie := strings.Repeat("d4", 32)
	other := strings.Repeat("e5", 32)
	store := newStore(t)
	meta := &nip11.Metadata{Limitation: nip11.Limitation{MembershipRequired: true}}
	sh := NewSessionHandler(store, meta, nil)
	s := &Session{SessionContext: NewSessionContext(store, &ClientInfo{}, meta, nil, nil, nil)}
	s.addIdentity(AuthedIdentity{Pubkey: newbie, Membership: MembershipNone})
	bystander := &Session{SessionContext: NewSessionContext(store, &ClientInfo{}, meta, nil, nil, nil)}
	bystander.addIdentity(AuthedIdentity{Pubkey: other, Membership: MembershipNone})
	sh.sessions.Store(int64(1), s)
	sh.sessions.Store(int64(2), bystander)

	if err := sh.membership.Join(newbie, nil); err != nil {
		t.Fatal(err)
	}
	if !s.HasMembership() {
		t.Error("live session of a new member still has no membership")
	}
	if bystander.HasMembership() {
		t.Error("another pubkey's join granted this session")
	}
}

// Every join and leave republishes the relay-signed kind:13534 list, with
// roles, so clients can see who is in.
func TestMembershipChange_PublishesMembershipList(t *testing.T) {
	alice := strings.Repeat("a1", 32)
	bob := strings.Repeat("b2", 32)
	store := newStore(t)
	sh := NewSessionHandler(store, &nip11.Metadata{Self: authTestPubKey}, nil, WithSessionPrivKey(authTestPrivKey))

	latest := func() *nip43.MembershipList {
		t.Helper()
		evs, err := store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{nip43.KindMembershipList}, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 1 {
			t.Fatalf("%d kind:13534 events stored, want exactly 1", len(evs))
		}
		if evs[0].PubKey != authTestPubKey {
			t.Errorf("kind:13534 signed by %s, want the relay's own key", evs[0].PubKey)
		}
		list, err := nip43.ParseMembershipList(evs[0])
		if err != nil {
			t.Fatal(err)
		}
		return list
	}

	if err := sh.membership.Join(alice, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if err := sh.membership.Join(bob, nil); err != nil {
		t.Fatal(err)
	}
	list := latest()
	roles := map[string][]string{}
	for _, m := range list.Members {
		roles[m.Pubkey] = m.Roles
	}
	if len(roles) != 2 || len(roles[alice]) != 1 || roles[alice][0] != "admin" {
		t.Errorf("after two joins: %+v", list.Members)
	}

	if err := sh.membership.Leave(alice); err != nil {
		t.Fatal(err)
	}
	if list := latest(); len(list.Members) != 1 || list.Members[0].Pubkey != bob {
		t.Errorf("after alice left: %+v", list.Members)
	}
}

// NIP-42: a private group read refused before AUTH says "auth-required:",
// so the client knows to authenticate rather than give up.
func TestGroupRefusal_AuthRequiredBeforeAuth(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	if got := groupRefusal(sess, "g"); !strings.HasPrefix(got, "auth-required:") {
		t.Errorf("unauthenticated: %q", got)
	}
	sess.addIdentity(AuthedIdentity{Pubkey: authTestPubKey})
	if got := groupRefusal(sess, "g"); !strings.HasPrefix(got, "restricted:") {
		t.Errorf("authenticated: %q", got)
	}
}
