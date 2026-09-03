package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

func TestCheckSelfAuthored(t *testing.T) {
	tests := []struct {
		name       string
		kind       int
		pubkey     string
		selfPubkey string
		wantOK     bool
	}{
		{
			name:       "non-relay-authored kind always passes",
			kind:       1,
			pubkey:     memberA,
			selfPubkey: memberB,
			wantOK:     true,
		},
		{
			name:       "relay-authored kind signed by self",
			kind:       nip43.KindMembershipList,
			pubkey:     memberA,
			selfPubkey: memberA,
			wantOK:     true,
		},
		{
			name:       "relay-authored kind signed by someone else",
			kind:       nip43.KindMembershipList,
			pubkey:     memberA,
			selfPubkey: memberB,
			wantOK:     false,
		},
		{
			name:       "relay-authored kind, no self configured",
			kind:       nip43.KindRoleDefinition,
			pubkey:     memberA,
			selfPubkey: "",
			wantOK:     false,
		},
		{
			name:       "join request (not relay-authored) from any pubkey",
			kind:       nip43.KindJoinRequest,
			pubkey:     memberA,
			selfPubkey: memberB,
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, PubKey: tt.pubkey}
			ok, msg := CheckSelfAuthored(ev, tt.selfPubkey)
			if ok != tt.wantOK {
				t.Fatalf("CheckSelfAuthored() ok = %v, want %v (message: %q)", ok, tt.wantOK, msg)
			}
			if !ok && msg == "" {
				t.Fatal("CheckSelfAuthored() rejected with an empty message")
			}
		})
	}
}

// newSelfAuthTestSession builds a Session whose relay identity is
// selfPubkey, with no auth/membership requirement -- isolating the
// self-authored gate in processEvent from the AuthRequired gate.
func newSelfAuthTestSession(t *testing.T, selfPubkey string) *Session {
	t.Helper()
	sc := NewSessionContext(newStore(t), &ClientInfo{}, &nip11.Metadata{
		Self: selfPubkey,
	}, nil, nil, nil)
	return &Session{SessionContext: sc}
}

func sendEventAndAwaitOKForSession(t *testing.T, sess *Session, ev *nip01.Event) *wire.OkSubscriptionResponse {
	t.Helper()
	if err := sess.processEvent(context.Background(), &wire.EventPacket{Event: ev}); err != nil {
		t.Fatalf("processEvent: %v", err)
	}
	reply := <-sess.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	return ok
}

func TestProcessEvent_RejectsImpersonationOfRelayAuthoredKind(t *testing.T) {
	sess := newSelfAuthTestSession(t, authTestPubKey)

	// Signed by a *different* key than the configured self pubkey.
	ev := nip43.NewMembershipList(nip43.MembershipListParams{SelfPubkey: authTestPubKey})
	otherPrivKey := "0000000000000000000000000000000000000000000000000000000000000001"
	if err := ev.Sign(otherPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for a relay-authored kind signed by a non-self key")
	}
}

func TestProcessEvent_AcceptsRelayAuthoredEventFromSelf(t *testing.T) {
	sess := newSelfAuthTestSession(t, authTestPubKey)

	ev := nip43.NewMembershipList(nip43.MembershipListParams{SelfPubkey: authTestPubKey})
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a relay-authored kind signed by self (message: %s)", resp.Message)
	}
}

func TestProcessEvent_OrdinaryEventUnaffectedBySelfAuthoredGate(t *testing.T) {
	// No self pubkey configured at all -- an ordinary kind:1 event must
	// still be accepted; only NIP-43's relay-authored kinds are gated.
	sess := newSelfAuthTestSession(t, "")

	ev := CreateEvent(t, 1)
	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for an ordinary kind:1 event (message: %s)", resp.Message)
	}
}

/////////////////////////////////////////////////////////////////////
// Join / Leave / Invite flow
/////////////////////////////////////////////////////////////////////

// newMembershipEnabledTestSession builds a Session with a real,
// store-backed MembershipService wired in, the relay's own selfPubkey set
// to authTestPubKey (so relay-authored events can be signed with
// authTestPrivKey), and PrivKey configured for the same reason.
func newMembershipEnabledTestSession(t *testing.T) *Session {
	t.Helper()
	store := newStore(t)
	cfg := defaultSessionConfig()
	cfg.PrivKey = authTestPrivKey
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{
		Self: authTestPubKey,
	}, nil, nil, cfg)
	sc.membership = NewMembershipService(store)
	return &Session{SessionContext: sc}
}

func joinRequestEvent(t *testing.T, claim string) *nip01.Event {
	t.Helper()
	ev := nip43.NewJoinRequest(authTestPubKey, claim)
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign join request: %v", err)
	}
	return ev
}

func leaveRequestEvent(t *testing.T) *nip01.Event {
	t.Helper()
	ev := nip43.NewLeaveRequest(authTestPubKey)
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign leave request: %v", err)
	}
	return ev
}

func TestHandleEvent_Join_UnknownClaim(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "no-such-claim"))
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for an unknown invite claim")
	}
	if resp.Message != "restricted: that is an invalid invite code." {
		t.Fatalf("Message = %q, want the spec's exact invalid-claim wording", resp.Message)
	}
	if sess.membership.IsMember(authTestPubKey) {
		t.Fatal("IsMember() = true after a rejected join, want false")
	}
}

func TestHandleEvent_Join_ExpiredClaim(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	if err := sess.store.PutInviteClaim(&InviteClaim{Code: "expired", ExpiresAt: 1}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "expired"))
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for an expired invite claim")
	}
	if resp.Message != "restricted: that invite code is expired." {
		t.Fatalf("Message = %q, want the spec's exact expired-claim wording", resp.Message)
	}
}

func TestHandleEvent_Join_Success(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	if err := sess.store.PutInviteClaim(&InviteClaim{Code: "good-claim"}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "good-claim"))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a valid invite claim (message: %s)", resp.Message)
	}
	wantMsg := "info: welcome to " + sess.relayURL + "!"
	if resp.Message != wantMsg {
		t.Fatalf("Message = %q, want %q", resp.Message, wantMsg)
	}
	if !sess.membership.IsMember(authTestPubKey) {
		t.Fatal("IsMember() = false after a successful join, want true")
	}
	rec, err := sess.store.GetMember(authTestPubKey)
	if err != nil {
		t.Fatalf("GetMember: %v", err)
	}
	if rec == nil {
		t.Fatal("GetMember() = nil after a successful join, want a persisted record")
	}
}

func TestHandleEvent_Join_AlreadyMember(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	if err := sess.membership.Join(authTestPubKey, nil); err != nil {
		t.Fatalf("Join: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "irrelevant"))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for an already-member duplicate join (message: %s)", resp.Message)
	}
	if resp.Message != "duplicate: you are already a member of this relay." {
		t.Fatalf("Message = %q, want the spec's exact duplicate wording", resp.Message)
	}
}

func TestHandleEvent_Join_PublishesAddUserWhenConfigured(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	sess.config.MembershipPublishAddRemove = true
	if err := sess.store.PutInviteClaim(&InviteClaim{Code: "good-claim"}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "good-claim"))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", resp.Message)
	}

	events, err := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Kinds: []int{nip43.KindAddUser}, Limit: 10})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored kind:8000 events = %d, want 1", len(events))
	}
	addUser, err := nip43.ParseAddUser(events[0])
	if err != nil {
		t.Fatalf("ParseAddUser: %v", err)
	}
	if addUser.Pubkey != authTestPubKey {
		t.Fatalf("AddUser.Pubkey = %q, want %q", addUser.Pubkey, authTestPubKey)
	}
}

func TestHandleEvent_Leave_Success(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	if err := sess.membership.Join(authTestPubKey, nil); err != nil {
		t.Fatalf("Join: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, leaveRequestEvent(t))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a successful leave (message: %s)", resp.Message)
	}
	if resp.Message != "info: you have left this relay." {
		t.Fatalf("Message = %q, want the leave-success wording", resp.Message)
	}
	if sess.membership.IsMember(authTestPubKey) {
		t.Fatal("IsMember() = true after a successful leave, want false")
	}
}

func TestHandleEvent_Leave_NotAMember(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)

	resp := sendEventAndAwaitOKForSession(t, sess, leaveRequestEvent(t))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a non-member leave (message: %s)", resp.Message)
	}
	if resp.Message != "duplicate: you are not a member of this relay." {
		t.Fatalf("Message = %q, want the non-member-leave wording", resp.Message)
	}
}

func TestHandleEvent_NilMembership_RejectsJoinAndLeave(t *testing.T) {
	// No membership service wired in at all -- distinct from
	// newMembershipEnabledTestSession, which always sets one.
	sess := newSelfAuthTestSession(t, authTestPubKey)

	for _, ev := range []*nip01.Event{joinRequestEvent(t, "any-claim"), leaveRequestEvent(t)} {
		resp := sendEventAndAwaitOKForSession(t, sess, ev)
		if resp.Accepted {
			t.Fatalf("Accepted = true for kind %d with no membership service configured, want false", ev.Kind)
		}
		if resp.Message != "restricted: NIP-43 membership is not enabled on this relay" {
			t.Fatalf("Message = %q, want the not-enabled wording", resp.Message)
		}
	}
}

func TestReplaceFromEvent_ViaManualPublish(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)

	ev := nip43.NewMembershipList(nip43.MembershipListParams{
		SelfPubkey: authTestPubKey,
		Members:    []nip43.Member{{Pubkey: memberA}, {Pubkey: memberB}},
	})
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for a valid self-authored membership list (message: %s)", resp.Message)
	}

	// Give the async task.done consumer's ReplaceFromEvent hook a moment
	// to run -- it fires from the same goroutine that already sent the OK
	// reply we just drained above, immediately after.
	deadline := time.Now().Add(2 * time.Second)
	for !sess.membership.IsMember(memberA) {
		if time.Now().After(deadline) {
			t.Fatal("ReplaceFromEvent did not sync the membership cache from the published kind:13534 event in time")
		}
		time.Sleep(time.Millisecond)
	}
	if !sess.membership.IsMember(memberB) {
		t.Fatal("IsMember(memberB) = false after ReplaceFromEvent, want true")
	}
}

/////////////////////////////////////////////////////////////////////
// MembershipRequired gate
/////////////////////////////////////////////////////////////////////

func TestProcessEvent_MembershipRequiredGate(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	sess.limitation.MembershipRequired = true

	// Non-member, never authenticated: rejected.
	ev := CreateEvent(t, 1)
	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true for a non-member event with MembershipRequired, want false")
	}
	if resp.Message != "restricted: valid NIP-43 membership required" {
		t.Fatalf("Message = %q, want the membership-required wording", resp.Message)
	}

	// Join, then AUTH (membership is resolved at AUTH time) -- now allowed.
	if err := sess.membership.Join(authTestPubKey, nil); err != nil {
		t.Fatalf("Join: %v", err)
	}
	authEv := mustSignedAuthEvent(t, sess)
	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: authEv}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}
	<-sess.incoming // drain the AUTH OK reply

	resp = sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false for a member's event with MembershipRequired, want true (message: %s)", resp.Message)
	}
}

func TestProcessEvent_MembershipRequiredGate_JoinRequestExempt(t *testing.T) {
	// A non-member must still be able to send a Join Request even when
	// MembershipRequired is on -- otherwise nobody could ever join.
	sess := newMembershipEnabledTestSession(t)
	sess.limitation.MembershipRequired = true
	if err := sess.store.PutInviteClaim(&InviteClaim{Code: "good-claim"}); err != nil {
		t.Fatalf("PutInviteClaim: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, "good-claim"))
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true -- Join Request must bypass MembershipRequired (message: %s)", resp.Message)
	}
}

func TestProcessRequest_MembershipRequiredGate(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)
	sess.limitation.MembershipRequired = true

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: CreateFilter([]int{}, 10)}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest (non-member): %v", err)
	}
	if reply := <-sess.incoming; true {
		if _, isNotice := reply.(*wire.NoticeSubscriptionResponse); !isNotice {
			t.Fatalf("reply type = %T, want *wire.NoticeSubscriptionResponse", reply)
		}
	}
	if reply := <-sess.incoming; true {
		if _, isClosed := reply.(*wire.ClosedSubscriptionResponse); !isClosed {
			t.Fatalf("reply type = %T, want *wire.ClosedSubscriptionResponse", reply)
		}
	}
}

func mustSignedAuthEvent(t *testing.T, sess *Session) *nip01.Event {
	t.Helper()
	sess.challenge = "chal-membership-test"
	ev := nip01.NewEvent(22242, "", []string{"relay", sess.relayURL}, []string{"challenge", sess.challenge})
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign auth event: %v", err)
	}
	return ev
}
