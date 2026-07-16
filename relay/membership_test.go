package relay

import (
	"context"
	"testing"

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
	reply := <-sess.SessionContext.incoming
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
