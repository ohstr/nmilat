package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/wire"
)

// authAsVirtualMember drives a full AUTH exchange granting sess a virtual
// membership for agentPubkey, scoped by conditions, then drains the AUTH
// OK reply so the session is ready for a subsequent EVENT.
func authAsVirtualMember(t *testing.T, sess *Session, conditions string) {
	t.Helper()
	authTag := signAuthTag(t, ownerPrivKey, agentPubkey, conditions)
	ev := agentAuthEvent(t, sess.relayURL, sess.challenge, authTag)
	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}
	reply := <-sess.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk || !ok.Accepted {
		t.Fatalf("AUTH did not succeed: reply = %+v", reply)
	}
}

func TestProcessEvent_KindEnforcement_Allows(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-ke-1", true)
	authAsVirtualMember(t, sess, "kind=1")

	ev := CreateEvent(t, 1)
	ev.PubKey = agentPubkey
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true for kind:1 authorized by the kind=1 credential (message: %s)", resp.Message)
	}
}

func TestProcessEvent_KindEnforcement_Rejects(t *testing.T) {
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-ke-2", true)
	authAsVirtualMember(t, sess, "kind=1")

	ev := CreateEvent(t, 7)
	ev.PubKey = agentPubkey
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if resp.Accepted {
		t.Fatal("Accepted = true, want false for kind:7 when the credential only authorizes kind=1")
	}
	if resp.Message != "restricted: kind not authorized by credential" {
		t.Fatalf("Message = %q, want the kind-enforcement wording", resp.Message)
	}
}

func TestProcessEvent_KindEnforcement_DisabledByDefault(t *testing.T) {
	// kindEnforcement=false: the credential's kind=1 condition is advisory
	// only, per spec -- kind:7 must still be accepted.
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-ke-3", false)
	authAsVirtualMember(t, sess, "kind=1")

	ev := CreateEvent(t, 7)
	ev.PubKey = agentPubkey
	if err := ev.Sign(agentPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, ev)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true -- kind enforcement is off by default, kind= is advisory only (message: %s)", resp.Message)
	}
}

func TestProcessEvent_ConjunctiveKindFootgun(t *testing.T) {
	// A credential with "kind=1&kind=7" is a known spec footgun: since no
	// single event can have two kinds simultaneously, this conjunctive
	// condition can never be satisfied by anything. This test documents
	// that as an intentional, passing outcome -- not a bug to "fix" in
	// EvaluateKind.
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-ke-4", true)
	authAsVirtualMember(t, sess, "kind=1&kind=7")

	for _, kind := range []int{1, 7} {
		ev := CreateEvent(t, kind)
		ev.PubKey = agentPubkey
		if err := ev.Sign(agentPrivKey); err != nil {
			t.Fatalf("sign: %v", err)
		}
		resp := sendEventAndAwaitOKForSession(t, sess, ev)
		if resp.Accepted {
			t.Fatalf("Accepted = true for kind:%d, want false -- kind=1&kind=7 is never satisfiable", kind)
		}
	}
}

func TestProcessEvent_KindEnforcement_ActiveMemberUnaffected(t *testing.T) {
	// Kind enforcement only applies to virtual members with a retained
	// credential -- a direct/active member's events must never be
	// filtered by it (they have no Conditions at all).
	sess := newAgentAuthTestSession(t, "wss://relay.example", "chal-ke-5", true)

	ev := nip42.NewAuthEvent("chal-ke-5", "wss://relay.example")
	if err := ev.Sign(ownerPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}
	<-sess.incoming

	eventFromOwner := CreateEvent(t, 7)
	eventFromOwner.PubKey = ownerPubkey
	if err := eventFromOwner.Sign(ownerPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	resp := sendEventAndAwaitOKForSession(t, sess, eventFromOwner)
	if !resp.Accepted {
		t.Fatalf("Accepted = false, want true -- kind enforcement must not apply to active members (message: %s)", resp.Message)
	}
}
