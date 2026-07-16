package relay

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
	"github.com/ohstr/nmilat/wire"
)

func inviteRequestFilter() *nip01.SubscriptionFilterGroup {
	return CreateFilter([]int{nip43.KindInviteRequest}, 10)
}

func TestMembershipRequestHandler_CanHandle(t *testing.T) {
	h := &MembershipRequestHandler{}

	rp := &wire.RequestPacket{SubscriptionID: "sub", Filters: inviteRequestFilter()}
	if !h.CanHandle(rp) {
		t.Fatal("CanHandle() = false for a filter requesting kind:28935, want true")
	}

	other := &wire.RequestPacket{SubscriptionID: "sub", Filters: CreateFilter([]int{1}, 10)}
	if h.CanHandle(other) {
		t.Fatal("CanHandle() = true for an unrelated kind filter, want false")
	}
}

func TestMembershipRequestHandler_DisabledWhenNoMembershipService(t *testing.T) {
	sess := newSelfAuthTestSession(t, authTestPubKey)

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	reply := <-sess.incoming
	closed, isClosed := reply.(*wire.ClosedSubscriptionResponse)
	if !isClosed {
		t.Fatalf("reply type = %T, want *wire.ClosedSubscriptionResponse", reply)
	}
	if closed.Message != "unsupported: NIP-43 membership is not enabled on this relay" {
		t.Fatalf("Message = %q, want the not-enabled wording", closed.Message)
	}
}

func TestMembershipRequestHandler_ErrorsWithoutPrivKey(t *testing.T) {
	store := newStore(t)
	cfg := defaultSessionConfig()
	// Deliberately no PrivKey.
	sc := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{Self: authTestPubKey}, nil, nil, cfg)
	sc.membership = NewMembershipService(store)
	sess := &Session{SessionContext: sc}

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}
	reply := <-sess.incoming
	closed, isClosed := reply.(*wire.ClosedSubscriptionResponse)
	if !isClosed {
		t.Fatalf("reply type = %T, want *wire.ClosedSubscriptionResponse", reply)
	}
	if closed.Message == "" {
		t.Fatal("expected a non-empty error message when PrivKey is missing")
	}
}

func TestMembershipRequestHandler_Success(t *testing.T) {
	sess := newMembershipEnabledTestSession(t)

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: inviteRequestFilter()}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest: %v", err)
	}

	eventReply, ok := (<-sess.incoming).(*wire.EventSubscriptionResponse)
	if !ok {
		t.Fatal("expected an EventSubscriptionResponse first")
	}
	if _, ok := (<-sess.incoming).(*wire.EOSESubscriptionResponse); !ok {
		t.Fatal("expected an EOSESubscriptionResponse second")
	}
	if _, ok := (<-sess.incoming).(*wire.ClosedSubscriptionResponse); !ok {
		t.Fatal("expected a ClosedSubscriptionResponse third (one-shot)")
	}

	var ev nip01.Event
	if err := json.Unmarshal(eventReply.EventBytes, &ev); err != nil {
		t.Fatalf("unmarshal invite response event: %v", err)
	}
	if err := ev.Verify(); err != nil {
		t.Fatalf("invite response event failed signature verification: %v", err)
	}
	if ev.PubKey != authTestPubKey {
		t.Fatalf("invite response signed by %q, want the relay's self pubkey %q", ev.PubKey, authTestPubKey)
	}

	inviteResp, err := nip43.ParseInviteResponse(&ev)
	if err != nil {
		t.Fatalf("ParseInviteResponse: %v", err)
	}

	claim, err := sess.store.GetInviteClaim(inviteResp.Claim)
	if err != nil {
		t.Fatalf("GetInviteClaim: %v", err)
	}
	if claim == nil {
		t.Fatal("the generated claim was not persisted")
	}
	if claim.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("ExpiresAt = %d, want a future timestamp", claim.ExpiresAt)
	}

	// The claim this handler just issued should actually work for a Join
	// Request -- an end-to-end check that the invite and join flows agree
	// on the same store.
	joinResp := sendEventAndAwaitOKForSession(t, sess, joinRequestEvent(t, inviteResp.Claim))
	if !joinResp.Accepted {
		t.Fatalf("joining with the handler-issued claim failed: %s", joinResp.Message)
	}
}
