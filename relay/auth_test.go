package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/wire"
)

// Shared test keypair (see test_common_test.go's publicKey).
const (
	authTestPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	authTestPubKey  = publicKey
)

// newAuthTestSession builds a Session with AuthRequired on, relayURL as its
// configured identity, and challenge as the value already sent to the
// client. Uses a real EventStore so authed EVENT inserts don't panic.
func newAuthTestSession(t *testing.T, relayURL, challenge string) *Session {
	t.Helper()
	sc := NewSessionContext(newStore(t), &ClientInfo{}, &nip11.Metadata{
		URL:        relayURL,
		Limitation: nip11.Limitation{AuthRequired: true},
	}, nil, nil, nil)
	return &Session{SessionContext: sc, challenge: challenge}
}

func TestProcessAuth_Success(t *testing.T) {
	sess := newAuthTestSession(t, "wss://relay.example", "chal-1")

	ev := nip42.NewAuthEvent("chal-1", "wss://relay.example")
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}

	if sess.authedPubkey != authTestPubKey {
		t.Fatalf("authedPubkey = %q, want %q", sess.authedPubkey, authTestPubKey)
	}

	reply := <-sess.SessionContext.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	if !ok.Accepted {
		t.Fatalf("Accepted = false, want true (message: %s)", ok.Message)
	}
}

// Regression test: an AUTH event addressed to a different relay must be
// rejected, not accepted because the tag matched itself.
func TestProcessAuth_RejectsRelayTagForAnotherRelay(t *testing.T) {
	sess := newAuthTestSession(t, "wss://real-relay.example", "chal-2")

	ev := nip42.NewAuthEvent("chal-2", "wss://attacker.example")
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}

	if sess.authedPubkey != "" {
		t.Fatalf("authedPubkey = %q, want empty -- event's relay tag did not match this relay", sess.authedPubkey)
	}

	reply := <-sess.SessionContext.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	if ok.Accepted {
		t.Fatal("Accepted = true, want false for an AUTH event addressed to a different relay")
	}
}

func TestProcessAuth_NoChallengeSent(t *testing.T) {
	sess := newAuthTestSession(t, "wss://relay.example", "")

	ev := nip42.NewAuthEvent("whatever", "wss://relay.example")
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}

	if sess.authedPubkey != "" {
		t.Fatalf("authedPubkey = %q, want empty", sess.authedPubkey)
	}

	reply := <-sess.SessionContext.incoming
	notice, isNotice := reply.(*wire.NoticeSubscriptionResponse)
	if !isNotice {
		t.Fatalf("reply type = %T, want *wire.NoticeSubscriptionResponse", reply)
	}
	if notice.Message != "auth: no challenge sent" {
		t.Fatalf("Message = %q, want %q", notice.Message, "auth: no challenge sent")
	}
}

func TestProcessAuth_InvalidSignature(t *testing.T) {
	sess := newAuthTestSession(t, "wss://relay.example", "chal-3")

	ev := nip42.NewAuthEvent("chal-3", "wss://relay.example")
	if err := ev.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Corrupt the signature only, so Verify() is what fails.
	ev.Sig = "00" + ev.Sig[2:]

	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: ev}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}

	if sess.authedPubkey != "" {
		t.Fatalf("authedPubkey = %q, want empty", sess.authedPubkey)
	}

	reply := <-sess.SessionContext.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	if ok.Accepted {
		t.Fatal("Accepted = true, want false for a corrupted signature")
	}
}

// REQ and EVENT are rejected before AUTH and allowed after.
func TestAuthGating_RequestAndEvent(t *testing.T) {
	sess := newAuthTestSession(t, "wss://relay.example", "chal-4")

	req := &wire.RequestPacket{SubscriptionID: "sub-1", Filters: CreateFilter([]int{}, 10)}
	if err := sess.processRequest(context.Background(), req); err != nil {
		t.Fatalf("processRequest (unauthed): %v", err)
	}
	if reply := <-sess.SessionContext.incoming; reply == nil {
		t.Fatal("expected a NOTICE reply for unauthed REQ")
	} else if _, isNotice := reply.(*wire.NoticeSubscriptionResponse); !isNotice {
		t.Fatalf("reply type = %T, want *wire.NoticeSubscriptionResponse", reply)
	}
	if reply := <-sess.SessionContext.incoming; reply == nil {
		t.Fatal("expected a CLOSED reply for unauthed REQ")
	} else if _, isClosed := reply.(*wire.ClosedSubscriptionResponse); !isClosed {
		t.Fatalf("reply type = %T, want *wire.ClosedSubscriptionResponse", reply)
	}

	ev := CreateEvent(t, 1)
	if err := sess.processEvent(context.Background(), &wire.EventPacket{Event: ev}); err != nil {
		t.Fatalf("processEvent (unauthed): %v", err)
	}
	if reply := <-sess.SessionContext.incoming; reply == nil {
		t.Fatal("expected an OK reply for unauthed EVENT")
	} else if ok, isOk := reply.(*wire.OkSubscriptionResponse); !isOk || ok.Accepted {
		t.Fatalf("reply = %+v, want OK false for unauthed EVENT", reply)
	}

	// Authenticate, then drain its own OK reply.
	authEv := nip42.NewAuthEvent("chal-4", "wss://relay.example")
	if err := authEv.Sign(authTestPrivKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sess.processAuth(context.Background(), &wire.AuthPacket{Event: authEv}); err != nil {
		t.Fatalf("processAuth: %v", err)
	}
	<-sess.SessionContext.incoming

	if err := sess.processEvent(context.Background(), &wire.EventPacket{Event: ev}); err != nil {
		t.Fatalf("processEvent (authed): %v", err)
	}
	reply := <-sess.SessionContext.incoming
	ok, isOk := reply.(*wire.OkSubscriptionResponse)
	if !isOk {
		t.Fatalf("reply type = %T, want *wire.OkSubscriptionResponse", reply)
	}
	if !ok.Accepted {
		t.Fatalf("Accepted = false, want true once authed (message: %s)", ok.Message)
	}
}
