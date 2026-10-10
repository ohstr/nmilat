package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// remoteSigner stands in for a key held elsewhere: it signs with a key the
// connection never sees, and counts calls.
type remoteSigner struct {
	key   string
	calls atomic.Int32
	err   error
	block chan struct{}
	ctxOK atomic.Bool // set when Sign saw its ctx cancelled
}

func (s *remoteSigner) PubKey() string {
	pub, _ := utils.GetPublicKey(s.key)
	return pub
}

func (s *remoteSigner) Sign(ctx context.Context, ev *nip01.Event) error {
	s.calls.Add(1)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			s.ctxOK.Store(true)
			return ctx.Err()
		}
	}
	if s.err != nil {
		return s.err
	}
	return ev.Sign(s.key)
}

func TestConnection_AuthWithSigner(t *testing.T) {
	const challenge = "signer-challenge"
	signer := &remoteSigner{key: testPrivKey}
	var authedAs string
	server := newAuthChallengeServer(t, challenge, 2*time.Second, func(ap *wire.AuthPacket) *wire.OkSubscriptionResponse {
		if err := nip42.ValidateAuthEvent(ap.Event.Kind, ap.Event.Tags, ap.Event.CreatedAt, challenge, ap.Event.GetTag("relay")[0]); err != nil {
			t.Errorf("ValidateAuthEvent: %v", err)
		}
		if err := ap.Event.Verify(); err != nil {
			t.Errorf("Verify: %v", err)
		}
		authedAs = ap.Event.PubKey
		return &wire.OkSubscriptionResponse{EventID: ap.Event.ID, Accepted: true, Message: "auth-success"}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Signer wins over SigningKeyHex.
	other := "0000000000000000000000000000000000000000000000000000000000000009"
	conn, err := NewConnection(ctx, dialURL(t, server), &ConnectionConfig{Signer: signer, SigningKeyHex: other})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if got := waitForAuthState(conn, 2*time.Second); got != AuthStateSucceeded {
		t.Fatalf("AuthState() = %v, want Succeeded", got)
	}
	if authedAs != signer.PubKey() || signer.calls.Load() != 1 {
		t.Errorf("authenticated as %s after %d signs, want %s once", authedAs, signer.calls.Load(), signer.PubKey())
	}
}

func TestConnection_SignerFailureSettlesAuth(t *testing.T) {
	signer := &remoteSigner{key: testPrivKey, err: errors.New("denied: not paired")}
	server := newAuthChallengeServer(t, "c", 500*time.Millisecond, func(*wire.AuthPacket) *wire.OkSubscriptionResponse {
		t.Error("an AUTH packet went out although signing failed")
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := NewConnection(ctx, dialURL(t, server), &ConnectionConfig{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case <-conn.AuthSettled():
	case <-time.After(2 * time.Second):
		t.Fatal("AuthSettled never closed")
	}
	if conn.AuthState() != AuthStateFailed || conn.AuthMessage() == "" {
		t.Errorf("state %v message %q, want Failed with the signer's error", conn.AuthState(), conn.AuthMessage())
	}
}

// A signer still waiting (say, on a human approving it) is told to stop
// when the connection closes, instead of outliving it.
func TestConnection_CloseCancelsPendingSign(t *testing.T) {
	signer := &remoteSigner{key: testPrivKey, block: make(chan struct{})}
	server := newAuthChallengeServer(t, "c", 2*time.Second, func(*wire.AuthPacket) *wire.OkSubscriptionResponse { return nil })
	conn, err := NewConnection(context.Background(), dialURL(t, server), &ConnectionConfig{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for signer.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()
	for !signer.ctxOK.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !signer.ctxOK.Load() {
		t.Error("pending Sign was not cancelled by Close")
	}
}

func TestReadEventsFromRelayWithSigner(t *testing.T) {
	const challenge = "membership-gate-challenge"
	event := nip01.NewEvent(1, "members only")
	if err := event.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	u := dialURL(t, newMembershipGatedRelayServer(t, challenge, event))
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{Kinds: []int{1}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signer := &remoteSigner{key: testPrivKey}
	events, restricted, err := ReadEventsFromRelayWithSigner(ctx, u, filters, signer)
	if err != nil || restricted || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events %v restricted %v err %v", events, restricted, err)
	}
	if signer.calls.Load() == 0 {
		t.Error("signer never asked to sign AUTH")
	}

	if _, restricted, err := ReadEventsFromRelayWithSigner(ctx, u, filters, nil); err != nil || !restricted {
		t.Errorf("anonymous read: restricted %v err %v, want restricted", restricted, err)
	}
}

func TestKeySigner(t *testing.T) {
	s := KeySigner(testPrivKey)
	ev := nip01.NewEvent(1, "x")
	if err := s.Sign(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := ev.Verify(); err != nil || ev.PubKey != s.PubKey() {
		t.Errorf("signed %+v: %v", ev, err)
	}
}
