package client

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/relay"
)

// newPrivateGroupTestRelay starts a REAL, store-backed relay (relay.New,
// the same constructor a host actually running one calls) with NIP-42
// auth required -- not a hand-rolled WebSocket mock. This is deliberate:
// the bug this file guards against (ReadEventsFromRelayWithAuth returning
// "connection closed" for every authenticated read of a private group,
// even by its own creator) was only ever observed against a real relay
// process, never reproduced against the package's own mocks, so the
// mocks alone don't prove the fix actually holds against the real
// processRequest/processAuth/GroupsService code paths on the other end.
func newPrivateGroupTestRelay(t *testing.T) *url.URL {
	t.Helper()
	f, err := os.CreateTemp("", "private-group-integration-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	// The relay's own AUTH-challenge validation checks a client's "relay"
	// tag against its own configured nip11.Metadata.URL (relay/packet.go:
	// deliberately not whatever the client's tag claims, or the check
	// would be a tautology) -- so that URL has to be known, and set,
	// before the handshake can ever succeed. httptest assigns its port
	// only once the listener starts, so the server starts unstarted,
	// first to learn that port.
	srv := httptest.NewUnstartedServer(nil)
	wsURL, err := url.Parse("ws://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// A group's kind:39000/39001/39002 mirrors are relay-authored
	// (relay/membership.go's publishSelfSigned), which no-ops with
	// nothing stored at all if the relay has no PrivKey configured --
	// relay.New's own simplified constructor never sets one, so this
	// builds the store+handler directly (relay.New's own doc comment
	// points here for exactly this: "for ... session options, build the
	// store and handler directly").
	relayPrivKey := generateTestPrivKey(t)
	relaySelfEvent := nip01.NewEvent(0, "")
	if err := relaySelfEvent.Sign(relayPrivKey); err != nil {
		t.Fatalf("derive relay pubkey: %v", err)
	}

	metadata := &nip11.Metadata{
		Name: "private-group-integration-test",
		URL:  wsURL.String(),
		Self: relaySelfEvent.PubKey,
		Limitation: nip11.Limitation{
			MaxMessageLength: 1024 * 1024,
			AuthRequired:     true,
		},
	}
	store, err := relay.NewEventStore(f.Name(), &metadata.Limitation)
	if err != nil {
		t.Fatalf("relay.NewEventStore: %v", err)
	}
	t.Cleanup(store.Close)

	handler := relay.NewSessionHandler(store, metadata, nil, relay.WithSessionPrivKey(relayPrivKey))
	handler.VerificationWorker.Start(1)
	t.Cleanup(handler.VerificationWorker.Stop)

	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	return wsURL
}

// generateTestPrivKey returns a fresh, arbitrary, never-funded private key
// -- for tests that need a second identity distinct from testPrivKey (an
// outsider who authenticates as themselves but isn't a group member).
func generateTestPrivKey(t *testing.T) string {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(priv.Serialize())
}

// authenticateAndPublish dials relayURL, waits for its own NIP-42
// handshake to settle, publishes ev, and reports whether the relay
// accepted it. The wait matters here specifically because this relay has
// AuthRequired set: processEvent gates EVENT on it exactly like
// processRequest gates REQ, so publishing before the handshake settles
// would itself come back "restricted" -- unlike
// ReadEventsFromRelayWithAuth, this helper doesn't retry, so it waits
// up front instead.
func authenticateAndPublish(t *testing.T, relayURL *url.URL, signingKeyHex string, ev *nip01.Event) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := NewConnection(ctx, relayURL, &ConnectionConfig{SigningKeyHex: signingKeyHex})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer conn.Close()

	select {
	case <-conn.AuthSettled():
	case <-time.After(3 * time.Second):
		t.Fatal("handshake never settled before publish")
	}
	if conn.AuthState() != AuthStateSucceeded {
		t.Fatalf("AuthState() = %v, want Succeeded (message: %s)", conn.AuthState(), conn.AuthMessage())
	}

	resp, err := conn.Publish(ctx, ev)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return resp.Accepted
}

// createPrivateGroup publishes a kind:9007 create-group event signed by
// creatorPrivKey, fails the test if the relay didn't accept it, and waits
// until the group's kind:39000 mirror is actually queryable before
// returning. The OK accepting the create only confirms GroupsService's
// own in-memory cache took it (IsPrivate/IsMember are correct
// immediately, which is what the access gate itself checks) -- the
// mirror event's durable storage goes through EventStore's normal
// batched write queue (relay/config.go's default BatchInterval is 10ms),
// so a query sent immediately after the OK can legitimately race ahead
// of that commit and come back empty with no restriction involved at
// all. That race is a property of this test's setup, not of
// ReadEventsFromRelayWithAuth (which only retries a REQ the relay
// actually closed as restricted, not a REQ that was allowed through but
// found nothing yet) -- so every test in this file gets a confirmed-
// durable starting point from here, rather than each asserting
// separately through a timing race.
func createPrivateGroup(t *testing.T, relayURL *url.URL, creatorPrivKey, groupID string) {
	t.Helper()
	create := nip29.NewCreateGroup("", groupID)
	if err := create.Sign(creatorPrivKey); err != nil {
		t.Fatalf("sign create-group event: %v", err)
	}
	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, create); !accepted {
		t.Fatalf("create-group event for %q was not accepted", groupID)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		events, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), creatorPrivKey)
		cancel()
		if err == nil && len(events) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("group %q's kind:39000 mirror never became queryable (last: events=%d err=%v)", groupID, len(events), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func groupMetadataFilter(groupID string) *nip01.SubscriptionFilterGroup {
	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{
		Kinds: []int{39000},
		Tags:  map[string][]string{"d": {groupID}},
	})
	return filters
}

// TestPrivateGroup_CreatorReadsOwnGroup_EndToEnd is the real-relay,
// real-client reproduction of the originally reported scenario (create a
// private group, then read its own kind:39000 metadata as the creator,
// authenticated) -- no mocks on either side. This is exactly the case
// ReadEventsFromRelayWithAuth's redial fix exists for: a private+closed
// group requires membership to read even its own metadata, and the
// creator is the identity that just proved it by creating the group.
func TestPrivateGroup_CreatorReadsOwnGroup_EndToEnd(t *testing.T) {
	relayURL := newPrivateGroupTestRelay(t)
	const groupID = "end-to-end-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), testPrivKey)
	if err != nil {
		t.Fatalf("creator's read of their own private group: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("creator's read returned %d events, want exactly 1 (the kind:39000 mirror)", len(events))
	}
	if events[0].Kind != 39000 {
		t.Fatalf("event kind = %d, want 39000", events[0].Kind)
	}
}

// TestPrivateGroup_AnonymousReadIsDenied is the gate's other side: with no
// identity at all, the read comes back empty rather than erroring --
// ReadEventsFromRelayWithAuth(..., "") never attempts NIP-42 at all (no
// behavior change from before --auth-identity existed), and the relay's
// deniedPrivateGroupFilter closes the REQ as restricted since an
// unauthenticated connection is a member of nothing.
func TestPrivateGroup_AnonymousReadIsDenied(t *testing.T) {
	relayURL := newPrivateGroupTestRelay(t)
	const groupID = "anon-denied-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), "")
	if err != nil {
		t.Fatalf("anonymous read error = %v, want nil (an empty result, not an error)", err)
	}
	if len(events) != 0 {
		t.Fatalf("anonymous read returned %d events, want 0 -- a non-member must not see a private group's metadata", len(events))
	}
}

// TestPrivateGroup_NonMemberReadIsDenied covers the third angle: a second,
// real identity that authenticates successfully (proving it controls its
// own distinct pubkey) but never joined the group. NIP-42 alone proves
// identity, not membership -- membership is what actually enforces the
// group being private, and this is what would catch that check
// accidentally degrading into "any authenticated pubkey may read any
// group."
func TestPrivateGroup_NonMemberReadIsDenied(t *testing.T) {
	relayURL := newPrivateGroupTestRelay(t)
	const groupID = "non-member-denied-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	outsiderPrivKey := generateTestPrivKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), outsiderPrivKey)
	if err != nil {
		t.Fatalf("outsider's read error = %v, want nil (an empty result, not an error)", err)
	}
	if len(events) != 0 {
		t.Fatalf("outsider's read returned %d events, want 0 -- authenticating as a real, different pubkey must not substitute for membership", len(events))
	}
}
