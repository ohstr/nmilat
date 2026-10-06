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
// the same constructor a host actually running one calls) -- not a
// hand-rolled WebSocket mock. This is deliberate: the bug this file
// guards against (ReadEventsFromRelayWithAuth returning "connection
// closed" for every authenticated read of a private group, even by its
// own creator) was only ever observed against a real relay process,
// never reproduced against the package's own mocks, so the mocks alone
// don't prove the fix actually holds against the real
// processRequest/processAuth/GroupsService code paths on the other end.
//
// Returns the relay's own URL and the privkey configured as its NIP-11
// "self" identity (relay/membership.go's CheckSelfAuthored gates every
// NIP-43 relay-authored kind on this exact key).
//
// authRequired controls nip11.limitation.auth_required -- true matches
// the relay-wide-authenticated setup the redial fix was originally
// reproduced against; false exercises the lazy, REQ-time-only challenge
// deniedPrivateGroupFilter's own branch issues instead, which is what
// lets write access (kind:9007 group creation) stay anonymous while
// reads of a private group still end up authenticatable.
func newPrivateGroupTestRelay(t *testing.T, authRequired bool) (*url.URL, string) {
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
			AuthRequired:     authRequired,
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

	return wsURL, relayPrivKey
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
		events, _, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), creatorPrivKey)
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
	relayURL, _ := newPrivateGroupTestRelay(t, true)
	const groupID = "end-to-end-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), testPrivKey)
	if err != nil {
		t.Fatalf("creator's read of their own private group: %v", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- the creator's retry succeeded")
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
// unauthenticated connection is a member of nothing. restricted is false
// here specifically because signingKeyHex == "" delegates straight to
// ReadEventsFromRelay, which has no restricted-vs-empty signal to report
// at all -- not because the relay didn't restrict it (it did).
func TestPrivateGroup_AnonymousReadIsDenied(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, true)
	const groupID = "anon-denied-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), "")
	if err != nil {
		t.Fatalf("anonymous read error = %v, want nil (an empty result, not an error)", err)
	}
	if restricted {
		t.Error("restricted = true, want false -- an anonymous read has no identity to retry with, so it can't observe this signal")
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
	relayURL, _ := newPrivateGroupTestRelay(t, true)
	const groupID = "non-member-denied-private-group"
	createPrivateGroup(t, relayURL, testPrivKey, groupID)

	outsiderPrivKey := generateTestPrivKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, restricted, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), outsiderPrivKey)
	if err != nil {
		t.Fatalf("outsider's read error = %v, want nil (an empty result, not an error)", err)
	}
	if !restricted {
		t.Error("restricted = false, want true -- the outsider authenticated fine, but is still not a member, so the retry is denied too")
	}
	if len(events) != 0 {
		t.Fatalf("outsider's read returned %d events, want 0 -- authenticating as a real, different pubkey must not substitute for membership", len(events))
	}
}

// TestPrivateGroup_LazyChallengeWithoutRelayWideAuthRequired is the real-
// relay reproduction of nmilat#64 part 1: a relay with
// nip11.limitation.auth_required left false -- so kind:9007 group
// creation stays anonymous, the write path AuthRequired: true would
// otherwise have blocked -- must still let the creator's authenticated
// retry succeed. Before the fix, AuthRequired false meant Start() never
// sent a challenge on connect at all, and nothing else sent one either,
// so this read would hang out the full authRetryWindow waiting on a
// handshake that could never start; deniedPrivateGroupFilter's branch
// now issues one itself, independent of that flag.
func TestPrivateGroup_LazyChallengeWithoutRelayWideAuthRequired(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)
	const groupID = "lazy-challenge-no-auth-required"

	// Anonymous write: no identity configured at all -- exactly the write
	// access AuthRequired: true would otherwise have blocked.
	create := nip29.NewCreateGroup("", groupID)
	if err := create.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := NewConnection(writeCtx, relayURL, nil)
	if err != nil {
		writeCancel()
		t.Fatalf("NewConnection: %v", err)
	}
	resp, err := conn.Publish(writeCtx, create)
	conn.Close()
	writeCancel()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("create-group event was not accepted: %s", resp.Message)
	}

	// The read that needs the lazy challenge: AuthRequired never sent one
	// on connect, so without deniedPrivateGroupFilter's own branch issuing
	// one, there would be nothing for the creator's identity to answer at
	// all. Polls past the same mirror-durability race createPrivateGroup
	// guards against (see its own doc comment).
	deadline := time.Now().Add(2 * time.Second)
	for {
		readCtx, readCancel := context.WithTimeout(context.Background(), time.Second)
		events, restricted, err := ReadEventsFromRelayWithAuth(readCtx, relayURL, groupMetadataFilter(groupID), testPrivKey)
		readCancel()
		if err == nil && len(events) > 0 {
			if restricted {
				t.Error("restricted = true, want false -- the creator's lazy-challenge retry succeeded")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("group %q's kind:39000 mirror never became queryable via the lazy-challenge path (last: events=%d restricted=%v err=%v)", groupID, len(events), restricted, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPrivateGroup_UntaggedQueryHidesPrivateGroupFromNonMembers is the
// real-relay regression test for the untagged-query privacy bypass
// (docs/specs/community-relay-readiness-plan.md's P0 #1):
// deniedPrivateGroupFilter (relay/groups.go) only ever inspected the
// REQUEST's own "d"/"h" tags, so a bare {"kinds":[39000]} query -- exactly
// what "ncli groups list" sends for legitimate public-group discovery --
// named no group at all and sailed straight through unfiltered, handing
// back every group's metadata, private or not, to anyone at all,
// authenticated or not.
//
// The fix (relay/groups.go's deniedPrivateGroupEvent/
// deniedPrivateGroupPotentialEvent, wired into relay/handlers.go's
// StandardRequestHandler.Handle) moves enforcement to delivery time:
// every candidate event is checked against its own group's current
// privacy+membership state right before being sent, regardless of
// whether the request's filter named a group at all. This test uses
// authRequired=false deliberately (like
// TestPrivateGroup_LazyChallengeWithoutRelayWideAuthRequired above) --
// the relay-wide AuthRequired gate would otherwise reject the entire
// anonymous sub-test's REQ outright, before this fix's own per-event
// check ever gets a chance to run; NIP-29 group privacy must hold on its
// own, independent of that unrelated setting.
func TestPrivateGroup_UntaggedQueryHidesPrivateGroupFromNonMembers(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)

	const publicGroupID = "untagged-query-public-group"
	const privateGroupID = "untagged-query-private-group"

	createPrivateGroup(t, relayURL, testPrivKey, publicGroupID)
	createPrivateGroup(t, relayURL, testPrivKey, privateGroupID)

	// A fresh group defaults to private+closed -- flip publicGroupID's own
	// privacy flag off so this test actually has one of each kind, rather
	// than two private groups that would pass trivially.
	edit := nip29.NewEditMetadata("", publicGroupID, nip29.GroupMetadataParams{Private: false, Closed: false})
	if err := edit.Sign(testPrivKey); err != nil {
		t.Fatal(err)
	}
	if accepted := authenticateAndPublish(t, relayURL, testPrivKey, edit); !accepted {
		t.Fatal("edit-metadata to public was not accepted")
	}

	outsiderPrivKey := generateTestPrivKey(t)

	newUntaggedGroupMetadataFilter := func() *nip01.SubscriptionFilterGroup {
		filters := nip01.NewSubscriptionFilterGroup()
		filters.Add(&nip01.SubscriptionFilter{Kinds: []int{39000}})
		return filters
	}

	groupIDsSeen := func(t *testing.T, signingKeyHex string) map[string]bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		events, _, err := ReadEventsFromRelayWithAuth(ctx, relayURL, newUntaggedGroupMetadataFilter(), signingKeyHex)
		if err != nil {
			t.Fatalf("untagged query (signingKeyHex set: %v): %v", signingKeyHex != "", err)
		}
		ids := make(map[string]bool, len(events))
		for _, ev := range events {
			if meta, perr := nip29.ParseGroupMetadata(ev); perr == nil {
				ids[meta.ID] = true
			}
		}
		return ids
	}

	t.Run("anonymous sees only the public group", func(t *testing.T) {
		ids := groupIDsSeen(t, "")
		if !ids[publicGroupID] {
			t.Error("public group missing from an anonymous untagged query")
		}
		if ids[privateGroupID] {
			t.Error("private group leaked to an anonymous untagged query")
		}
	})

	t.Run("the creator (a member) sees both", func(t *testing.T) {
		ids := groupIDsSeen(t, testPrivKey)
		if !ids[publicGroupID] {
			t.Error("public group missing from the creator's untagged query")
		}
		if !ids[privateGroupID] {
			t.Error("private group missing from its own creator's untagged query")
		}
	})

	t.Run("an authenticated non-member still sees only the public group", func(t *testing.T) {
		ids := groupIDsSeen(t, outsiderPrivKey)
		if !ids[publicGroupID] {
			t.Error("public group missing from an authenticated outsider's untagged query")
		}
		if ids[privateGroupID] {
			t.Error("private group leaked to an authenticated non-member's untagged query")
		}
	})
}
