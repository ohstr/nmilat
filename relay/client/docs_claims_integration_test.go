package client

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip29"
	"github.com/ohstr/nmilat/nip43"
)

// TestNIP43ProtectedEvent_AddUserRequiresConnectionAuthAsOwnPubkey verifies,
// against a real relay process, the claim the README's NIP-43 quick start
// makes: nip43.NewAddUser builds a kind:8000 event, which the relay only
// ever accepts when (a) it's signed by the relay's own configured NIP-11
// "self" identity -- relay/membership.go's CheckSelfAuthored, which runs
// before the generic NIP-70 "protected" gate ever gets a say, since every
// other signer is rejected on sight regardless of connection state -- and
// (b) that connection has itself authenticated (NIP-42) as that same
// pubkey, which is the generic NIP-70 gate in relay/packet.go's
// processEvent (s.IdentityMembership(ep.Event.PubKey)). A valid signature
// alone satisfies neither.
func TestNIP43ProtectedEvent_AddUserRequiresConnectionAuthAsOwnPubkey(t *testing.T) {
	relayURL, relaySelfPrivKey := newPrivateGroupTestRelay(t, false)
	relaySelfPubkey := pubkeyFor(t, relaySelfPrivKey)

	memberPrivKey := generateTestPrivKey(t)
	memberPubkey := pubkeyFor(t, memberPrivKey)

	addEv := nip43.NewAddUser(relaySelfPubkey, memberPubkey)
	if err := addEv.Sign(relaySelfPrivKey); err != nil {
		t.Fatalf("sign add-user event: %v", err)
	}

	// Unauthenticated connection: even though addEv is correctly signed
	// by the relay's own self key, nothing has authenticated as that
	// pubkey on *this* connection yet, so NIP-70 must still refuse it.
	t.Run("rejected without matching connection auth", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := NewConnection(ctx, relayURL, nil)
		if err != nil {
			t.Fatalf("NewConnection: %v", err)
		}
		defer conn.Close()

		resp, err := conn.Publish(ctx, addEv)
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if resp.Accepted {
			t.Fatalf("Accepted = true, want false (protected event over an unauthenticated connection)")
		}
		if !strings.HasPrefix(resp.Message, "auth-required") {
			t.Fatalf("Message = %q, want an auth-required prefix", resp.Message)
		}
	})

	// A signature from some OTHER key entirely -- not the relay's own
	// self identity -- must be rejected regardless of connection auth:
	// CheckSelfAuthored's gate, which has nothing to do with who the
	// connection authenticated as.
	t.Run("rejected when not even signed by the relay's own self key", func(t *testing.T) {
		outsiderPrivKey := generateTestPrivKey(t)
		wrongSignerEv := nip43.NewAddUser("", memberPubkey)
		if err := wrongSignerEv.Sign(outsiderPrivKey); err != nil {
			t.Fatalf("sign add-user event: %v", err)
		}
		// The connection authenticates as exactly who signed this event
		// (satisfying NIP-70), but that pubkey still isn't the relay's
		// own self identity -- CheckSelfAuthored must refuse it anyway.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := NewConnection(ctx, relayURL, &ConnectionConfig{SigningKeyHex: outsiderPrivKey})
		if err != nil {
			t.Fatalf("NewConnection: %v", err)
		}
		defer conn.Close()
		select {
		case <-conn.AuthSettled():
		case <-time.After(3 * time.Second):
			t.Fatal("handshake never settled before publish")
		}

		resp, err := conn.Publish(ctx, wrongSignerEv)
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if resp.Accepted {
			t.Fatalf("Accepted = true, want false (kind:8000 not signed by the relay's own self key)")
		}
		if !strings.Contains(resp.Message, "may only be published by the relay itself") {
			t.Fatalf("Message = %q, want the CheckSelfAuthored rejection", resp.Message)
		}
	})

	// Same event, this time over a connection that authenticated (NIP-42)
	// as exactly the pubkey that signed it: the relay's own self key.
	t.Run("accepted once the connection authenticates as the relay's own self key", func(t *testing.T) {
		if accepted := authenticateAndPublish(t, relayURL, relaySelfPrivKey, addEv); !accepted {
			t.Fatalf("add-user event was not accepted once the connection authenticated as the relay's own self key")
		}
	})
}

// TestNIP29EditMetadata_OmittingPrivateClosedFlipsGroupPublic verifies,
// against a real relay process, the footgun the README's NIP-29 quick
// start flags: nip29.NewEditMetadata's kind:9002 is a full replace of the
// relay's mirrored metadata (relay/groups.go's handleEditMetadata ->
// GroupsService.SetMetadata, which takes groupMetadataFieldsFromAction's
// result wholesale, no merge against what was already stored) -- so an
// edit that omits Private/Closed does not leave them as they were, it
// resets them to false.
func TestNIP29EditMetadata_OmittingPrivateClosedFlipsGroupPublic(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)

	creatorPrivKey := generateTestPrivKey(t)
	groupID := "standup"
	createPrivateGroup(t, relayURL, creatorPrivKey, groupID)

	meta := fetchGroupMetadata(t, relayURL, creatorPrivKey, groupID)
	if !meta.Private || !meta.Closed {
		t.Fatalf("freshly created group: Private=%v Closed=%v, want both true (the documented creation default)", meta.Private, meta.Closed)
	}

	// Edit the group's name only, exactly as a caller who forgot the
	// gotcha would: no Private/Closed in the params at all.
	editEv := nip29.NewEditMetadata("", groupID, nip29.GroupMetadataParams{Name: "Standup"})
	if err := editEv.Sign(creatorPrivKey); err != nil {
		t.Fatalf("sign edit-metadata event: %v", err)
	}
	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, editEv); !accepted {
		t.Fatalf("edit-metadata event was not accepted")
	}

	meta = fetchGroupMetadata(t, relayURL, creatorPrivKey, groupID)
	if meta.Private || meta.Closed {
		t.Fatalf("after an edit omitting Private/Closed: Private=%v Closed=%v, want both false -- "+
			"if this now fails, the full-replace behavior the README warns about has changed and that warning is stale",
			meta.Private, meta.Closed)
	}
	if meta.Name != "Standup" {
		t.Fatalf("Name = %q, want %q", meta.Name, "Standup")
	}

	// The documented fix: pass them explicitly and they stick.
	editEv2 := nip29.NewEditMetadata("", groupID, nip29.GroupMetadataParams{
		Name:    "Standup",
		Private: true,
		Closed:  true,
	})
	if err := editEv2.Sign(creatorPrivKey); err != nil {
		t.Fatalf("sign second edit-metadata event: %v", err)
	}
	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, editEv2); !accepted {
		t.Fatalf("second edit-metadata event was not accepted")
	}

	meta = fetchGroupMetadata(t, relayURL, creatorPrivKey, groupID)
	if !meta.Private || !meta.Closed {
		t.Fatalf("after re-asserting Private/Closed explicitly: Private=%v Closed=%v, want both true", meta.Private, meta.Closed)
	}
}

// pubkeyFor derives the pubkey a private key would sign with, the same
// way relaySelfEvent does in private_group_integration_test.go, without
// needing a throwaway event at every call site.
func pubkeyFor(t *testing.T, privKeyHex string) string {
	t.Helper()
	ev := nip01.NewEvent(0, "")
	if err := ev.Sign(privKeyHex); err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	return ev.PubKey
}

// fetchGroupMetadata reads back a group's kind:39000 mirror and parses
// it, failing the test on any read or parse error.
func fetchGroupMetadata(t *testing.T, relayURL *url.URL, readerPrivKey, groupID string) *nip29.GroupMetadata {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, _, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), readerPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("group %q: no kind:39000 mirror found", groupID)
	}
	meta, err := nip29.ParseGroupMetadata(events[0])
	if err != nil {
		t.Fatalf("ParseGroupMetadata: %v", err)
	}
	return meta
}
