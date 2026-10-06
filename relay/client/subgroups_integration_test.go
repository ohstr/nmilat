package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip29"

	// Blank-imported so RegisterNIP(29) actually fires -- the same thing
	// that puts 29 into supported_nips in a real relay binary, and the
	// gate relay/session.go's ServeHTTP checks before ever setting the
	// NIP-11 document's "nip29" object. Without this, every assertion
	// here about NIP-29 behavior still holds (GroupsService doesn't care
	// whether the registry knows about it), but the NIP-11 test
	// specifically needs it to see anything other than an absent field.
	_ "github.com/ohstr/nmilat/nip29/relayreg"
)

const (
	groupA = "subgroups-a"
	groupB = "subgroups-b"
)

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

// reparentEvent builds and signs a kind:9002 edit-metadata event naming
// newParent, carrying private/closed exactly as the test's groups were
// created with (true/true, createPrivateGroup's own default) -- a kind:9002
// is a full replace, so every field a test cares about has to be restated
// on every edit, not just the one it means to change.
func reparentEvent(t *testing.T, groupID, signerPrivKey, newParent string) *nip01.Event {
	t.Helper()
	ev := nip29.NewEditMetadata("", groupID, nip29.GroupMetadataParams{
		Parent:  newParent,
		Private: true,
		Closed:  true,
	})
	if err := ev.Sign(signerPrivKey); err != nil {
		t.Fatalf("sign edit-metadata event: %v", err)
	}
	return ev
}

func deleteGroupEventFor(t *testing.T, groupID, signerPrivKey string) *nip01.Event {
	t.Helper()
	ev := nip29.NewDeleteGroup("", groupID)
	if err := ev.Sign(signerPrivKey); err != nil {
		t.Fatalf("sign delete-group event: %v", err)
	}
	return ev
}

func fetchGroupMetadataOverWire(t *testing.T, relayURL *url.URL, readerPrivKey, groupID string) *nip29.GroupMetadata {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, _, err := ReadEventsFromRelayWithAuth(ctx, relayURL, groupMetadataFilter(groupID), readerPrivKey)
	if err != nil {
		t.Fatalf("ReadEventsFromRelayWithAuth(%s): %v", groupID, err)
	}
	if len(events) == 0 {
		t.Fatalf("group %q: no kind:39000 mirror found over the wire", groupID)
	}
	meta, err := nip29.ParseGroupMetadata(events[0])
	if err != nil {
		t.Fatalf("ParseGroupMetadata(%s): %v", groupID, err)
	}
	return meta
}

func TestNIP29Subgroups_ReparentPublishesChildTagOnParentMirror(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)
	creatorPrivKey := generateTestPrivKey(t)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupA)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupB)

	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, reparentEvent(t, groupB, creatorPrivKey, groupA)); !accepted {
		t.Fatal("reparent (groupB -> groupA) was not accepted")
	}

	parent := fetchGroupMetadataOverWire(t, relayURL, creatorPrivKey, groupA)
	if len(parent.Children) != 1 || parent.Children[0] != groupB {
		t.Fatalf("groupA's Children over the wire = %v, want [%s]", parent.Children, groupB)
	}
	child := fetchGroupMetadataOverWire(t, relayURL, creatorPrivKey, groupB)
	if child.Parent != groupA {
		t.Fatalf("groupB's Parent over the wire = %q, want %q", child.Parent, groupA)
	}
}

func TestNIP29Subgroups_CycleRejectedEndToEnd(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)
	creatorPrivKey := generateTestPrivKey(t)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupA)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupB)

	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, reparentEvent(t, groupB, creatorPrivKey, groupA)); !accepted {
		t.Fatal("reparent (groupB -> groupA) was not accepted")
	}

	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, reparentEvent(t, groupA, creatorPrivKey, groupB)); accepted {
		t.Fatal("reparent (groupA -> groupB) was accepted, want rejected (would close A -> B -> A)")
	}
}

func TestNIP29Subgroups_CrossGroupAdminRequiredEndToEnd(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)
	ownerAPrivKey := generateTestPrivKey(t)
	ownerBPrivKey := generateTestPrivKey(t)
	createPrivateGroup(t, relayURL, ownerAPrivKey, groupA)
	createPrivateGroup(t, relayURL, ownerBPrivKey, groupB)

	t.Run("rejected without admin rights on the new parent", func(t *testing.T) {
		if accepted := authenticateAndPublish(t, relayURL, ownerBPrivKey, reparentEvent(t, groupB, ownerBPrivKey, groupA)); accepted {
			t.Fatal("ownerB (not an admin of groupA) reparented groupB under it, want rejected")
		}
	})

	t.Run("accepted once the submitter is also an admin of the new parent", func(t *testing.T) {
		// Grant ownerB admin rights on groupA too -- now ownerB is an
		// admin of both the group being edited (groupB) and the new
		// parent (groupA), which is what the cross-group check requires.
		grantEv := nip29.NewPutUser("", groupA, pubkeyFor(t, ownerBPrivKey), "admin")
		if err := grantEv.Sign(ownerAPrivKey); err != nil {
			t.Fatalf("sign grant-admin event: %v", err)
		}
		if accepted := authenticateAndPublish(t, relayURL, ownerAPrivKey, grantEv); !accepted {
			t.Fatal("granting ownerB admin on groupA was not accepted")
		}

		if accepted := authenticateAndPublish(t, relayURL, ownerBPrivKey, reparentEvent(t, groupB, ownerBPrivKey, groupA)); !accepted {
			t.Fatal("ownerB (now admin of both groupB and groupA) reparenting groupB under groupA was not accepted")
		}
	})
}

func TestNIP29Subgroups_DeleteParentCascadesOverRealRelay(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)
	creatorPrivKey := generateTestPrivKey(t)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupA)
	createPrivateGroup(t, relayURL, creatorPrivKey, groupB)

	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, reparentEvent(t, groupB, creatorPrivKey, groupA)); !accepted {
		t.Fatal("reparent (groupB -> groupA) was not accepted")
	}

	if accepted := authenticateAndPublish(t, relayURL, creatorPrivKey, deleteGroupEventFor(t, groupA, creatorPrivKey)); !accepted {
		t.Fatal("delete groupA was not accepted")
	}

	child := fetchGroupMetadataOverWire(t, relayURL, creatorPrivKey, groupB)
	if child.Parent != "" {
		t.Fatalf("groupB's Parent over the wire after its parent was deleted = %q, want root (empty)", child.Parent)
	}
}

func TestNIP29Subgroups_NIP11AdvertisesSubgroupsCapability(t *testing.T) {
	relayURL, _ := newPrivateGroupTestRelay(t, false)

	req, err := http.NewRequest(http.MethodGet, "http://"+relayURL.Host, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Accept", nip11.ContentTypeHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch NIP-11 document: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc struct {
		NIP29 *struct {
			Subgroups bool `json:"subgroups"`
		} `json:"nip29"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode NIP-11 document: %v", err)
	}
	if doc.NIP29 == nil {
		t.Fatal(`NIP-11 document has no "nip29" object, want {"subgroups":true}`)
	}
	if !doc.NIP29.Subgroups {
		t.Fatalf(`NIP-11 "nip29" object = %+v, want Subgroups=true`, doc.NIP29)
	}
}
