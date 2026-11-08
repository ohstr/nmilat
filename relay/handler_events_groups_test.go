package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ohstr/nmilat/nip29"
)

// TestEventsHandlerRefusesGroupModerationKinds: a NIP-29 moderation
// event or group request is a command the WebSocket path applies, so
// /events refuses it rather than storing it unapplied.
func TestEventsHandlerRefusesGroupModerationKinds(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	for _, kind := range []int{nip29.KindPutUser, nip29.KindCreateGroup, nip29.KindCreateInvite, 9020, nip29.KindJoinRequest, nip29.KindLeaveRequest} {
		ev := CreateEvent(t, kind, []string{"h", groupA})
		body, _ := json.Marshal(ev)
		resp := postEvent(t, url, body, queryTestPrivKey)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("kind %d: status = %d, want 400", kind, resp.StatusCode)
		}
		if store.has(ev.ID) {
			t.Fatalf("kind %d was stored", kind)
		}
	}
}

// TestEventsHandlerGroupWriteGate: with the relay's groups, content
// tagged into a closed group needs its author to be a member, as over the
// WebSocket.
func TestEventsHandlerGroupWriteGate(t *testing.T) {
	store := newStore(t)
	groups := NewGroupsService(store)
	if err := groups.Create(newGroupRecord(groupA, memberA)); err != nil { // private and closed
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "", WithEventsGroups(groups)))
	t.Cleanup(srv.Close)

	outsider := CreateEvent(t, 9, []string{"h", groupA})
	body, _ := json.Marshal(outsider)
	if resp := postEvent(t, srv.URL, body, queryTestPrivKey); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member: status = %d, want 403", resp.StatusCode)
	}
	if store.has(outsider.ID) {
		t.Fatal("a non-member's group message was stored")
	}

	if _, err := groups.UpsertMember(groupA, GroupMember{Pubkey: publicKey}); err != nil {
		t.Fatal(err)
	}
	member := CreateEvent(t, 9, []string{"h", groupA}, []string{"t", "member"})
	body, _ = json.Marshal(member)
	if resp := postEvent(t, srv.URL, body, queryTestPrivKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("member: status = %d, want 200", resp.StatusCode)
	}
}
