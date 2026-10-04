package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip43"
)

func newEventsTestServer(t *testing.T, store *EventStore) string {
	t.Helper()
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, ""))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newEventsTestServerWithMembership(t *testing.T, store *EventStore) (url string, membership *MembershipService) {
	t.Helper()
	membership = NewMembershipService(store)
	limitation := &nip11.Limitation{MembershipRequired: true}
	srv := httptest.NewServer(NewEventsHandler(store, limitation, membership, ""))
	t.Cleanup(srv.Close)
	return srv.URL, membership
}

func postEvent(t *testing.T, url string, body []byte, signWith string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if signWith != "" {
		req.Header.Set("Authorization", nip98AuthHeader(t, signWith, url, http.MethodPost, body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestEventsHandlerAcceptsValidEvent is the golden path: a NIP-98-
// authenticated POST /events, signed by the same key as the submitted
// event, stores it and reports {"accepted":true}.
func TestEventsHandlerAcceptsValidEvent(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	ev := CreateEvent(t, 9, []string{"h", "test-channel"})
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	resp := postEvent(t, url, body, queryTestPrivKey)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}

	var got struct {
		ID       string `json:"event_id"`
		Accepted bool   `json:"accepted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.ID != ev.ID || !got.Accepted {
		t.Fatalf("got %+v, want id=%s accepted=true", got, ev.ID)
	}

	// Actually landed in the store, not just acknowledged.
	stored, err := store.FetchAll()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, se := range stored {
		if se.ID == ev.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("event %s was acknowledged but not found in the store", ev.ID)
	}
}

// TestEventsHandlerDuplicateIsAcceptedIdempotently mirrors processEvent's
// own duplicate tolerance: resubmitting the same event is still accepted
// (just flagged), not an error -- a retrying client should never see a
// different outcome on resend.
func TestEventsHandlerDuplicateIsAcceptedIdempotently(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	ev := CreateEvent(t, 9)
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	first := postEvent(t, url, body, queryTestPrivKey)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first send: status = %d, want 200", first.StatusCode)
	}

	second := postEvent(t, url, body, queryTestPrivKey)
	if second.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(second.Body)
		t.Fatalf("duplicate send: status = %d, want 200, body=%s", second.StatusCode, data)
	}
	var got struct {
		Accepted bool   `json:"accepted"`
		Message  string `json:"message"`
	}
	if err := json.NewDecoder(second.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !got.Accepted || !strings.HasPrefix(got.Message, "duplicate:") {
		t.Fatalf("got %+v, want accepted=true with a duplicate: message", got)
	}
}

func TestEventsHandlerRejectsUnauthenticatedRequest(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	ev := CreateEvent(t, 9)
	body, _ := json.Marshal(ev)

	resp := postEvent(t, url, body, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestEventsHandlerRejectsSignerPubkeyMismatch guards the handler's own
// narrowing beyond processEvent's WS parity: the NIP-98 signer must be the
// submitted event's own author, not merely some validly-signed caller
// relaying someone else's pre-signed event. See NewEventsHandler's doc
// comment for why this is deliberately stricter than the WS path.
func TestEventsHandlerRejectsSignerPubkeyMismatch(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	ev := CreateEvent(t, 9) // authored by publicKey/queryTestPrivKey
	body, _ := json.Marshal(ev)

	// NIP-98 signed by a *different* key than the event's own author.
	resp := postEvent(t, url, body, queryOtherPrivKey)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestEventsHandlerRejectsJoinLeaveRequests guards the explicit scope
// boundary documented on NewEventsHandler: NIP-43 join/leave needs a live
// *Session for its side effects, which this endpoint doesn't have.
func TestEventsHandlerRejectsJoinLeaveRequests(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)

	for _, kind := range []int{nip43.KindJoinRequest, nip43.KindLeaveRequest} {
		ev := CreateEvent(t, kind)
		body, _ := json.Marshal(ev)
		resp := postEvent(t, url, body, queryTestPrivKey)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("kind %d: status = %d, want 400", kind, resp.StatusCode)
		}
	}
}

// TestEventsHandlerRejectsRelayAuthoredKindFromNonRelay guards
// CheckSelfAuthored: a relay-authored kind (e.g. the NIP-43 membership
// list) may only be published by the relay's own key.
func TestEventsHandlerRejectsRelayAuthoredKindFromNonRelay(t *testing.T) {
	store := newStore(t)
	// selfPubkey deliberately not publicKey, so CreateEvent's author is a
	// non-relay impersonator for this kind.
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "0000000000000000000000000000000000000000000000000000000000000002"))
	t.Cleanup(srv.Close)

	ev := CreateEvent(t, nip43.KindMembershipList)
	body, _ := json.Marshal(ev)
	resp := postEvent(t, srv.URL, body, queryTestPrivKey)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestEventsHandlerRejectsNonMemberWhenMembershipRequired(t *testing.T) {
	store := newStore(t)
	url, _ := newEventsTestServerWithMembership(t, store)
	ev := CreateEvent(t, 9)
	body, _ := json.Marshal(ev)

	resp := postEvent(t, url, body, queryTestPrivKey)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestEventsHandlerAllowsMemberWhenMembershipRequired(t *testing.T) {
	store := newStore(t)
	url, membership := newEventsTestServerWithMembership(t, store)
	ev := CreateEvent(t, 9)
	body, _ := json.Marshal(ev)

	if err := membership.Join(publicKey, nil); err != nil {
		t.Fatalf("Join: %v", err)
	}

	resp := postEvent(t, url, body, queryTestPrivKey)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}
}

func TestEventsHandlerRejectsNonPostMethod(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestEventsHandlerRejectsMalformedBody(t *testing.T) {
	store := newStore(t)
	url := newEventsTestServer(t, store)
	// A JSON array (not an object) fails to unmarshal into nip01.Event --
	// unlike a well-formed-but-empty object, which would merely zero-fill
	// the struct and get rejected by the signer/pubkey check instead.
	body := []byte(`[1,2,3]`)

	resp := postEvent(t, url, body, queryTestPrivKey)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
