package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
)

const (
	queryTestPrivKey  = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	queryOtherPrivKey = "0000000000000000000000000000000000000000000000000000000000000001"
)

func newQueryTestServer(t *testing.T, store *EventStore) string {
	t.Helper()
	srv := httptest.NewServer(NewQueryHandler(store, nil, nil))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newQueryTestServerWithMembership serves a relay with MembershipRequired
// set, backed by membership (which the caller populates via Join before
// or after this call -- the service is live, not a snapshot).
func newQueryTestServerWithMembership(t *testing.T, store *EventStore) (url string, membership *MembershipService) {
	t.Helper()
	membership = NewMembershipService(store)
	limitation := &nip11.Limitation{MembershipRequired: true}
	srv := httptest.NewServer(NewQueryHandler(store, limitation, membership))
	t.Cleanup(srv.Close)
	return srv.URL, membership
}

func postQuery(t *testing.T, url string, body []byte, sign bool) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if sign {
		req.Header.Set("Authorization", nip98AuthHeader(t, queryTestPrivKey, url, http.MethodPost, body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestQueryHandlerReturnsMatchingEventsAsFlatArray is the issue #48 golden
// path: a NIP-98-authenticated POST /query with a plain NIP-01 filter array
// returns the matching stored events as a flat JSON array -- the same
// semantics a REQ for the same filter would stream before EOSE, just over
// HTTP.
func TestQueryHandlerReturnsMatchingEventsAsFlatArray(t *testing.T) {
	ev := CreateEvent(t, 1, []string{"p", publicKey})
	other := CreateEvent(t, 1)
	store := newStoreWithEvents(t, []*nip01.Event{ev, other})

	url := newQueryTestServer(t, store)
	body := []byte(`[{"kinds":[1],"#p":["` + publicKey + `"]}]`)

	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}

	var got []nip01.Event
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (filtered by #p)", len(got))
	}
	if got[0].ID != ev.ID {
		t.Fatalf("got event ID = %s, want %s", got[0].ID, ev.ID)
	}
}

// TestQueryHandlerDedupesAcrossFilters guards the OR-of-filters/dedup
// semantics a REQ already has: an event matching more than one filter in
// the array is still delivered once.
func TestQueryHandlerDedupesAcrossFilters(t *testing.T) {
	ev := CreateEvent(t, 1, []string{"p", publicKey})
	store := newStoreWithEvents(t, []*nip01.Event{ev})

	url := newQueryTestServer(t, store)
	body := []byte(`[{"kinds":[1]},{"#p":["` + publicKey + `"]}]`)

	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}

	var got []nip01.Event
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 (deduped across both matching filters)", len(got))
	}
}

// TestQueryHandlerBeforeIDResumesPastSameTimestampTie is the HTTP-level
// counterpart to relay/store_limit_consumers_test.go's FindEvents test,
// through the actual public /query contract: a client paging with Limit,
// cursoring Until/BeforeID off the previous page's last entry exactly as
// buzz-acp's own query_raw_all does, must see every event exactly once and
// must terminate. Until alone cannot disambiguate a same-second tie -- it
// re-matches the boundary event(s) forever.
func TestQueryHandlerBeforeIDResumesPastSameTimestampTie(t *testing.T) {
	tied := uint64(1700000000)
	const total = 7
	const pageLimit = 3
	var all []*nip01.Event
	for i := 0; i < total; i++ {
		// A distinguishing tag per event, or all seven would hash to the
		// same id: CreateEventWithTimestamp's content is fixed.
		all = append(all, CreateEventWithTimestamp(t, 1, tied, []string{"d", fmt.Sprintf("%d", i)}))
	}
	store := newStoreWithEvents(t, all)
	url := newQueryTestServer(t, store)

	seen := map[string]int{}
	filter := map[string]interface{}{"kinds": []int{1}, "limit": pageLimit}
	const maxPages = total/pageLimit + 2

	for page := 1; ; page++ {
		if page > maxPages {
			t.Fatalf("exceeded %d pages without terminating -- before_id is not advancing the cursor", maxPages)
		}
		body, err := json.Marshal([]map[string]interface{}{filter})
		if err != nil {
			t.Fatal(err)
		}
		resp := postQuery(t, url, body, true)
		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			t.Fatalf("page %d: status = %d, body=%s", page, resp.StatusCode, data)
		}
		var got []nip01.Event
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("page %d: decoding response: %v", page, err)
		}
		for _, ev := range got {
			seen[ev.ID]++
		}
		if len(got) < pageLimit {
			break
		}
		last := got[len(got)-1]
		filter["until"] = last.CreatedAt
		filter["before_id"] = last.ID
	}

	if len(seen) != total {
		t.Errorf("got %d unique events, want %d", len(seen), total)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("event %s returned %d times, want exactly once", id, count)
		}
	}
}

// TestQueryHandlerEmptyResultIsEmptyArray guards the "no match" shape the
// issue specifies: an empty JSON array, not null or an error.
func TestQueryHandlerEmptyResultIsEmptyArray(t *testing.T) {
	store := newStore(t)
	url := newQueryTestServer(t, store)
	body := []byte(`[{"kinds":[1]}]`)

	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("body = %q, want []", data)
	}
}

func TestQueryHandlerRejectsUnauthenticatedRequest(t *testing.T) {
	store := newStore(t)
	url := newQueryTestServer(t, store)
	body := []byte(`[{"kinds":[1]}]`)

	resp := postQuery(t, url, body, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestQueryHandlerAcceptsAnyValidlySignedPubkey(t *testing.T) {
	// NIP-98 here binds identity/freshness, not authorization: a second,
	// otherwise-unrelated keypair should be served exactly like the first.
	ev := CreateEvent(t, 1)
	store := newStoreWithEvents(t, []*nip01.Event{ev})
	url := newQueryTestServer(t, store)
	body := []byte(`[{"kinds":[1]}]`)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", nip98AuthHeader(t, queryOtherPrivKey, url, http.MethodPost, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestQueryHandlerRejectsNonPostMethod(t *testing.T) {
	store := newStore(t)
	url := newQueryTestServer(t, store)

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestQueryHandlerRejectsMalformedBody(t *testing.T) {
	store := newStore(t)
	url := newQueryTestServer(t, store)
	body := []byte(`{"not":"an array"}`)

	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// TestQueryHandlerRejectsNonMemberWhenMembershipRequired guards the gate
// NIP-CW's own Access Scoping section requires: this endpoint must not
// bypass whatever access control an equivalent REQ would get. On this
// relay that is the NIP-43 MembershipRequired connection-level check
// (processRequest); a validly-signed but non-member caller must be
// refused here exactly as a REQ would refuse it, not served anyway just
// because the signature checks out.
func TestQueryHandlerRejectsNonMemberWhenMembershipRequired(t *testing.T) {
	ev := CreateEvent(t, 1)
	store := newStoreWithEvents(t, []*nip01.Event{ev})
	url, _ := newQueryTestServerWithMembership(t, store)
	body := []byte(`[{"kinds":[1]}]`)

	// queryTestPrivKey is validly signed (NIP-98 passes) but was never
	// granted membership.
	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestQueryHandlerAllowsMemberWhenMembershipRequired(t *testing.T) {
	ev := CreateEvent(t, 1)
	store := newStoreWithEvents(t, []*nip01.Event{ev})
	url, membership := newQueryTestServerWithMembership(t, store)
	body := []byte(`[{"kinds":[1]}]`)

	memberPubkey := pubkeyOfPrivKey(t, queryTestPrivKey)
	if err := membership.Join(memberPubkey, nil); err != nil {
		t.Fatalf("Join: %v", err)
	}

	resp := postQuery(t, url, body, true)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}

	var got []nip01.Event
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
}

// TestQueryHandlerFailsClosedWithoutMembershipService guards the
// fail-closed posture when MembershipRequired is set but no
// MembershipService was wired through: an operator's misconfiguration
// must not accidentally open the endpoint to everyone.
func TestQueryHandlerFailsClosedWithoutMembershipService(t *testing.T) {
	store := newStore(t)
	limitation := &nip11.Limitation{MembershipRequired: true}
	srv := httptest.NewServer(NewQueryHandler(store, limitation, nil))
	t.Cleanup(srv.Close)
	body := []byte(`[{"kinds":[1]}]`)

	resp := postQuery(t, srv.URL, body, true)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
