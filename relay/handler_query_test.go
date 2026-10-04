package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

const queryTestPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

func newQueryTestServer(t *testing.T, store *EventStore) string {
	t.Helper()
	srv := httptest.NewServer(NewQueryHandler(store))
	t.Cleanup(srv.Close)
	return srv.URL
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
	otherPrivKey := "0000000000000000000000000000000000000000000000000000000000000001"
	req.Header.Set("Authorization", nip98AuthHeader(t, otherPrivKey, url, http.MethodPost, body))
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
