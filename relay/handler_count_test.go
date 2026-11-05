package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
)

// postAs POSTs body to url signed (NIP-98) by privKey.
func postAs(t *testing.T, url, privKey string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", nip98AuthHeader(t, privKey, url, http.MethodPost, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeCount(t *testing.T, resp *http.Response) int64 {
	t.Helper()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}
	var got struct {
		Count *int64 `json:"count"`
	}
	if err := json.Unmarshal(data, &got); err != nil || got.Count == nil {
		t.Fatalf("body %s is not {\"count\": n} (%v)", data, err)
	}
	return *got.Count
}

func decodeEvents(t *testing.T, resp *http.Response) []nip01.Event {
	t.Helper()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, data)
	}
	var got []nip01.Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
	return got
}

func TestCountHandlerCountsMatchingEvents(t *testing.T) {
	store := newStoreWithEvents(t, []*nip01.Event{CreateEvent(t, 1, []string{"n", "a"}), CreateEvent(t, 1, []string{"n", "b"}), CreateEvent(t, 7)})
	srv := httptest.NewServer(NewCountHandler(store, nil, nil, nil))
	t.Cleanup(srv.Close)

	if got := decodeCount(t, postAs(t, srv.URL, queryTestPrivKey, []byte(`[{"kinds":[1]}]`))); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if got := decodeCount(t, postAs(t, srv.URL, queryTestPrivKey, []byte(`[{"kinds":[1]},{"kinds":[7]}]`))); got != 3 {
		t.Fatalf("count over two filters = %d, want 3", got)
	}
}

func TestCountHandlerErrorsMatchQuery(t *testing.T) {
	store := newStore(t)
	srv := httptest.NewServer(NewCountHandler(store, nil, nil, nil))
	t.Cleanup(srv.Close)

	if resp := postQuery(t, srv.URL, []byte(`[{"kinds":[1]}]`), false); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: status = %d, want 401", resp.StatusCode)
	}
	if resp := postAs(t, srv.URL, queryTestPrivKey, []byte(`{"kinds":[1]}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad body: status = %d, want 400", resp.StatusCode)
	}
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status = %d, want 405", resp.StatusCode)
	}
}

func TestCountHandlerRefusesNonMemberWhenMembershipRequired(t *testing.T) {
	store := newStoreWithEvents(t, []*nip01.Event{CreateEvent(t, 1)})
	membership := NewMembershipService(store)
	srv := httptest.NewServer(NewCountHandler(store, &nip11.Limitation{MembershipRequired: true}, membership, nil))
	t.Cleanup(srv.Close)
	body := []byte(`[{"kinds":[1]}]`)

	if resp := postAs(t, srv.URL, queryTestPrivKey, body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member: status = %d, want 403", resp.StatusCode)
	}
	if err := membership.Join(pubkeyOfPrivKey(t, queryTestPrivKey), nil); err != nil {
		t.Fatal(err)
	}
	if got := decodeCount(t, postAs(t, srv.URL, queryTestPrivKey, body)); got != 1 {
		t.Fatalf("member: count = %d, want 1", got)
	}
}

// A private group's events are counted only for its members, and a count
// always equals the number of events /query returns for the same signer.
func TestCountHandlerPrivateGroupMatchesQuery(t *testing.T) {
	const groupID = "closed-room"
	inGroup1 := CreateEvent(t, 9, []string{"h", groupID}, []string{"n", "a"})
	inGroup2 := CreateEvent(t, 9, []string{"h", groupID}, []string{"n", "b"})
	outside := CreateEvent(t, 9)
	store := newStoreWithEvents(t, []*nip01.Event{inGroup1, inGroup2, outside})

	groups := NewGroupsService(store)
	if err := groups.Create(newGroupRecord(groupID, authTestPubKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := groups.UpsertMember(groupID, GroupMember{Pubkey: pubkeyOfPrivKey(t, queryTestPrivKey)}); err != nil {
		t.Fatal(err)
	}

	countSrv := httptest.NewServer(NewCountHandler(store, nil, nil, groups))
	t.Cleanup(countSrv.Close)
	querySrv := httptest.NewServer(NewQueryHandler(store, nil, nil, groups))
	t.Cleanup(querySrv.Close)
	untagged := []byte(`[{"kinds":[9]}]`)

	for _, tc := range []struct {
		name string
		priv string
		want int64
	}{
		{"member", queryTestPrivKey, 3},
		{"non-member", queryOtherPrivKey, 1},
	} {
		count := decodeCount(t, postAs(t, countSrv.URL, tc.priv, untagged))
		events := decodeEvents(t, postAs(t, querySrv.URL, tc.priv, untagged))
		if count != tc.want || int64(len(events)) != count {
			t.Fatalf("%s: count = %d, /query = %d events, want both %d", tc.name, count, len(events), tc.want)
		}
	}

	named := []byte(`[{"kinds":[9],"#h":["` + groupID + `"]}]`)
	if resp := postAs(t, countSrv.URL, queryOtherPrivKey, named); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-member naming the group: status = %d, want 403", resp.StatusCode)
	}
	if got := decodeCount(t, postAs(t, countSrv.URL, queryTestPrivKey, named)); got != 2 {
		t.Fatalf("member naming the group: count = %d, want 2", got)
	}
}

func TestCountHandlerRecipientOnlyKinds(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t, WithRecipientOnlyKinds(1059))
	wrap := roSigned(t, 1059, wrapperPrivKey, []string{"p", pubOf(t, recipientPrivKey)})
	dialRO(t, handler, url).publish(wrap)

	srv := httptest.NewServer(handler.CountHandler())
	t.Cleanup(srv.Close)
	body := []byte(`[{"kinds":[1059]}]`)
	if got := decodeCount(t, postAs(t, srv.URL, recipientPrivKey, body)); got != 1 {
		t.Fatalf("recipient: count = %d, want 1", got)
	}
	if got := decodeCount(t, postAs(t, srv.URL, strangerPrivKey, body)); got != 0 {
		t.Fatalf("stranger: count = %d, want 0", got)
	}
}
