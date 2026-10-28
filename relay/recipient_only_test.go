package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip42"
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/testlogger"
)

const (
	recipientPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	strangerPrivKey  = "0000000000000000000000000000000000000000000000000000000000000002"
	wrapperPrivKey   = "0000000000000000000000000000000000000000000000000000000000000003"
)

// roClient is a test websocket connection that remembers the AUTH
// challenge the relay opened with.
type roClient struct {
	t         *testing.T
	conn      *websocket.Conn
	url       string
	challenge string
}

func newRecipientOnlyRelay(t *testing.T, opts ...SessionOption) (*SessionHandler, string) {
	t.Helper()
	store := newStore(t)
	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1 << 20}}
	handler := NewSessionHandler(store, metadata, nil, append([]SessionOption{WithLogger(testlogger.New(t))}, opts...)...)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	// Runs after every connection's own cleanup has closed it (LIFO), and
	// before srv.Close: see createWS.
	t.Cleanup(func() { waitForSessionCount(t, handler, 0) })
	metadata.URL = "ws" + strings.TrimPrefix(srv.URL, "http")
	return handler, metadata.URL
}

func dialRO(t *testing.T, handler *SessionHandler, url string) *roClient {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &roClient{t: t, conn: conn, url: url}
	label, raw := c.read()
	if label != "AUTH" {
		t.Fatalf("first message %s, want AUTH", label)
	}
	_ = json.Unmarshal(raw[1], &c.challenge)
	return c
}

func (c *roClient) send(msg ...any) {
	c.t.Helper()
	if err := c.conn.WriteJSON(msg); err != nil {
		c.t.Fatal(err)
	}
}

func (c *roClient) read() (string, []json.RawMessage) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var raw []json.RawMessage
	if err := c.conn.ReadJSON(&raw); err != nil {
		c.t.Fatal(err)
	}
	var label string
	_ = json.Unmarshal(raw[0], &label)
	return label, raw
}

// until reads until a message labelled one of labels arrives.
func (c *roClient) until(labels ...string) (string, []json.RawMessage) {
	c.t.Helper()
	for {
		label, raw := c.read()
		for _, l := range labels {
			if label == l {
				return label, raw
			}
		}
	}
}

func (c *roClient) auth(priv string) {
	c.t.Helper()
	ev := nip42.NewAuthEvent(c.challenge, c.url)
	if err := ev.Sign(priv); err != nil {
		c.t.Fatal(err)
	}
	c.send("AUTH", ev)
	_, raw := c.until("OK")
	var ok bool
	_ = json.Unmarshal(raw[2], &ok)
	if !ok {
		c.t.Fatalf("AUTH refused: %s", raw[3])
	}
}

func (c *roClient) publish(ev *nip01.Event) {
	c.t.Helper()
	c.send("EVENT", ev)
	_, raw := c.until("OK")
	var ok bool
	_ = json.Unmarshal(raw[2], &ok)
	if !ok {
		c.t.Fatalf("EVENT refused: %s", raw[3])
	}
}

// req sends a REQ and returns the ids delivered before EOSE, or the CLOSED
// message if it was refused.
func (c *roClient) req(subID string, filter map[string]any) (ids []string, closed string) {
	c.t.Helper()
	c.send("REQ", subID, filter)
	for {
		label, raw := c.until("EVENT", "EOSE", "CLOSED")
		switch label {
		case "EVENT":
			var ev nip01.Event
			_ = json.Unmarshal(raw[2], &ev)
			ids = append(ids, ev.ID)
		case "EOSE":
			return ids, ""
		case "CLOSED":
			_ = json.Unmarshal(raw[2], &closed)
			return ids, closed
		}
	}
}

func (c *roClient) count(subID string, filter map[string]any) (n int64, closed string) {
	c.t.Helper()
	c.send("COUNT", subID, filter)
	label, raw := c.until("COUNT", "CLOSED")
	if label == "CLOSED" {
		_ = json.Unmarshal(raw[2], &closed)
		return 0, closed
	}
	var body struct {
		Count int64 `json:"count"`
	}
	_ = json.Unmarshal(raw[2], &body)
	return body.Count, ""
}

// roSeq makes each roSigned event's content, and so its id, unique.
var roSeq atomic.Int64

func roSigned(t *testing.T, kind int, priv string, tags ...[]string) *nip01.Event {
	t.Helper()
	ev, err := nip01.NewSignedEvent(kind, fmt.Sprint(roSeq.Add(1)), priv, tags...)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func pubOf(t *testing.T, priv string) string {
	return roSigned(t, 1, priv).PubKey
}

// T17-03 (S-CP-09): with WithRecipientOnlyKinds(1059) an un-AUTHed REQ for
// kind 1059 is CLOSED auth-required, the AUTHed recipient gets its wraps and
// anyone else gets none, by REQ, COUNT, live tail or a kind-less filter.
func TestRecipientOnlyKinds(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t, WithRecipientOnlyKinds(1059))
	recipient := pubOf(t, recipientPrivKey)
	wrap := roSigned(t, 1059, wrapperPrivKey, []string{"p", recipient})
	note := roSigned(t, 1, wrapperPrivKey)

	pub := dialRO(t, handler, url)
	pub.publish(wrap)
	pub.publish(note)

	anon := dialRO(t, handler, url)
	if ids, closed := anon.req("a", map[string]any{"kinds": []int{1059}}); len(ids) != 0 || !strings.HasPrefix(closed, "auth-required:") {
		t.Fatalf("un-AUTHed REQ: ids %v closed %q", ids, closed)
	}
	if _, closed := anon.count("c", map[string]any{"kinds": []int{1059}}); !strings.HasPrefix(closed, "auth-required:") {
		t.Fatalf("un-AUTHed COUNT: closed %q", closed)
	}
	// A kind-less filter is served, without the wrap.
	if ids, closed := anon.req("b", map[string]any{"authors": []string{wrap.PubKey}}); closed != "" || len(ids) != 1 || ids[0] != note.ID {
		t.Fatalf("un-AUTHed kind-less REQ: ids %v closed %q", ids, closed)
	}

	other := dialRO(t, handler, url)
	other.auth(strangerPrivKey)
	if ids, closed := other.req("a", map[string]any{"kinds": []int{1059}}); closed != "" || len(ids) != 0 {
		t.Fatalf("AUTHed stranger: ids %v closed %q", ids, closed)
	}
	if n, closed := other.count("c", map[string]any{"kinds": []int{1059}}); closed != "" || n != 0 {
		t.Fatalf("AUTHed stranger COUNT: %d %q", n, closed)
	}

	me := dialRO(t, handler, url)
	me.auth(recipientPrivKey)
	if ids, closed := me.req("a", map[string]any{"kinds": []int{1059}, "#p": []string{recipient}}); closed != "" || len(ids) != 1 || ids[0] != wrap.ID {
		t.Fatalf("AUTHed recipient: ids %v closed %q", ids, closed)
	}
	if n, closed := me.count("c", map[string]any{"kinds": []int{1059}}); closed != "" || n != 1 {
		t.Fatalf("AUTHed recipient COUNT: %d %q", n, closed)
	}

	// Live tail: a new wrap reaches the recipient's open subscription and
	// not the stranger's.
	if ids, _ := other.req("live", map[string]any{"kinds": []int{1059, 1}}); len(ids) != 1 {
		t.Fatalf("stranger stored: %v", ids)
	}
	if ids, _ := me.req("live", map[string]any{"kinds": []int{1059}}); len(ids) != 1 {
		t.Fatalf("recipient stored: %v", ids)
	}
	wrap2 := roSigned(t, 1059, wrapperPrivKey, []string{"p", recipient})
	note2 := roSigned(t, 1, wrapperPrivKey)
	pub.publish(wrap2)
	pub.publish(note2)
	_, raw := me.until("EVENT")
	var got nip01.Event
	_ = json.Unmarshal(raw[2], &got)
	if got.ID != wrap2.ID {
		t.Fatalf("recipient live: got %s", got.ID)
	}
	_, raw = other.until("EVENT")
	_ = json.Unmarshal(raw[2], &got)
	if got.ID != note2.ID {
		t.Fatalf("stranger live: got kind %d, want the note only", got.Kind)
	}
}

// T17-03: off by default, a wrap is served to anyone.
func TestRecipientOnlyKindsOffByDefault(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t)
	wrap := roSigned(t, 1059, wrapperPrivKey, []string{"p", pubOf(t, recipientPrivKey)})
	c := dialRO(t, handler, url)
	c.publish(wrap)
	if ids, closed := c.req("a", map[string]any{"kinds": []int{1059}}); closed != "" || len(ids) != 1 {
		t.Fatalf("default relay: ids %v closed %q", ids, closed)
	}
}

// T17-03: a NEG-OPEN naming 1059 un-AUTHed is refused with a NEG-ERR, and an
// AUTHed stranger's id set leaves the wrap out.
func TestRecipientOnlyKindsNegentropy(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t, WithRecipientOnlyKinds(1059))
	wrap := roSigned(t, 1059, wrapperPrivKey, []string{"p", pubOf(t, recipientPrivKey)})
	c := dialRO(t, handler, url)
	c.publish(wrap)
	c.send("NEG-OPEN", "n", map[string]any{"kinds": []int{1059}}, "61")
	_, raw := c.until("NEG-ERR", "NEG-MSG")
	var label, code string
	_ = json.Unmarshal(raw[0], &label)
	_ = json.Unmarshal(raw[2], &code)
	if label != "NEG-ERR" || !strings.HasPrefix(code, "auth-required:") {
		t.Fatalf("un-AUTHed NEG-OPEN: %s %q", label, code)
	}

	skip := func(pe *PotentialEvent) bool {
		return handler.config.deniedRecipientOnlyPotentialEvent(pubkeyReader{pubOf(t, strangerPrivKey)}, pe)
	}
	f := &nip01.SubscriptionFilter{Kinds: []int{1059}}
	items, err := handler.store.queryNip77Items(context.Background(), f, skip)
	if err != nil || len(items) != 0 {
		t.Fatalf("stranger's items: %v %v", items, err)
	}
	var all []nip77.Item
	if all, err = handler.store.QueryNip77Items(context.Background(), f); err != nil || len(all) != 1 {
		t.Fatalf("unfiltered items: %v %v", all, err)
	}
}

// T17-03: SessionHandler.QueryHandler applies the same rule to POST /query,
// the NIP-98 signer standing in for the AUTHed pubkey.
func TestRecipientOnlyKindsQueryHandler(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t, WithRecipientOnlyKinds(1059))
	wrap := roSigned(t, 1059, wrapperPrivKey, []string{"p", pubOf(t, recipientPrivKey)})
	dialRO(t, handler, url).publish(wrap)

	srv := httptest.NewServer(handler.QueryHandler())
	t.Cleanup(srv.Close)
	body := []byte(`[{"kinds":[1059]}]`)
	for _, tc := range []struct {
		priv string
		want int
	}{{recipientPrivKey, 1}, {strangerPrivKey, 0}} {
		req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", nip98AuthHeader(t, tc.priv, srv.URL, http.MethodPost, body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var got []nip01.Event
		if err := json.Unmarshal(data, &got); err != nil || len(got) != tc.want {
			t.Fatalf("signer %s…: %s (%v), want %d events", tc.priv[60:], data, err, tc.want)
		}
	}
}
