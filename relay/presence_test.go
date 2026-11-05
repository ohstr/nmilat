package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func presenceQuery(t *testing.T, url, signer string, authors ...string) (int, []nip01.Event) {
	t.Helper()
	body := []byte(fmt.Sprintf(`[{"kinds":[%d],"authors":["%s"]}]`, DefaultPresenceQueryKind, strings.Join(authors, `","`)))
	resp := postAs(t, url, signer, body)
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var evs []nip01.Event
	if err := json.Unmarshal(data, &evs); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
	return resp.StatusCode, evs
}

func statusOf(t *testing.T, evs []nip01.Event, pubkey string) string {
	t.Helper()
	for i := range evs {
		if tagValue(&evs[i], "p") == pubkey {
			return evs[i].Content
		}
	}
	t.Fatalf("no presence for %s in %v", pubkey, evs)
	return ""
}

func TestPresenceSnapshot(t *testing.T) {
	handler, url := newRecipientOnlyRelay(t,
		WithSessionPrivKey(authTestPrivKey),
		WithPresenceQueryKind(DefaultPresenceQueryKind),
		WithRelayAuthoredKinds(DefaultPresenceQueryKind))
	srv := httptest.NewServer(handler.QueryHandler())
	t.Cleanup(srv.Close)

	alice, bob := pubOf(t, recipientPrivKey), pubOf(t, strangerPrivKey)
	c := dialRO(t, handler, url)
	c.auth(recipientPrivKey)

	code, evs := presenceQuery(t, srv.URL, strangerPrivKey, alice, bob)
	if code != http.StatusOK || len(evs) != 2 {
		t.Fatalf("status %d, %d events, want 200 and 2", code, len(evs))
	}
	for i := range evs {
		if evs[i].PubKey != authTestPubKey || evs[i].Kind != KindPresence || evs[i].Verify() != nil {
			t.Fatalf("event %+v is not a relay-signed kind %d", evs[i], KindPresence)
		}
	}
	if s := statusOf(t, evs, alice); s != "online" {
		t.Fatalf("connected alice = %q, want online", s)
	}
	if s := statusOf(t, evs, bob); s != "offline" {
		t.Fatalf("absent bob = %q, want offline", s)
	}

	t.Run("a published status replaces online", func(t *testing.T) {
		away, err := nip01.NewSignedEvent(KindPresence, "away", recipientPrivKey)
		if err != nil {
			t.Fatal(err)
		}
		c.publish(away)
		_, evs := presenceQuery(t, srv.URL, strangerPrivKey, alice)
		if s := statusOf(t, evs, alice); s != "away" {
			t.Fatalf("alice = %q, want away", s)
		}
	})

	t.Run("nothing is stored", func(t *testing.T) {
		stored, err := handler.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{Authors: []string{authTestPubKey}, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(stored) != 0 {
			t.Fatalf("stored %d relay-signed events, want 0", len(stored))
		}
	})

	t.Run("a client may not publish the query kind", func(t *testing.T) {
		forged, err := nip01.NewSignedEvent(DefaultPresenceQueryKind, "", recipientPrivKey)
		if err != nil {
			t.Fatal(err)
		}
		c.send("EVENT", forged)
		_, raw := c.until("OK")
		var ok bool
		_ = json.Unmarshal(raw[2], &ok)
		if ok {
			t.Fatal("a client-signed presence query kind was accepted")
		}
	})

	t.Run("authors are checked", func(t *testing.T) {
		if code, _ := presenceQuery(t, srv.URL, strangerPrivKey, "not-hex"); code != http.StatusBadRequest {
			t.Fatalf("bad author: status %d, want 400", code)
		}
		many := make([]string, MaxPresenceAuthors+1)
		for i := range many {
			many[i] = fmt.Sprintf("%064x", i)
		}
		if code, _ := presenceQuery(t, srv.URL, strangerPrivKey, many...); code != http.StatusBadRequest {
			t.Fatalf("too many authors: status %d, want 400", code)
		}
	})

	t.Run("offline once the last connection closes", func(t *testing.T) {
		_ = c.conn.Close()
		waitForSessionCount(t, handler, 0)
		_, evs := presenceQuery(t, srv.URL, strangerPrivKey, alice)
		if s := statusOf(t, evs, alice); s != "offline" {
			t.Fatalf("disconnected alice = %q, want offline", s)
		}
		if s := handler.presence.get(alice); s != "" {
			t.Fatalf("kept status %q after the last connection closed", s)
		}
	})
}

func TestPresenceSnapshotOffByDefault(t *testing.T) {
	handler, _ := newRecipientOnlyRelay(t, WithSessionPrivKey(authTestPrivKey))
	srv := httptest.NewServer(handler.QueryHandler())
	t.Cleanup(srv.Close)

	code, evs := presenceQuery(t, srv.URL, strangerPrivKey, pubOf(t, recipientPrivKey))
	if code != http.StatusOK || len(evs) != 0 {
		t.Fatalf("status %d, %d events, want an ordinary empty /query result", code, len(evs))
	}
}
