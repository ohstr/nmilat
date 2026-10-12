package relay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// banKind1 refuses kind 1 and takes anything else.
func banKind1(ev *nip01.Event) string {
	if ev.Kind == 1 {
		return "blocked: kind 1 is not allowed here"
	}
	return ""
}

// SessionConfig.EventPolicy refuses an EVENT with its message, and the
// event is not stored; an event it allows goes through.
func TestEventPolicy_WebSocket(t *testing.T) {
	sess := newGroupsEnabledTestSession(t)
	sess.config.EventPolicy = banKind1

	refused := nip01.NewEvent(1, "no")
	if err := refused.Sign(authTestPrivKey); err != nil {
		t.Fatal(err)
	}
	resp := sendEventAndAwaitOKForSession(t, sess, refused)
	if resp.Accepted || resp.Message != "blocked: kind 1 is not allowed here" {
		t.Fatalf("kind 1: accepted=%v %q", resp.Accepted, resp.Message)
	}
	if evs, _ := sess.store.QueryEvents(context.Background(), &nip01.SubscriptionFilter{IDs: []string{refused.ID}}); len(evs) != 0 {
		t.Fatal("a refused event was stored")
	}

	allowed := nip01.NewEvent(7, "+")
	if err := allowed.Sign(authTestPrivKey); err != nil {
		t.Fatal(err)
	}
	if resp := sendEventAndAwaitOKForSession(t, sess, allowed); !resp.Accepted {
		t.Fatalf("kind 7 refused: %s", resp.Message)
	}
}

// WithEventsPolicy applies the same policy to POST /events.
func TestEventPolicy_HTTP(t *testing.T) {
	store := newStore(t)
	srv := httptest.NewServer(NewEventsHandler(store, nil, nil, "", WithEventsPolicy(banKind1)))
	t.Cleanup(srv.Close)

	ev := CreateEvent(t, 1)
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	resp := postEvent(t, srv.URL, body, queryTestPrivKey)
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(msg), "blocked: kind 1 is not allowed here") {
		t.Fatalf("status %d: %s", resp.StatusCode, msg)
	}
}
