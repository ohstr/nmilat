package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip86"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/ohstr/nmilat/wire"
)

// embeddingAdminPrivKey signs the NIP-98 request below; its pubkey is the
// one AllowedPubkeys trusts, mirroring examples/relay-with-management-api.
const embeddingAdminPrivKey = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"

// nip98AuthHeader builds a NIP-98 Authorization header over body, the way a
// real NIP-86 client would. Mirrors nip86's own authHeader test helper
// (nip86/handler_test.go), reimplemented here since that one is unexported
// and this test lives in a different package.
func nip98AuthHeader(t *testing.T, privKey, url, method string, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	ev := &nip01.Event{
		Kind:      27235,
		CreatedAt: uint64(time.Now().Unix()),
		Tags: [][]string{
			{"u", url},
			{"method", method},
			{"payload", hex.EncodeToString(sum[:])},
		},
	}
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(raw)
}

// TestEmbeddingPatternComposesRelayAndManagementAPI proves, over the wire,
// the embedding pattern examples/relay-with-management-api documents and
// ncli already relies on in production: relay.SessionHandler and
// nip86.Handler are two independent http.Handlers, composed by the
// embedder under one mux and sharing one *EventStore, with no router or
// mux of nmilat's own involved.
//
// It drives both halves for real: publish + REQ a kind:1 event through the
// relay's WebSocket upgrade on "/", and call the NIP-86 management API on
// "/admin" with a NIP-98-signed request, confirming both an unauthenticated
// call is refused and an authenticated one from the configured admin
// pubkey succeeds.
func TestEmbeddingPatternComposesRelayAndManagementAPI(t *testing.T) {
	store := newStore(t)

	metadata := &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}}
	relayHandler := NewSessionHandler(store, metadata, nil, WithLogger(testlogger.New(t)))

	router := nip86.NewRouter()
	router.Handle(nip86.MethodSupportedMethods, func(_ context.Context, caller string, _ nip86.Request) (any, error) {
		return router.MethodsFor(caller), nil
	})
	adminPubkey := pubkeyOfPrivKey(t, embeddingAdminPrivKey)
	adminHandler := nip86.NewHandler(nip86.Config{
		Router:         router,
		AllowedPubkeys: []string{adminPubkey},
	})

	mux := http.NewServeMux()
	mux.Handle("/", relayHandler)
	mux.Handle("/admin", adminHandler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// --- relay half: publish, then REQ it back ---

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		waitForSessionCount(t, relayHandler, 0)
	})

	ev := CreateEvent(t, 1)
	if err := conn.WriteJSON(wire.NewEventPacket(ev)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	var okPayload wire.ClientPayload
	if err := conn.ReadJSON(&okPayload); err != nil {
		t.Fatalf("reading OK response: %v", err)
	}
	okResp, isOK := okPayload.SubscriptionResponse.(*wire.OkSubscriptionResponse)
	if !isOK || !okResp.Accepted {
		t.Fatalf("publish not accepted: %#v", okPayload.SubscriptionResponse)
	}

	req := wire.NewRequestPacket("embedding-sub", CreateFilter([]int{1}, 10))
	if err := conn.WriteJSON(req); err != nil {
		t.Fatalf("REQ: %v", err)
	}

	var sawEvent bool
	_ = conn.SetReadDeadline(deadline)
	for !sawEvent {
		var payload wire.ClientPayload
		if err := conn.ReadJSON(&payload); err != nil {
			t.Fatalf("reading REQ response: %v", err)
		}
		switch r := payload.SubscriptionResponse.(type) {
		case *wire.EventSubscriptionResponse:
			if r.Event == nil || r.Event.ID != ev.ID {
				t.Fatalf("delivered event = %#v, want ID %s", r.Event, ev.ID)
			}
			sawEvent = true
		case *wire.EOSESubscriptionResponse:
			t.Fatalf("EOSE before the published event was delivered")
		}
	}

	// --- management-API half: unauthenticated refused, authenticated works ---

	body := []byte(`{"method":"supportedmethods","params":[]}`)
	adminURL := srv.URL + "/admin"

	unauthed, err := http.Post(adminURL, nip86.ContentType, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unauthenticated POST /admin: %v", err)
	}
	_ = unauthed.Body.Close()
	if unauthed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /admin status = %d, want %d", unauthed.StatusCode, http.StatusUnauthorized)
	}

	authedReq, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	authedReq.Header.Set("Content-Type", nip86.ContentType)
	authedReq.Header.Set("Authorization", nip98AuthHeader(t, embeddingAdminPrivKey, adminURL, http.MethodPost, body))

	authed, err := http.DefaultClient.Do(authedReq)
	if err != nil {
		t.Fatalf("authenticated POST /admin: %v", err)
	}
	defer func() { _ = authed.Body.Close() }()
	if authed.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /admin status = %d, want %d", authed.StatusCode, http.StatusOK)
	}

	var resp nip86.Response
	if err := json.NewDecoder(authed.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding /admin response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("authenticated /admin returned error: %s", resp.Error)
	}
}

// pubkeyOfPrivKey derives the pubkey a signed event would carry for
// privKey, without needing a real event to sign.
func pubkeyOfPrivKey(t *testing.T, privKey string) string {
	t.Helper()
	ev := &nip01.Event{}
	if err := ev.Sign(privKey); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev.PubKey
}
