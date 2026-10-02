package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// newAnnouncementRelay serves whatever events `serve` returns in answer to any REQ,
// then EOSEs so the reader returns instead of hanging.
//
// A fake rather than the real relay because the session's job is to fetch, verify and
// cache — not to exercise relay storage. Modelled on newFakeClosingWalletServer's own
// shape, which already speaks this protocol.
func newAnnouncementRelay(t *testing.T, serve func() []*nip01.Event) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		writeMsg := func(v json.Marshaler) bool {
			b, err := v.MarshalJSON()
			if err != nil {
				return false
			}
			return conn.WriteMessage(websocket.TextMessage, b) == nil
		}

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}
			req, ok := payload.Packet.(*wire.RequestPacket)
			if !ok {
				continue
			}
			for _, ev := range serve() {
				evBytes, err := json.Marshal(ev)
				if err != nil {
					return
				}
				if !writeMsg(&wire.EventSubscriptionResponse{
					SubscriptionID: req.SubscriptionID, EventBytes: evBytes,
				}) {
					return
				}
			}
			if !writeMsg(&wire.EOSESubscriptionResponse{SubscriptionID: req.SubscriptionID}) {
				return
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func sessionKeypair(t *testing.T) (privHex, xonlyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex = hex.EncodeToString(priv.Serialize())
	pub, err := utils.GetPublicKey(privHex)
	if err != nil {
		t.Fatal(err)
	}
	return privHex, pub
}

// signedAnnouncement builds a real, signed kind-11190 for hubPriv.
func signedAnnouncement(t *testing.T, hubPriv, hubXOnly, inbox string, limits transport.Limits, relays []string) *nip01.Event {
	t.Helper()
	ev, err := transport.NewAnnouncement(hubXOnly, inbox, limits, relays)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Sign(hubPriv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestBatchSession_FetchesVerifiesAndCaches covers the obligations the SDK exists to
// absorb: fetch the announcement, verify it against the identity already trusted, use
// the announced inbox rather than assuming it equals that identity, and size envelopes
// against the announced limits rather than a default.
func TestBatchSession_FetchesVerifiesAndCaches(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, inbox := sessionKeypair(t)

	limits := transport.DefaultLimits()
	limits.MaxItems = 7 // deliberately not the default, so a default cannot pass

	relay := newAnnouncementRelay(t, func() []*nip01.Event {
		return []*nip01.Event{signedAnnouncement(t, hubPriv, hubXOnly, inbox, limits, nil)}
	})

	c := &Client{}
	s, err := c.NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}

	if got := s.Inbox(); got != inbox {
		t.Errorf("Inbox() = %q, want the ANNOUNCED inbox %q", got, inbox)
	}
	if got := s.Inbox(); got == hubXOnly {
		t.Error("Inbox() returned the hub identity; they are different keys by design")
	}
	if got := s.HubIdentity(); got != hubXOnly {
		t.Errorf("HubIdentity() = %q, want %q", got, hubXOnly)
	}
	if got := s.Limits().MaxItems; got != 7 {
		t.Errorf("Limits().MaxItems = %d, want the announced 7 — a default would be %d",
			got, transport.DefaultLimits().MaxItems)
	}
}

// TestBatchSession_RejectsAnAnnouncementFromAnyoneElse is the substitution defence. An
// announcement carries the inbox envelopes get encrypted to, so believing one signed by
// an attacker would mean encrypting a holder's requests to them.
func TestBatchSession_RejectsAnAnnouncementFromAnyoneElse(t *testing.T) {
	_, hubXOnly := sessionKeypair(t)
	attackerPriv, attackerXOnly := sessionKeypair(t)
	_, attackerInbox := sessionKeypair(t)

	relay := newAnnouncementRelay(t, func() []*nip01.Event {
		// Well-formed, correctly signed — by the wrong identity.
		return []*nip01.Event{signedAnnouncement(t, attackerPriv, attackerXOnly, attackerInbox,
			transport.DefaultLimits(), nil)}
	})

	c := &Client{}
	_, err := c.NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if !errors.Is(err, ErrNoAnnouncement) {
		t.Fatalf("NewBatchSession() error = %v, want ErrNoAnnouncement for a foreign signature", err)
	}
}

// TestBatchSession_NoAnnouncementIsNotAFault: the transport is OPTIONAL in both
// directions, so a hub that publishes nothing is a normal answer a caller reacts to by
// falling back — not an error to retry.
func TestBatchSession_NoAnnouncementIsNotAFault(t *testing.T) {
	_, hubXOnly := sessionKeypair(t)
	relay := newAnnouncementRelay(t, func() []*nip01.Event { return nil })

	c := &Client{}
	_, err := c.NewBatchSession(context.Background(), hubXOnly, []string{relay})
	if !errors.Is(err, ErrNoAnnouncement) {
		t.Fatalf("NewBatchSession() error = %v, want ErrNoAnnouncement", err)
	}
}

// TestBatchSession_PrefersAnnouncedRelaysButKeepsTheHints: a bill's token hints were
// fixed at mint time and the hub may have moved, so announced relays take over. The
// hints are kept as a fallback because if the announced relays later disappear they are
// the only way back to the hub.
func TestBatchSession_PrefersAnnouncedRelaysButKeepsTheHints(t *testing.T) {
	hubPriv, hubXOnly := sessionKeypair(t)
	_, inbox := sessionKeypair(t)

	const announced = "wss://announced.example"
	hintRelay := newAnnouncementRelay(t, func() []*nip01.Event {
		return []*nip01.Event{signedAnnouncement(t, hubPriv, hubXOnly, inbox,
			transport.DefaultLimits(), []string{announced})}
	})

	c := &Client{}
	s, err := c.NewBatchSession(context.Background(), hubXOnly, []string{hintRelay})
	if err != nil {
		t.Fatalf("NewBatchSession() error = %v", err)
	}

	relays := s.Relays()
	if len(relays) == 0 || relays[0] != announced {
		t.Errorf("Relays() = %v, want the announced relay first", relays)
	}

	// A refresh must still be able to reach the original hint, or a hub whose
	// announced relays vanish becomes permanently unreachable.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Refresh(ctx); err != nil {
		t.Errorf("Refresh() error = %v; the caller's own hints must stay in the candidate set", err)
	}
}

// TestBatchSession_RequiresRelaysToLookOn: with nowhere to look there is no announcement
// to be had, and saying so beats a confusing empty-result path.
func TestBatchSession_RequiresRelaysToLookOn(t *testing.T) {
	_, hubXOnly := sessionKeypair(t)
	c := &Client{}
	if _, err := c.NewBatchSession(context.Background(), hubXOnly, nil); err == nil {
		t.Fatal("NewBatchSession() with no relays = nil error")
	}
}
