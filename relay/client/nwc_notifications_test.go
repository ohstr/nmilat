package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// newNotifyingWalletServer answers the first REQ it sees by pushing events
// on that subscription, then waits for a CLOSE and reports it on closedSub.
func newNotifyingWalletServer(t *testing.T, events []*nip01.Event, closedSub chan<- string) *nip47.PairingInfo {
	t.Helper()
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var payload wire.RelayPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				continue
			}
			switch p := payload.Packet.(type) {
			case *wire.RequestPacket:
				for _, ev := range events {
					evBytes, _ := json.Marshal(ev)
					out, _ := (&wire.EventSubscriptionResponse{SubscriptionID: p.SubscriptionID, EventBytes: evBytes}).MarshalJSON()
					if err := conn.WriteMessage(websocket.TextMessage, out); err != nil {
						return
					}
				}
			case *wire.ClosePacket:
				select {
				case closedSub <- p.SubscriptionID:
				default:
				}
			}
		}
	}))
	t.Cleanup(server.Close)

	walletPubkey, err := utils.GetPublicKey(testWalletPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	return &nip47.PairingInfo{
		WalletPubkey: walletPubkey,
		RelayURLs:    []string{strings.Replace(server.URL, "http", "ws", 1)},
		Secret:       testAppPrivKey,
	}
}

func signedNotification(t *testing.T, signerPriv, notifType string, nip44 bool) *nip01.Event {
	t.Helper()
	appPubkey, err := utils.GetPublicKey(testAppPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nip47.NewNotificationEvent(signerPriv, appPubkey, nip47.Notification{
		NotificationType: notifType,
		Notification:     json.RawMessage(`{"amount":1000}`),
	}, nip44)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Sign(signerPriv); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestNWCClient_Notifications(t *testing.T) {
	const strangerPriv = "0000000000000000000000000000000000000000000000000000000000000003"
	closed := make(chan string, 1)
	pairing := newNotifyingWalletServer(t, []*nip01.Event{
		signedNotification(t, strangerPriv, "forged", true), // not the wallet: dropped
		signedNotification(t, testWalletPrivKey, "payment_received", true),
		signedNotification(t, testWalletPrivKey, "payment_sent", false), // legacy NIP-04
	}, closed)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	notifs, err := client.Notifications(ctx, 4)
	if err != nil {
		t.Fatalf("Notifications: %v", err)
	}

	for _, want := range []string{"payment_received", "payment_sent"} {
		select {
		case n := <-notifs:
			if n.NotificationType != want {
				t.Fatalf("got %q, want %q", n.NotificationType, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}

	cancel()
	select {
	case _, ok := <-notifs:
		if ok {
			t.Fatal("unexpected extra notification (forged one should be dropped)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed after ctx cancel")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("relay never got a CLOSE for the notification subscription")
	}
}

func TestNWCClient_NotificationsClosedWithClient(t *testing.T) {
	pairing := newNotifyingWalletServer(t, nil, make(chan string, 1))
	client, err := NewNWCClient(context.Background(), pairing, "")
	if err != nil {
		t.Fatalf("NewNWCClient: %v", err)
	}
	notifs, err := client.Notifications(context.Background(), 1)
	if err != nil {
		t.Fatalf("Notifications: %v", err)
	}
	select {
	case <-client.Done():
		t.Fatal("Done closed while the client is still open")
	default:
	}
	client.Close()
	select {
	case <-client.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	select {
	case _, ok := <-notifs:
		if ok {
			t.Fatal("unexpected notification")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed after client.Close")
	}
	if _, err := client.Notifications(context.Background(), 1); err == nil {
		t.Fatal("Notifications on a closed client should fail")
	}
}
