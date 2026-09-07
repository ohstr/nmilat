package client

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/utils"
)

// TestNWCClient_AgainstRealRelay_LiveDeliveryOfFastReply is a hermetic
// reproduction attempt for the production symptom found while root-causing
// lokihub integration test timeouts: a wallet-side connection that answers
// essentially instantly, and a client-side NWCClient subscribing for the
// reply — does a real relay.SessionHandler (the same engine ncli embeds,
// same nmilat version) actually deliver that live event to the client's
// subscription, or is it lost?
//
// Unlike every other test in this package, both sides here are real
// WebSocket connections to a real, independent relay process (in-process,
// but a genuine separate goroutine/session per connection with its own
// event store) — the fake echo server used elsewhere answers on the same
// connection it read the request from, which can never exercise a genuine
// cross-connection live-broadcast race the way a real relay does.
func TestNWCClient_AgainstRealRelay_LiveDeliveryOfFastReply(t *testing.T) {
	f, err := os.CreateTemp("", "nwc-real-relay-test-*.db")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	r, err := relay.New(f.Name(), &nip11.Metadata{Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024}})
	if err != nil {
		t.Fatalf("relay.New() error = %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	wsURL := strings.Replace(server.URL, "http", "ws", 1)

	walletPubkey, err := utils.GetPublicKey(testWalletPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	// Wallet side: a real Connection (not NWCClient — we're playing the
	// server role here) that subscribes for requests addressed to its own
	// pubkey and answers each one as fast as possible, matching lokihub's
	// backend's own observed same-second turnaround in production.
	relayURL, err := url.Parse(wsURL)
	if err != nil {
		t.Fatalf("parse relay url: %v", err)
	}
	walletConn, err := Connect(context.Background(), relayURL)
	if err != nil {
		t.Fatalf("wallet Connect() error = %v", err)
	}
	t.Cleanup(walletConn.Close)

	reqFilter := nip01.NewSubscriptionFilterGroup(
		nip01.NewFilter().WithKinds(nip47.KindNWCRequest).WithTag("p", walletPubkey),
	)
	// SubscribeWithID + Events, not Subscribe: Subscribe() closes its
	// channel at EOSE (it's meant for "give me historical results, then
	// I'm done"), which fires almost immediately for a fresh filter with
	// nothing stored yet — wrong tool for "keep listening," which is what a
	// wallet service actually needs. This is the same long-lived pattern
	// NWCClient itself uses internally.
	walletSubID := "wallet-req-sub"
	if ok := walletConn.SubscribeWithID(walletSubID, reqFilter); !ok {
		t.Fatalf("SubscribeWithID() = false")
	}
	reqEvents := walletConn.Events(walletSubID)
	walletSawRequest := make(chan struct{}, 1)
	walletSentReply := make(chan struct{}, 1)
	go func() {
		for reqEvent := range reqEvents {
			select {
			case walletSawRequest <- struct{}{}:
			default:
			}
			respEvent := signedPayInvoiceResponse(t, reqEvent.Event, "deadbeef")
			ok := walletConn.Send(respEvent)
			t.Logf("wallet: got request %s, sent reply %s, Send()=%v", reqEvent.Event.ID, respEvent.ID, ok)
			select {
			case walletSentReply <- struct{}{}:
			default:
			}
		}
	}()

	pairing := &nip47.PairingInfo{
		WalletPubkey: walletPubkey,
		RelayURLs:    []string{wsURL},
		Secret:       testAppPrivKey,
	}
	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	elapsed := time.Since(start)
	select {
	case <-walletSawRequest:
		t.Log("diagnostic: wallet DID receive the forwarded request")
	default:
		t.Log("diagnostic: wallet NEVER received the forwarded request")
	}
	select {
	case <-walletSentReply:
		t.Log("diagnostic: wallet DID send a reply")
	default:
		t.Log("diagnostic: wallet never got far enough to send a reply")
	}
	if err != nil {
		t.Fatalf("PayInvoice() error = %v after %s (relay never delivered the wallet's live reply to the client's subscription)", err, elapsed)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
	t.Logf("round trip took %s", elapsed)
}
