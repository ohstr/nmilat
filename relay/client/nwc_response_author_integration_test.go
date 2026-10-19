package client

import (
	"context"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/relay"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// Against a real relay, where anyone can publish: an attacker watching for
// requests answers first, the wallet answers after it, and the client returns
// the wallet's answer.
func TestNWCClient_RealRelay_IgnoresAnAttackersFasterResponse(t *testing.T) {
	r, err := relay.New(filepath.Join(t.TempDir(), "relay.db"), &nip11.Metadata{
		Name:       "nwc-response-author",
		Limitation: nip11.Limitation{MaxMessageLength: 1024 * 1024},
	})
	if err != nil {
		t.Fatalf("relay.New: %v", err)
	}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	relayURL, err := url.Parse(strings.Replace(srv.URL, "http", "ws", 1))
	if err != nil {
		t.Fatal(err)
	}
	walletPubkey, err := utils.GetPublicKey(testWalletPrivKey)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The watcher sees every request; the publisher answers each one, first
	// as the attacker and then as the real wallet. Subscribe would stop at
	// EOSE, before any request arrives, so this listens on Read.
	watcher, err := Connect(ctx, relayURL)
	if err != nil {
		t.Fatalf("Connect watcher: %v", err)
	}
	defer watcher.Close()
	publisher, err := Connect(ctx, relayURL)
	if err != nil {
		t.Fatalf("Connect publisher: %v", err)
	}
	defer publisher.Close()
	watcher.SubscribeWithID("requests", nip01.NewSubscriptionFilterGroup(
		nip01.NewFilter().WithKinds(nip47.KindNWCRequest).WithTag("p", walletPubkey),
	))
	go func() {
		for msg := range watcher.Read() {
			m, ok := msg.(*wire.EventSubscriptionResponse)
			if !ok || m.Event == nil {
				continue
			}
			if _, err := publisher.Publish(ctx, forgedPayInvoiceResponse(t, testAttackerPrivKey, m.Event, "forged")); err != nil {
				t.Errorf("publish forged reply: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := publisher.Publish(ctx, signedPayInvoiceResponse(t, m.Event, "deadbeef")); err != nil {
				t.Errorf("publish wallet reply: %v", err)
			}
		}
	}()
	// Let the relay register the watcher's REQ before the request goes out.
	time.Sleep(200 * time.Millisecond)

	client, err := NewNWCClient(ctx, &nip47.PairingInfo{
		WalletPubkey: walletPubkey,
		RelayURLs:    []string{relayURL.String()},
		Secret:       testAppPrivKey,
	}, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient: %v", err)
	}
	defer client.Close()

	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err != nil {
		t.Fatalf("PayInvoice: %v", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want the wallet's %q", result.Preimage, "deadbeef")
	}
}
