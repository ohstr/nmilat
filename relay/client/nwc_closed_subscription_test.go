package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// newFakeClosingWalletServer starts an in-process WebSocket server that,
// for the subscription a client opens, sends a CLOSED message instead of
// (or, if respond is non-nil, in addition to) ever answering with a real
// response event.
//
// If respond is nil, CLOSED is sent immediately upon receiving the REQ —
// this reproduces a relay rejecting the subscription outright (e.g. NIP-11
// max_subscriptions exceeded), which a real relay always follows a
// rejection NOTICE with. If respond is non-nil, the server first sends
// whatever events respond returns for the request it reads, then sends
// CLOSED for that same subscription right after — this reproduces the
// relay revoking a subscription immediately after a response was already
// in flight to it.
func newFakeClosingWalletServer(t *testing.T, closeMessage string, respond func(reqEvent *nip01.Event) []*nip01.Event) *httptest.Server {
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

		var subID string
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
				subID = p.SubscriptionID
				if respond == nil {
					if !writeMsg(&wire.ClosedSubscriptionResponse{SubscriptionID: subID, Message: closeMessage}) {
						return
					}
				}
			case *wire.EventPacket:
				if subID == "" || respond == nil {
					continue
				}
				for _, respEvent := range respond(p.Event) {
					eventBytes, err := json.Marshal(respEvent)
					if err != nil {
						return
					}
					if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: eventBytes}) {
						return
					}
				}
				if !writeMsg(&wire.ClosedSubscriptionResponse{SubscriptionID: subID, Message: closeMessage}) {
					return
				}
			}
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestPairingWithServer(t *testing.T, server *httptest.Server) *nip47.PairingInfo {
	t.Helper()
	walletPubkey, err := utils.GetPublicKey(testWalletPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	wsURL := strings.Replace(server.URL, "http", "ws", 1)
	if _, err := url.Parse(wsURL); err != nil {
		t.Fatalf("failed to parse relay URL: %v", err)
	}

	return &nip47.PairingInfo{
		WalletPubkey: walletPubkey,
		RelayURLs:    []string{wsURL},
		Secret:       testAppPrivKey,
	}
}

// TestNWCClient_SubscriptionClosed_FailsFastNotTimeout is a regression test
// for the bug this fix addresses: previously, a relay rejecting a
// subscription (CLOSED, with no response ever coming) was silently ignored
// by dispatch() — the call had no way to learn its subscription was dead,
// and just blocked until ctx's full timeout, indistinguishable from an
// ordinary slow response. With the fix, the call returns immediately with a
// *SubscriptionClosedError carrying the relay's own message.
func TestNWCClient_SubscriptionClosed_FailsFastNotTimeout(t *testing.T) {
	const closeReason = "too many concurrent subscriptions"
	server := newFakeClosingWalletServer(t, closeReason, nil)
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	// Generous relative to how fast this must return: proves the call
	// fails fast on the relay's CLOSED, not by riding out the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("PayInvoice() error = nil, want a SubscriptionClosedError")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PayInvoice() error = %v, want a SubscriptionClosedError, not a context timeout", err)
	}
	var closedErr *SubscriptionClosedError
	if !errors.As(err, &closedErr) {
		t.Fatalf("PayInvoice() error = %v (%T), want *SubscriptionClosedError", err, err)
	}
	if closedErr.Reason != closeReason {
		t.Errorf("SubscriptionClosedError.Reason = %q, want %q", closedErr.Reason, closeReason)
	}
	if elapsed >= 4*time.Second {
		t.Errorf("PayInvoice() took %s, want it to fail fast well before the 5s deadline", elapsed)
	}
}

// TestNWCClient_ResponseWinsOverRacingClosed proves the fix doesn't turn a
// real, successfully delivered response into a spurious error just because
// the relay also closes the subscription right after (e.g. immediately
// revoking it once the call it was opened for is done): a response that
// made it into the channel always takes priority over reporting the
// closure.
func TestNWCClient_ResponseWinsOverRacingClosed(t *testing.T) {
	server := newFakeClosingWalletServer(t, "subscription complete", func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{signedPayInvoiceResponse(t, reqEvent, "deadbeef")}
	})
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err != nil {
		t.Fatalf("PayInvoice() error = %v, want the real response despite the immediately-following CLOSED", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
}

// TestNWCClient_MultiPayInvoice_ClosedBeforeAnyResults exercises waitAll's
// own CLOSED handling (distinct from waitOne's, covered above) with the
// simplest case: the relay closes the subscription before answering any
// sub-payment at all.
func TestNWCClient_MultiPayInvoice_ClosedBeforeAnyResults(t *testing.T) {
	const closeReason = "too many concurrent subscriptions"
	server := newFakeClosingWalletServer(t, closeReason, nil)
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	results, err := client.MultiPayInvoice(ctx, nip47.MultiPayInvoiceParams{
		Invoices: []nip47.MultiPayInvoiceItem{
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc1..."}, Id: "a"},
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc2..."}, Id: "b"},
		},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("MultiPayInvoice() error = nil, want a SubscriptionClosedError")
	}
	var closedErr *SubscriptionClosedError
	if !errors.As(err, &closedErr) {
		t.Fatalf("MultiPayInvoice() error = %v (%T), want *SubscriptionClosedError", err, err)
	}
	if len(results) != 0 {
		t.Errorf("results = %+v, want none", results)
	}
	if elapsed >= 4*time.Second {
		t.Errorf("MultiPayInvoice() took %s, want it to fail fast well before the 5s deadline", elapsed)
	}
}

// TestNWCClient_MultiPayInvoice_ClosedAfterPartialResults exercises the part
// of waitAll's CLOSED handling TestNWCClient_MultiPayInvoice_ClosedBeforeAnyResults
// doesn't: some, but not all, sub-payments were already answered when the
// relay closes the subscription. The caller must get back what was
// collected so far, not silently lose it, alongside the error explaining
// why the rest never arrived.
func TestNWCClient_MultiPayInvoice_ClosedAfterPartialResults(t *testing.T) {
	const closeReason = "wallet is shutting down"
	server := newFakeClosingWalletServer(t, closeReason, func(reqEvent *nip01.Event) []*nip01.Event {
		req, err := nip47.ParseRequestEvent(reqEvent, testWalletPrivKey)
		if err != nil {
			t.Fatalf("ParseRequestEvent() error = %v", err)
		}
		var params nip47.MultiPayInvoiceParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			t.Fatalf("unmarshal params: %v", err)
		}
		// Answer only the first item - the second is left hanging, then the
		// relay closes.
		return []*nip01.Event{signedPayInvoiceResponse(t, reqEvent, "preimage-"+params.Invoices[0].Id, []string{"d", params.Invoices[0].Id})}
	})
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := client.MultiPayInvoice(ctx, nip47.MultiPayInvoiceParams{
		Invoices: []nip47.MultiPayInvoiceItem{
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc1..."}, Id: "a"},
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc2..."}, Id: "b"},
		},
	})

	var closedErr *SubscriptionClosedError
	if !errors.As(err, &closedErr) {
		t.Fatalf("MultiPayInvoice() error = %v (%T), want *SubscriptionClosedError", err, err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1 (the one answered before CLOSED)", len(results))
	}
	if results[0].Id != "a" || results[0].Result == nil || results[0].Result.Preimage != "preimage-a" {
		t.Errorf("results[0] = %+v, want id \"a\" with preimage \"preimage-a\"", results[0])
	}
}

// TestNWCClient_DuplicateClosed_DoesNotPanic guards dispatch()'s own
// already-closed check: a relay sending CLOSED twice for the same
// subscription (e.g. once for a NOTICE-driven rejection, once more on
// connection teardown) must not attempt to close sub.closed a second time -
// that would panic (close of closed channel) and take down every other
// in-flight call on the same connection, not just this one.
func TestNWCClient_DuplicateClosed_DoesNotPanic(t *testing.T) {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
			p, ok := payload.Packet.(*wire.RequestPacket)
			if !ok {
				continue
			}
			// Send CLOSED twice in a row for the same subscription.
			for i := 0; i < 2; i++ {
				b, err := (&wire.ClosedSubscriptionResponse{SubscriptionID: p.SubscriptionID, Message: "closed"}).MarshalJSON()
				if err != nil || conn.WriteMessage(websocket.TextMessage, b) != nil {
					return
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The assertion that matters here is implicit: if dispatch() panics on
	// the second CLOSED, the whole test binary crashes rather than this
	// call merely returning an error - go test -race also needs a clean
	// run to confirm the channel-close guard itself isn't racy.
	if _, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."}); err == nil {
		t.Fatal("PayInvoice() error = nil, want a SubscriptionClosedError")
	}

	// The connection, and dispatch()'s handling of it, must still be alive
	// and well after the duplicate CLOSED - prove it with a second, ordinary
	// call on the same client.
	server2 := newFakeClosingWalletServer(t, "", func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{signedPayInvoiceResponse(t, reqEvent, "deadbeef")}
	})
	pairing2 := newTestPairingWithServer(t, server2)
	client2, err := NewNWCClient(context.Background(), pairing2, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client2.Close()
	result, err := client2.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc2..."})
	if err != nil {
		t.Fatalf("PayInvoice() on a fresh client error = %v, dispatch() may be wedged from the earlier duplicate CLOSED", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
}

// TestNWCClient_ClosedForUnknownSubscription_Ignored guards dispatch()'s
// !found branch: a CLOSED for a subscription ID this client never
// registered (or already unregistered) - e.g. a stray message for a
// previous call reusing the same long-lived connection - must be silently
// ignored, not disrupt any other in-flight call.
func TestNWCClient_ClosedForUnknownSubscription_Ignored(t *testing.T) {
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

		// A CLOSED for a subscription ID that was never opened on this
		// connection at all.
		if !writeMsg(&wire.ClosedSubscriptionResponse{SubscriptionID: "not-a-real-subscription", Message: "stray"}) {
			return
		}

		var subID string
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
				subID = p.SubscriptionID
			case *wire.EventPacket:
				if subID == "" {
					continue
				}
				respEvent := signedPayInvoiceResponse(t, p.Event, "deadbeef")
				eventBytes, err := json.Marshal(respEvent)
				if err != nil {
					return
				}
				if !writeMsg(&wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: eventBytes}) {
					return
				}
			}
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	pairing := newTestPairingWithServer(t, server)

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err != nil {
		t.Fatalf("PayInvoice() error = %v, want the stray CLOSED for an unrelated subscription to be silently ignored", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
}
