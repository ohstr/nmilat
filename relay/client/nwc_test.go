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

const (
	testWalletPrivKey = "5a3c66fe899f8922d5cff0030b5affa83bcad6b7913e5681395a21979fd25bbf"
	testAppPrivKey    = "e46d12f2e1a4f4ac7b4245bf00b9cfe0b9699c3dbccc210d8bcbda9ef681e304"
)

// newFakeWalletServer starts an in-process WebSocket server that plays the
// wallet-service side of NIP-47: for every REQ+EVENT pair it reads (a
// client request), it invokes respond with the decrypted request event and
// sends back whatever signed response events respond returns, tagged with
// that request's subscription ID. It loops for as long as the connection
// stays open, so a single server instance supports a client that reuses
// its connection across many calls (unlike the relay itself, it doesn't
// EOSE — the client relies on that, matching a real relay's behavior for a
// freshly-opened filter).
func newFakeWalletServer(t *testing.T, respond func(reqEvent *nip01.Event) []*nip01.Event) *httptest.Server {
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

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
				for _, respEvent := range respond(p.Event) {
					eventBytes, err := json.Marshal(respEvent)
					if err != nil {
						return
					}
					evResp := &wire.EventSubscriptionResponse{SubscriptionID: subID, EventBytes: eventBytes}
					evJSON, err := evResp.MarshalJSON()
					if err != nil {
						return
					}
					if err := conn.WriteMessage(websocket.TextMessage, evJSON); err != nil {
						return
					}
				}
			}
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// newTestPairing starts a fake wallet server driven by respond (using
// testWalletPrivKey/testAppPrivKey) and returns a PairingInfo pointed at
// it.
func newTestPairing(t *testing.T, respond func(reqEvent *nip01.Event) []*nip01.Event) *nip47.PairingInfo {
	t.Helper()
	walletPubkey, err := utils.GetPublicKey(testWalletPrivKey)
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	server := newFakeWalletServer(t, respond)
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

func signedPayInvoiceResponse(t *testing.T, reqEvent *nip01.Event, preimage string, extraTags ...[]string) *nip01.Event {
	t.Helper()
	respEvent, err := nip47.NewResponseEvent(testWalletPrivKey, reqEvent.PubKey,
		nip47.MethodPayInvoice, nip47.PayInvoiceResult{Preimage: preimage},
		reqEvent, nip47.EncryptionNIP44V2, extraTags...)
	if err != nil {
		t.Fatalf("NewResponseEvent() error = %v", err)
	}
	if err := respEvent.Sign(testWalletPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return respEvent
}

func TestNWCClient_PayInvoice(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return []*nip01.Event{signedPayInvoiceResponse(t, reqEvent, "deadbeef")}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	result, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err != nil {
		t.Fatalf("PayInvoice() error = %v", err)
	}
	if result.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", result.Preimage, "deadbeef")
	}
}

func TestNWCClient_PayInvoice_WalletError(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		respEvent, err := nip47.NewErrorResponseEvent(testWalletPrivKey, reqEvent.PubKey,
			nip47.MethodPayInvoice, nip47.Error{Code: nip47.ErrInsufficientBalance, Message: "not enough funds"},
			reqEvent, nip47.EncryptionNIP44V2)
		if err != nil {
			t.Fatalf("NewErrorResponseEvent() error = %v", err)
		}
		if err := respEvent.Sign(testWalletPrivKey); err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		return []*nip01.Event{respEvent}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	_, err = client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err == nil {
		t.Fatal("expected error for wallet-declined request")
	}
	var walletErr *WalletError
	if !errors.As(err, &walletErr) {
		t.Fatalf("error = %v, want *WalletError", err)
	}
	if walletErr.Code != nip47.ErrInsufficientBalance {
		t.Errorf("Code = %q, want %q", walletErr.Code, nip47.ErrInsufficientBalance)
	}
}

func TestNWCClient_ConnectionReuse(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		req, err := nip47.ParseRequestEvent(reqEvent, testWalletPrivKey)
		if err != nil {
			t.Fatalf("ParseRequestEvent() error = %v", err)
		}
		switch req.Method {
		case nip47.MethodPayInvoice:
			return []*nip01.Event{signedPayInvoiceResponse(t, reqEvent, "deadbeef")}
		case nip47.MethodGetBalance:
			respEvent, err := nip47.NewResponseEvent(testWalletPrivKey, reqEvent.PubKey,
				nip47.MethodGetBalance, nip47.GetBalanceResult{BalanceMloki: 42000},
				reqEvent, nip47.EncryptionNIP44V2)
			if err != nil {
				t.Fatalf("NewResponseEvent() error = %v", err)
			}
			if err := respEvent.Sign(testWalletPrivKey); err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			return []*nip01.Event{respEvent}
		default:
			t.Fatalf("unexpected method %q", req.Method)
			return nil
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	payResult, err := client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if err != nil {
		t.Fatalf("PayInvoice() error = %v", err)
	}
	if payResult.Preimage != "deadbeef" {
		t.Errorf("Preimage = %q, want %q", payResult.Preimage, "deadbeef")
	}

	balResult, err := client.GetBalance(ctx)
	if err != nil {
		t.Fatalf("GetBalance() error = %v", err)
	}
	if balResult.BalanceMloki != 42000 {
		t.Errorf("BalanceMloki = %d, want %d", balResult.BalanceMloki, 42000)
	}
}

func TestNWCClient_MultiPayInvoice(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		req, err := nip47.ParseRequestEvent(reqEvent, testWalletPrivKey)
		if err != nil {
			t.Fatalf("ParseRequestEvent() error = %v", err)
		}
		if req.Method != nip47.MethodMultiPayInvoice {
			t.Fatalf("unexpected method %q", req.Method)
		}
		var params nip47.MultiPayInvoiceParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			t.Fatalf("unmarshal params: %v", err)
		}
		events := make([]*nip01.Event, len(params.Invoices))
		for i, item := range params.Invoices {
			events[i] = signedPayInvoiceResponse(t, reqEvent, "preimage-"+item.Id, []string{"d", item.Id})
		}
		return events
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewNWCClient(ctx, pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	results, err := client.MultiPayInvoice(ctx, nip47.MultiPayInvoiceParams{
		Invoices: []nip47.MultiPayInvoiceItem{
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc1..."}, Id: "a"},
			{PayInvoiceParams: nip47.PayInvoiceParams{Invoice: "lnfc2..."}, Id: "b"},
		},
	})
	if err != nil {
		t.Fatalf("MultiPayInvoice() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}

	byID := make(map[string]MultiPayInvoiceResult, len(results))
	for _, r := range results {
		byID[r.Id] = r
	}
	for _, id := range []string{"a", "b"} {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing result for id %q", id)
		}
		if r.Error != nil {
			t.Errorf("id %q: unexpected Error = %+v", id, r.Error)
		}
		if r.Result == nil || r.Result.Preimage != "preimage-"+id {
			t.Errorf("id %q: Result = %+v, want Preimage %q", id, r.Result, "preimage-"+id)
		}
	}
}

func TestNWCClient_CloseMidFlight(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return nil // never respond
	})

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := client.PayInvoice(context.Background(), nip47.PayInvoiceParams{Invoice: "lnfc1..."})
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond) // let the request actually reach the fake server
	client.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error after Close()")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PayInvoice did not return after Close()")
	}

	if _, err := client.PayInvoice(context.Background(), nip47.PayInvoiceParams{Invoice: "lnfc1..."}); err == nil {
		t.Fatal("expected error calling PayInvoice after Close()")
	}
}

func TestNWCClient_ContextTimeout(t *testing.T) {
	pairing := newTestPairing(t, func(reqEvent *nip01.Event) []*nip01.Event {
		return nil // never respond
	})

	client, err := NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatalf("NewNWCClient() error = %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err = client.PayInvoice(ctx, nip47.PayInvoiceParams{Invoice: "lnfc1..."})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
}
