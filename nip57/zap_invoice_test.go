package nip57

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// redirectToServerTransport rewrites every request's scheme/host to server's,
// so code that builds a fixed https://<domain>/... URL (GetLud16URL) can
// still be exercised against an httptest.Server.
type redirectToServerTransport struct{ server *httptest.Server }

func (rt redirectToServerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	serverURL, _ := req.URL.Parse(rt.server.URL)
	clone := req.Clone(req.Context())
	clone.URL.Scheme = serverURL.Scheme
	clone.URL.Host = serverURL.Host
	clone.Host = ""
	return http.DefaultTransport.RoundTrip(clone)
}

func TestRequestZapInvoice_HappyPath(t *testing.T) {
	recipientPubkey := "0000000000000000000000000000000000000000000000000000000000000001"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/lnurlp/alice":
			_, _ = fmt.Fprintf(w, `{
				"callback": "%s/callback",
				"minSendable": 1000,
				"maxSendable": 100000000,
				"metadata": "[[\"chain/flokicoin\",\"\"]]",
				"allowsNostr": true,
				"nostrPubkey": "%s"
			}`, "http://"+r.Host, recipientPubkey)
		case "/callback":
			nostrEvent := r.URL.Query().Get("nostr")
			var event struct {
				Kind int `json:"kind"`
			}
			if err := json.Unmarshal([]byte(nostrEvent), &event); err != nil || event.Kind != KindZapRequest {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"pr":"lnbc1invoice"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	result, err := RequestZapInvoice(context.Background(), client, RequestZapInvoiceParams{
		SenderPrivateKey: zapsTestPrivKey,
		RecipientPubkey:  recipientPubkey,
		RecipientLud16:   "alice@example.com",
		AmountMsat:       5000,
		Relays:           []string{"wss://relay.example.com"},
	})
	if err != nil {
		t.Fatalf("RequestZapInvoice: %v", err)
	}
	if result.Bolt11 != "lnbc1invoice" {
		t.Fatalf("Bolt11: got %q", result.Bolt11)
	}
	if len(result.PayResponse.Chains) != 1 || result.PayResponse.Chains[0] != "flokicoin" {
		t.Fatalf("PayResponse.Chains: got %v, want [flokicoin]", result.PayResponse.Chains)
	}
}

func TestRequestZapInvoice_RecipientDoesNotAcceptZaps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"callback":"https://example.com/callback","allowsNostr":false}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	_, err := RequestZapInvoice(context.Background(), client, RequestZapInvoiceParams{
		SenderPrivateKey: zapsTestPrivKey,
		RecipientPubkey:  "0000000000000000000000000000000000000000000000000000000000000001",
		RecipientLud16:   "alice@example.com",
		AmountMsat:       5000,
		Relays:           []string{"wss://relay.example.com"},
	})
	if err == nil {
		t.Fatal("expected an error when the provider doesn't support zaps")
	}
}

func TestRequestZapInvoice_AmountOutOfRange(t *testing.T) {
	recipientPubkey := "0000000000000000000000000000000000000000000000000000000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{
			"callback": "https://example.com/callback",
			"minSendable": 10000,
			"maxSendable": 100000,
			"allowsNostr": true,
			"nostrPubkey": "%s"
		}`, recipientPubkey)
	}))
	defer server.Close()

	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	_, err := RequestZapInvoice(context.Background(), client, RequestZapInvoiceParams{
		SenderPrivateKey: zapsTestPrivKey,
		RecipientPubkey:  recipientPubkey,
		RecipientLud16:   "alice@example.com",
		AmountMsat:       5000, // below minSendable
		Relays:           []string{"wss://relay.example.com"},
	})
	if err == nil {
		t.Fatal("expected an error for an amount below minSendable")
	}
}

func TestRequestZapInvoice_CallbackError(t *testing.T) {
	recipientPubkey := "0000000000000000000000000000000000000000000000000000000000000001"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/lnurlp/alice":
			_, _ = fmt.Fprintf(w, `{
				"callback": "%s/callback",
				"allowsNostr": true,
				"nostrPubkey": "%s"
			}`, "http://"+r.Host, recipientPubkey)
		case "/callback":
			_, _ = w.Write([]byte(`{"status":"ERROR","reason":"amount too small"}`))
		}
	}))
	defer server.Close()

	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	_, err := RequestZapInvoice(context.Background(), client, RequestZapInvoiceParams{
		SenderPrivateKey: zapsTestPrivKey,
		RecipientPubkey:  recipientPubkey,
		RecipientLud16:   "alice@example.com",
		AmountMsat:       5000,
		Relays:           []string{"wss://relay.example.com"},
	})
	if err == nil {
		t.Fatal("expected an error when the callback reports ERROR")
	}
}
