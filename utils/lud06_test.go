package utils

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePayMetadataChains_DefaultsToBitcoin(t *testing.T) {
	got := ParsePayMetadataChains(`[["text/plain","a description"]]`)
	if len(got) != 1 || got[0] != "bitcoin" {
		t.Fatalf("got %v, want [bitcoin]", got)
	}
}

func TestParsePayMetadataChains_MalformedDefaultsToBitcoin(t *testing.T) {
	got := ParsePayMetadataChains("not json")
	if len(got) != 1 || got[0] != "bitcoin" {
		t.Fatalf("got %v, want [bitcoin]", got)
	}
}

func TestParsePayMetadataChains_ExtractsChainEntries(t *testing.T) {
	got := ParsePayMetadataChains(`[["text/plain","a description"],["chain/flokicoin",""],["chain/litecoin",""]]`)
	want := []string{"flokicoin", "litecoin"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestFetchLud16PayResponse_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/lnurlp/alice" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"tag": "payRequest",
			"callback": "https://example.com/callback",
			"minSendable": 1000,
			"maxSendable": 100000000,
			"commentAllowed": 280,
			"metadata": "[[\"chain/flokicoin\",\"\"]]",
			"allowsNostr": true,
			"nostrPubkey": "abc123"
		}`))
	}))
	defer server.Close()

	resp, err := fetchTestPayResponse(t, server, "alice")
	if err != nil {
		t.Fatalf("FetchLud16PayResponse: %v", err)
	}
	if resp.Callback != "https://example.com/callback" {
		t.Fatalf("Callback: got %q", resp.Callback)
	}
	if !resp.AllowsNostr || resp.NostrPubkey != "abc123" {
		t.Fatalf("AllowsNostr/NostrPubkey: got %v/%q", resp.AllowsNostr, resp.NostrPubkey)
	}
	if len(resp.Chains) != 1 || resp.Chains[0] != "flokicoin" {
		t.Fatalf("Chains: got %v, want [flokicoin]", resp.Chains)
	}
	if resp.Tag != "payRequest" || resp.CommentAllowed != 280 {
		t.Fatalf("Tag/CommentAllowed: got %q/%d", resp.Tag, resp.CommentAllowed)
	}
	if resp.Metadata != `[["chain/flokicoin",""]]` {
		t.Fatalf("Metadata: got %q", resp.Metadata)
	}
}

func TestRequestPayInvoice_SendsParamsAndReturnsInvoice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("amount") != "5000" || q.Get("nostr") != `{"kind":9520}` || q.Get("lnurl") != "lnurl1x" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		if got := q.Get("comment"); got != "héllo" {
			t.Errorf("comment: got %q, want it truncated to 5 runes", got)
		}
		_, _ = w.Write([]byte(`{"pr":"lnfc50n1..."}`))
	}))
	defer server.Close()

	pay := &PayResponse{Callback: server.URL + "/cb?id=1", CommentAllowed: 5}
	pr, err := RequestPayInvoice(context.Background(), server.Client(), pay, PayInvoiceParams{
		AmountMsat: 5000, Nostr: `{"kind":9520}`, Lnurl: "lnurl1x", Comment: "héllo world",
	})
	if err != nil {
		t.Fatalf("RequestPayInvoice: %v", err)
	}
	if pr != "lnfc50n1..." {
		t.Fatalf("pr: got %q", pr)
	}
}

func TestRequestPayInvoice_OmitsCommentWhenNotAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("comment") {
			t.Errorf("comment sent to an endpoint with commentAllowed 0")
		}
		_, _ = w.Write([]byte(`{"pr":"lnbc1..."}`))
	}))
	defer server.Close()

	pay := &PayResponse{Callback: server.URL}
	if _, err := RequestPayInvoice(context.Background(), server.Client(), pay, PayInvoiceParams{AmountMsat: 1000, Comment: "hi"}); err != nil {
		t.Fatalf("RequestPayInvoice: %v", err)
	}
}

func TestRequestPayInvoice_ErrorReplies(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"lnurl error": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ERROR","reason":"amount too low"}`))
		},
		"http error": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad request"}`))
		},
		"empty pr": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		},
	} {
		server := httptest.NewServer(handler)
		_, err := RequestPayInvoice(context.Background(), server.Client(), &PayResponse{Callback: server.URL}, PayInvoiceParams{AmountMsat: 1000})
		server.Close()
		if !errors.Is(err, ErrPayCallbackFailed) {
			t.Errorf("%s: got %v, want ErrPayCallbackFailed", name, err)
		}
	}
}

func TestFetchLud16PayResponse_MissingCallbackErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"minSendable": 1000}`))
	}))
	defer server.Close()

	if _, err := fetchTestPayResponse(t, server, "alice"); err == nil {
		t.Fatal("expected an error for a pay response with no callback")
	}
}

func TestFetchLud16PayResponse_NonOKStatusErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	if _, err := fetchTestPayResponse(t, server, "alice"); err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

// fetchTestPayResponse calls FetchLud16PayResponse against server by
// rewriting GetLud16URL's fixed https://<domain>/... shape onto server's own
// address — GetLud16URL always builds an https URL, so tests exercise the
// request-building and response-parsing directly against server's handler
// via a client whose transport redirects to it.
func fetchTestPayResponse(t *testing.T, server *httptest.Server, name string) (*PayResponse, error) {
	t.Helper()
	client := &http.Client{Transport: redirectToServerTransport{server: server}}
	return FetchLud16PayResponse(context.Background(), client, name+"@example.com")
}

type redirectToServerTransport struct {
	server *httptest.Server
}

func (rt redirectToServerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := *req.URL
	serverURL, _ := req.URL.Parse(rt.server.URL)
	target.Scheme = serverURL.Scheme
	target.Host = serverURL.Host
	clone := req.Clone(req.Context())
	clone.URL = &target
	clone.Host = ""
	return http.DefaultTransport.RoundTrip(clone)
}
