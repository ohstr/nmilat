package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PayResponse is a LUD-06 payRequest document (a LUD-16 identifier's
// well-known endpoint), plus NIP-57's allowsNostr/nostrPubkey fields and
// NIP-AZ's chain/* metadata entries already parsed out.
type PayResponse struct {
	Tag            string // "payRequest" for an LNURL-pay endpoint
	Callback       string
	MinSendable    int64
	MaxSendable    int64
	CommentAllowed int64  // LUD-12: max comment length; 0 means no comments
	Metadata       string // raw metadata string, as served
	AllowsNostr    bool
	NostrPubkey    string
	Chains         []string // never empty; see ParsePayMetadataChains
}

// ParsePayMetadataChains extracts the Lightning-routable chains a LUD-06
// payRequest's "metadata" field advertises (NIP-AZ's "chain/<name>"
// entries, e.g. "chain/flokicoin"). metadata is the raw metadata string
// exactly as the payRequest response carries it — a JSON-encoded array, not
// a nested array itself. Returns ["bitcoin"] when no chain entry is present,
// or when metadata is malformed.
func ParsePayMetadataChains(metadata string) []string {
	var entries [][]any
	if err := json.Unmarshal([]byte(metadata), &entries); err != nil {
		return []string{"bitcoin"}
	}
	var chains []string
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		tag, ok := entry[0].(string)
		if !ok || !strings.HasPrefix(tag, "chain/") {
			continue
		}
		chains = append(chains, strings.TrimPrefix(tag, "chain/"))
	}
	if len(chains) == 0 {
		return []string{"bitcoin"}
	}
	return chains
}

// FetchLud16PayResponse fetches and parses a LUD-16 identifier's LNURL-pay
// document. Returns an error only for a transport failure, a non-200
// response, or a document missing its callback URL; a malformed metadata
// field degrades to Chains = ["bitcoin"] instead of failing the whole fetch.
func FetchLud16PayResponse(ctx context.Context, client *http.Client, lud16 string) (*PayResponse, error) {
	endpoint := GetLud16URL(lud16)
	if endpoint == "" {
		return nil, fmt.Errorf("invalid lud16 identifier %q", lud16)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lud16 %q: unexpected status %d", lud16, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var wire struct {
		Tag            string `json:"tag"`
		Callback       string `json:"callback"`
		MinSendable    int64  `json:"minSendable"`
		MaxSendable    int64  `json:"maxSendable"`
		CommentAllowed int64  `json:"commentAllowed"`
		Metadata       string `json:"metadata"`
		AllowsNostr    bool   `json:"allowsNostr"`
		NostrPubkey    string `json:"nostrPubkey"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("lud16 %q: parse pay response: %w", lud16, err)
	}
	if wire.Callback == "" {
		return nil, fmt.Errorf("lud16 %q: pay response has no callback", lud16)
	}

	return &PayResponse{
		Tag:            wire.Tag,
		Callback:       wire.Callback,
		MinSendable:    wire.MinSendable,
		MaxSendable:    wire.MaxSendable,
		CommentAllowed: wire.CommentAllowed,
		Metadata:       wire.Metadata,
		AllowsNostr:    wire.AllowsNostr,
		NostrPubkey:    wire.NostrPubkey,
		Chains:         ParsePayMetadataChains(wire.Metadata),
	}, nil
}

// ErrPayCallbackFailed is returned when an LNURL-pay callback does not
// return an invoice.
var ErrPayCallbackFailed = errors.New("lnurl: callback did not return an invoice")

// PayInvoiceParams are the query parameters for an LNURL-pay callback.
type PayInvoiceParams struct {
	AmountMsat int64  // "amount", in the chain's milli-units (msat or mloki)
	Nostr      string // "nostr": a signed zap request (NIP-57) or AltZap request (NIP-AZ), as JSON; optional
	Lnurl      string // "lnurl": the bech32 LNURL of the endpoint; optional
	Comment    string // "comment" (LUD-12); sent only when CommentAllowed > 0, truncated to it
}

// RequestPayInvoice calls pay's LNURL-pay callback (LUD-06 step 2) and
// returns the BOLT11 invoice. An {"status":"ERROR","reason":...} reply, a
// non-200 status, or an empty "pr" is reported as ErrPayCallbackFailed.
func RequestPayInvoice(ctx context.Context, client *http.Client, pay *PayResponse, p PayInvoiceParams) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pay.Callback, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Set("amount", fmt.Sprintf("%d", p.AmountMsat))
	if p.Nostr != "" {
		q.Set("nostr", p.Nostr)
	}
	if p.Lnurl != "" {
		q.Set("lnurl", p.Lnurl)
	}
	if p.Comment != "" && pay.CommentAllowed > 0 {
		comment := []rune(p.Comment)
		if int64(len(comment)) > pay.CommentAllowed {
			comment = comment[:pay.CommentAllowed]
		}
		q.Set("comment", string(comment))
	}
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}

	var wire struct {
		PR     string `json:"pr"`
		Status string `json:"status"`
		Reason string `json:"reason"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(body, &wire)
	if resp.StatusCode != http.StatusOK || wire.Status == "ERROR" || wire.PR == "" {
		reason := wire.Reason
		if reason == "" {
			reason = wire.Error
		}
		if reason == "" {
			reason = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("%w: %s", ErrPayCallbackFailed, reason)
	}
	return wire.PR, nil
}
