package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PayResponse is a LUD-06 payRequest document (a LUD-16 identifier's
// well-known endpoint), plus NIP-57's allowsNostr/nostrPubkey fields and the
// Zap Protocol's chain/* metadata entries already parsed out.
type PayResponse struct {
	Callback    string
	MinSendable int64
	MaxSendable int64
	AllowsNostr bool
	NostrPubkey string
	Chains      []string // never empty; see ParsePayMetadataChains
}

// ParsePayMetadataChains extracts the Lightning-routable chains a LUD-06
// payRequest's "metadata" field advertises (the Zap Protocol's "chain/<name>"
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
		Callback    string `json:"callback"`
		MinSendable int64  `json:"minSendable"`
		MaxSendable int64  `json:"maxSendable"`
		Metadata    string `json:"metadata"`
		AllowsNostr bool   `json:"allowsNostr"`
		NostrPubkey string `json:"nostrPubkey"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("lud16 %q: parse pay response: %w", lud16, err)
	}
	if wire.Callback == "" {
		return nil, fmt.Errorf("lud16 %q: pay response has no callback", lud16)
	}

	return &PayResponse{
		Callback:    wire.Callback,
		MinSendable: wire.MinSendable,
		MaxSendable: wire.MaxSendable,
		AllowsNostr: wire.AllowsNostr,
		NostrPubkey: wire.NostrPubkey,
		Chains:      ParsePayMetadataChains(wire.Metadata),
	}, nil
}
