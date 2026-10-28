package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RelayPowMinimum fetches a relay's NIP-11 document (ws → http, wss → https,
// Accept: application/nostr+json) and returns limitation.min_pow_difficulty, 0
// when absent.
func RelayPowMinimum(ctx context.Context, relayURL string) (int, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return 0, fmt.Errorf("transport: relay url: %w", err)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	case "http", "https":
	default:
		return 0, fmt.Errorf("transport: relay url %q is not ws or wss", relayURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("transport: NIP-11 fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("transport: NIP-11 fetch: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var doc struct {
		Limitation struct {
			MinPowDifficulty int `json:"min_pow_difficulty"`
		} `json:"limitation"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0, fmt.Errorf("transport: NIP-11 document: %w", err)
	}
	return max(doc.Limitation.MinPowDifficulty, 0), nil
}
