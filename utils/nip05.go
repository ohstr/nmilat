package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ResolveNip05 fetches a NIP-05 identifier's /.well-known/nostr.json and
// returns the pubkey it names, plus the relays the document lists for that
// pubkey (if any). "name@domain" looks up name; a bare "domain" or
// "_@domain" looks up the root name "_". Names match case-insensitively,
// since NIP-05 local parts are lowercase but users type them however.
func ResolveNip05(ctx context.Context, client *http.Client, nip05 string) (pubkey string, relays []string, err error) {
	name, domain := "_", nip05
	if at := strings.LastIndex(nip05, "@"); at >= 0 {
		name, domain = nip05[:at], nip05[at+1:]
	}
	if name == "" || domain == "" || strings.ContainsAny(domain, "/?#") {
		return "", nil, fmt.Errorf("nip05: invalid identifier %q", nip05)
	}

	endpoint := "https://" + domain + "/.well-known/nostr.json?name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("nip05 %q: unexpected status %d", nip05, resp.StatusCode)
	}

	var doc struct {
		Names  map[string]string   `json:"names"`
		Relays map[string][]string `json:"relays"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", nil, fmt.Errorf("nip05 %q: parse nostr.json: %w", nip05, err)
	}

	pubkey, ok := doc.Names[name]
	if !ok {
		for k, v := range doc.Names {
			if strings.EqualFold(k, name) {
				pubkey, ok = v, true
				break
			}
		}
	}
	if !ok {
		return "", nil, fmt.Errorf("nip05 %q: name not found", nip05)
	}
	pubkey = strings.ToLower(pubkey)
	if err := Validate32Key(pubkey); err != nil {
		return "", nil, fmt.Errorf("nip05 %q: invalid pubkey: %w", nip05, err)
	}
	return pubkey, doc.Relays[pubkey], nil
}
