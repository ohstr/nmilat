package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GetNip05URL returns the URL to fetch the NIP-05 JSON for a given identifier.
func GetNip05URL(nip05 string) string {
	name, domain, ok := splitIdentifier(nip05)
	if !ok {
		return ""
	}
	return fmt.Sprintf("https://%s/.well-known/nostr.json?name=%s", domain, url.QueryEscape(name))
}

// GetLud16URL returns the URL to fetch the LNURL-pay JSON for a given LUD-16 identifier.
func GetLud16URL(lud16 string) string {
	name, domain, ok := splitIdentifier(lud16)
	if !ok {
		return ""
	}
	return fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, url.PathEscape(name))
}

// GetDomainOnly extracts the domain from a NIP-05 or LUD-16 identifier.
func GetDomainOnly(id string) string {
	parts := strings.Split(id, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// GetFullHTTPURL recreates the absolute URL string from an incoming HTTP request
// to strictly validate exactly what the client signed for NIP-98 matching.
func GetFullHTTPURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// VerifyNip05 parses the NIP-05 response and checks if the given pubkey matches the name.
// Names are matched case-insensitively.
func VerifyNip05(r io.Reader, pubkey, nip05 string) bool {
	name, _, ok := splitIdentifier(nip05)
	if !ok {
		return false
	}

	var res struct {
		Names map[string]string `json:"names"`
	}
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return false
	}

	if pk, ok := res.Names[name]; ok {
		return strings.EqualFold(pk, pubkey)
	}
	for n, pk := range res.Names {
		if strings.EqualFold(n, name) {
			return strings.EqualFold(pk, pubkey)
		}
	}
	return false
}

// UnmarshalJSON inlines a simple JSON unmarshaler and handles errors.
func UnmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// IsValidPictureURL performs a basic check to see if a string looks like a valid HTTP or HTTPS URL.
func IsValidPictureURL(u string) bool {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil {
		return false
	}
	return (p.Scheme == "http" || p.Scheme == "https") && p.Host != ""
}
