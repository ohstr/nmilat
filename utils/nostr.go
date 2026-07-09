package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetNip05URL returns the URL to fetch the NIP-05 JSON for a given identifier.
func GetNip05URL(nip05 string) string {
	parts := strings.Split(nip05, "@")
	if len(parts) != 2 {
		return ""
	}
	name := parts[0]
	domain := parts[1]
	return fmt.Sprintf("https://%s/.well-known/nostr.json?name=%s", domain, name)
}

// GetLud16URL returns the URL to fetch the LNURL-pay JSON for a given LUD-16 identifier.
func GetLud16URL(lud16 string) string {
	parts := strings.Split(lud16, "@")
	if len(parts) != 2 {
		return ""
	}
	name := parts[0]
	domain := parts[1]
	return fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, name)
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
func VerifyNip05(r io.Reader, pubkey, nip05 string) bool {
	parts := strings.Split(nip05, "@")
	if len(parts) != 2 {
		return false
	}
	name := parts[0]

	var res struct {
		Names map[string]string `json:"names"`
	}
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return false
	}

	if pk, ok := res.Names[name]; ok {
		return strings.EqualFold(pk, pubkey)
	}
	return false
}

// UnmarshalJSON inlines a simple JSON unmarshaler and handles errors.
func UnmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// IsValidPictureURL performs a basic check to see if a string looks like a valid HTTP or HTTPS URL.
func IsValidPictureURL(u string) bool {
	if u == "" {
		return false
	}
	// Basic prefix check instead of full url.Parse to avoid importing net/url just for this if possible
	// Or we can just import net/url
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}
