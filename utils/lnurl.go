package utils

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// ValidateLNURL decodes a bech32 LNURL string and validates the resulting URL.
func ValidateLNURL(lnurlStr string) error {
	_, err := DecodeLNURL(lnurlStr)
	return err
}

// DecodeLNURL returns the URL a bech32 "lnurl1..." string encodes. It must
// be HTTPS, or HTTP for an .onion host.
func DecodeLNURL(lnurlStr string) (string, error) {
	prefix, bits5, err := bech32.DecodeNoLimit(strings.ToLower(strings.TrimSpace(lnurlStr)))
	if err != nil {
		return "", fmt.Errorf("failed to decode bech32: %w", err)
	}
	if prefix != "lnurl" {
		return "", fmt.Errorf("invalid prefix: expected 'lnurl', got '%s'", prefix)
	}

	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}

	decoded := string(data)
	u, err := url.ParseRequestURI(decoded)
	if err != nil {
		return "", fmt.Errorf("decoded content is not a valid URL: %w", err)
	}
	if u.Scheme == "http" {
		if !strings.HasSuffix(u.Host, ".onion") {
			return "", fmt.Errorf("HTTP is only allowed for .onion domains")
		}
	} else if u.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme: expected https, got %s", u.Scheme)
	}
	return decoded, nil
}

// EncodeLNURL bech32-encodes rawURL as an "lnurl1..." string — the inverse
// of ValidateLNURL's decode step.
func EncodeLNURL(rawURL string) (string, error) {
	bits5, err := bech32.ConvertBits([]byte(rawURL), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	encoded, err := bech32.Encode("lnurl", bits5)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}
	return encoded, nil
}
