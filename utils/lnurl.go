package utils

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// ValidateLNURL decodes a bech32 LNURL string and validates the resulting URL.
func ValidateLNURL(lnurlStr string) error {
	// 1. Decode bech32
	prefix, bits5, err := bech32.DecodeNoLimit(lnurlStr)
	if err != nil {
		return fmt.Errorf("failed to decode bech32: %w", err)
	}

	if prefix != "lnurl" {
		return fmt.Errorf("invalid prefix: expected 'lnurl', got '%s'", prefix)
	}

	// 2. Convert 5-bit to 8-bit
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return fmt.Errorf("failed to convert bits: %w", err)
	}

	// 3. Parse as URL
	decodedUrl := string(data)
	u, err := url.ParseRequestURI(decodedUrl)
	if err != nil {
		return fmt.Errorf("decoded content is not a valid URL: %w", err)
	}

	// 4. Validate Scheme
	// LNURL must be HTTPS, or HTTP for .onion domains.
	if u.Scheme == "http" {
		if !strings.HasSuffix(u.Host, ".onion") {
			return fmt.Errorf("HTTP is only allowed for .onion domains")
		}
	} else if u.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme: expected https, got %s", u.Scheme)
	}

	return nil
}
