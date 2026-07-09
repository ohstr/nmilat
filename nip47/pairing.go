package nip47

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/utils"
)

// PairingURIScheme is the URI scheme used by NIP-47 connection strings.
const PairingURIScheme = "nostr+walletconnect"

// BuildPairingURI builds a nostr+walletconnect:// connection URI of the
// form "nostr+walletconnect://{pubkey}?relay={url}&relay={url2}&secret={hex}...",
// with one repeated "relay" param per entry in relayURLs. extra carries
// additional optional query parameters (e.g. "lud16"); pass nil if none are
// needed.
func BuildPairingURI(walletPubkey string, relayURLs []string, secret string, extra url.Values) string {
	q := url.Values{}
	for _, r := range relayURLs {
		q.Add("relay", r)
	}
	q.Set("secret", secret)
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return fmt.Sprintf("%s://%s?%s", PairingURIScheme, walletPubkey, q.Encode())
}

// PairingInfo is a parsed nostr+walletconnect:// connection URI.
type PairingInfo struct {
	WalletPubkey string
	RelayURLs    []string
	Secret       string
	Extra        url.Values
}

// ParsePairingURI parses a nostr+walletconnect:// connection URI.
func ParsePairingURI(uri string) (*PairingInfo, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid pairing uri: %w", err)
	}
	if u.Scheme != PairingURIScheme {
		return nil, fmt.Errorf("invalid pairing uri scheme %q, expected %q", u.Scheme, PairingURIScheme)
	}

	pubkey := u.Host
	if pubkey == "" {
		pubkey = strings.TrimPrefix(u.Opaque, "//")
	}
	if err := utils.Validate32Key(pubkey); err != nil {
		return nil, fmt.Errorf("invalid wallet pubkey in pairing uri: %w", err)
	}

	q := u.Query()
	relays := q["relay"]
	if len(relays) == 0 {
		return nil, fmt.Errorf("pairing uri missing relay parameter")
	}
	secret := q.Get("secret")
	if secret == "" {
		return nil, fmt.Errorf("pairing uri missing secret parameter")
	}
	q.Del("relay")
	q.Del("secret")

	return &PairingInfo{
		WalletPubkey: pubkey,
		RelayURLs:    relays,
		Secret:       secret,
		Extra:        q,
	}, nil
}
