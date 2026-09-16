package nip34

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/nip19"
)

// ErrInvalidCloneURL is returned by ParseCloneURL for a malformed
// "nostr://" clone URL.
var ErrInvalidCloneURL = errors.New("nip34: invalid nostr:// clone url")

const cloneURLScheme = "nostr://"

// CloneURL is a parsed "nostr://" repository clone URL (see NIP-34's
// "Nostr Clone URL format"), understood by a git-remote-nostr helper.
type CloneURL struct {
	// NAddr holds the raw naddr when the URL used the "nostr://<naddr>"
	// form. Empty for the "nostr://<npub|nip05>/..." forms, which
	// identify the repository by owner + identifier instead.
	NAddr string
	// Owner is the npub or NIP-05 identifier from the
	// "nostr://<npub|nip05>/..." forms. Empty when NAddr is set.
	Owner string
	// RelayHint is the optional relay URL segment. Its "wss://" scheme,
	// if the URL omitted it for brevity, is not restored here.
	RelayHint string
	// Identifier is the repository announcement's "d" tag value. Empty
	// when NAddr is set (the naddr already embeds it).
	Identifier string
}

// ParseCloneURL parses a "nostr://" clone URL into its components.
func ParseCloneURL(raw string) (*CloneURL, error) {
	if !strings.HasPrefix(raw, cloneURLScheme) {
		return nil, fmt.Errorf("%w: %q: missing %q scheme", ErrInvalidCloneURL, raw, cloneURLScheme)
	}

	rest := strings.TrimPrefix(raw, cloneURLScheme)
	parts := strings.Split(rest, "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: bad percent-encoding in segment %q: %w", ErrInvalidCloneURL, raw, part, err)
		}
		parts[i] = decoded
	}

	switch len(parts) {
	case 1:
		return &CloneURL{NAddr: parts[0]}, nil
	case 2:
		return &CloneURL{Owner: parts[0], Identifier: parts[1]}, nil
	case 3:
		return &CloneURL{Owner: parts[0], RelayHint: parts[1], Identifier: parts[2]}, nil
	default:
		return nil, fmt.Errorf("%w: %q: expected 1-3 path segments, got %d", ErrInvalidCloneURL, raw, len(parts))
	}
}

// ResolveAddr decodes c.NAddr (set when the URL used the
// "nostr://<naddr>" form) into its nip19.EntityPointer. Returns an error
// if this CloneURL instead used one of the "nostr://<npub|nip05>/..."
// forms (NAddr is empty).
func (c *CloneURL) ResolveAddr() (*nip19.EntityPointer, error) {
	if c.NAddr == "" {
		return nil, fmt.Errorf("%w: not an naddr-form clone url", ErrInvalidCloneURL)
	}
	return nip19.DecodeAddr(c.NAddr)
}

// BuildCloneURLFromAddr builds the "nostr://<naddr>" clone URL form from
// an already-encoded naddr string (see nip19.EncodeAddr).
func BuildCloneURLFromAddr(naddr string) string {
	return cloneURLScheme + naddr
}

// BuildCloneURL builds the "nostr://<owner>/[<relay-hint>/]<identifier>"
// clone URL form, percent-encoding relayHint and identifier per the spec.
// owner is an npub or NIP-05 identifier, used as-is; relayHint may be
// empty.
func BuildCloneURL(owner, relayHint, identifier string) string {
	if relayHint == "" {
		return fmt.Sprintf("%s%s/%s", cloneURLScheme, owner, url.PathEscape(identifier))
	}
	return fmt.Sprintf("%s%s/%s/%s", cloneURLScheme, owner, url.PathEscape(relayHint), url.PathEscape(identifier))
}
