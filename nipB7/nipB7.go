// Package nipB7 implements NIP-B7: Blossom media, letting clients discover
// a user's preferred Blossom (BUD-01/BUD-03) file servers via a kind:10063
// event, and locate a file by its SHA-256 hash across those servers when
// its original URL becomes unavailable.
package nipB7

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ohstr/nmilat/nip01"
)

const (
	KindBlossomServerList = 10063
)

// Failure modes for ParseBlossomServerList/ValidateBlossomServerList/
// NewBlossomServerList, for callers that need to distinguish them (e.g.
// via errors.Is) rather than match on message text.
var (
	ErrWrongKind           = errors.New("nipB7: wrong kind")
	ErrInvalidServerURL    = errors.New("nipB7: invalid server url")
	ErrInvalidServerScheme = errors.New("nipB7: server url must use http or https scheme")
	ErrEmptyServerList     = errors.New("nipB7: server list must have at least one server")
	ErrInvalidSignature    = errors.New("nipB7: invalid signature")
	ErrInvalidHash         = errors.New("nipB7: invalid sha256 hash")
)

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BlossomServerList is a parsed kind:10063 server-list event.
type BlossomServerList struct {
	*nip01.Event
	Servers []string
}

// ParseBlossomServerList parses and structurally validates a kind:10063 event.
func ParseBlossomServerList(event *nip01.Event) (*BlossomServerList, error) {
	if event.Kind != KindBlossomServerList {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindBlossomServerList)
	}

	sl := &BlossomServerList{Event: event}
	for _, tag := range event.Tags {
		if len(tag) < 2 || tag[0] != "server" {
			continue
		}
		u, err := url.ParseRequestURI(tag[1])
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidServerURL, tag[1], err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return nil, fmt.Errorf("%w: %q has scheme %q", ErrInvalidServerScheme, tag[1], u.Scheme)
		}
		sl.Servers = append(sl.Servers, tag[1])
	}

	return sl, nil
}

// ValidateBlossomServerList checks the signature and structure of a server-list event.
func ValidateBlossomServerList(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseBlossomServerList(event)
	return err
}

// NewBlossomServerList builds an unsigned kind:10063 server-list event.
// Caller must sign it.
func NewBlossomServerList(pubkey string, servers []string) (*nip01.Event, error) {
	if len(servers) == 0 {
		return nil, ErrEmptyServerList
	}

	var tags [][]string
	for _, s := range servers {
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidServerURL, s, err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return nil, fmt.Errorf("%w: %q has scheme %q", ErrInvalidServerScheme, s, u.Scheme)
		}
		tags = append(tags, []string{"server", s})
	}

	return nip01.NewUnsignedEvent(KindBlossomServerList, pubkey, "", tags...), nil
}

// IsSHA256Hex reports whether s is a 64-character lowercase hex string, the
// shape of a Blossom file hash.
func IsSHA256Hex(s string) bool {
	return sha256HexRE.MatchString(s)
}

// ExtractHashFromURL extracts a Blossom SHA-256 hash and optional file
// extension from a URL whose last path segment ends in a 64-character hex
// string (e.g. ".../<hash>.png"), per NIP-B7's file recovery process. ok is
// false if the URL's last path segment isn't hash-shaped.
func ExtractHashFromURL(rawURL string) (hash, ext string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}

	segments := strings.Split(u.Path, "/")
	last := segments[len(segments)-1]

	name := last
	if i := strings.LastIndex(last, "."); i >= 0 {
		name = last[:i]
		ext = last[i+1:]
	}

	if !IsSHA256Hex(name) {
		return "", "", false
	}
	return name, ext, true
}

// BuildServerURL builds the URL for fetching hash from server, per
// NIP-B7's "https://[server]/[hex-string].[extension]" format. ext may be
// empty.
func BuildServerURL(server, hash, ext string) (string, error) {
	if !IsSHA256Hex(hash) {
		return "", fmt.Errorf("%w: %q", ErrInvalidHash, hash)
	}
	base := strings.TrimRight(server, "/")
	if ext == "" {
		return fmt.Sprintf("%s/%s", base, hash), nil
	}
	return fmt.Sprintf("%s/%s.%s", base, hash, ext), nil
}
