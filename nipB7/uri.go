package nipB7

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URIScheme is the prefix of a BUD-10 Blossom URI: "blossom:<sha256>.<ext>".
const URIScheme = "blossom:"

// defaultURIExt is the extension a BUD-10 URI falls back to when the
// original file's extension is unknown, per spec.
const defaultURIExt = "bin"

// Failure modes for ParseURI, for callers that need to distinguish them
// (e.g. via errors.Is) rather than match on message text.
var (
	ErrInvalidURIScheme = errors.New("nipB7: uri missing blossom: scheme")
	ErrInvalidURIHash   = errors.New("nipB7: uri hash is not a valid sha256 hex string")
	ErrInvalidURISize   = errors.New("nipB7: uri sz parameter is not a valid size")
)

// URI is a parsed BUD-10 "blossom:<sha256>.<ext>?as=...&xs=...&sz=..." URI:
// a hash-addressed pointer to a blob plus optional discovery hints for
// resolving it (author pubkeys, server hints, expected size).
type URI struct {
	Hash    string
	Ext     string
	Authors []string // "as" — pubkeys that may have uploaded this blob
	Servers []string // "xs" — servers that may host this blob
	Size    int64    // "sz" — expected size in bytes, 0 if unset
}

// ParseURI parses a BUD-10 Blossom URI.
func ParseURI(raw string) (*URI, error) {
	if !strings.HasPrefix(raw, URIScheme) {
		return nil, ErrInvalidURIScheme
	}
	rest := raw[len(URIScheme):]

	path, query, _ := strings.Cut(rest, "?")

	hash := path
	ext := defaultURIExt
	if i := strings.LastIndex(path, "."); i >= 0 {
		hash, ext = path[:i], path[i+1:]
	}
	if !IsSHA256Hex(hash) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidURIHash, hash)
	}

	u := &URI{Hash: hash, Ext: ext}
	if query == "" {
		return u, nil
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidURIScheme, err)
	}
	u.Authors = values["as"]
	u.Servers = values["xs"]
	if sz := values.Get("sz"); sz != "" {
		n, err := strconv.ParseInt(sz, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: %q", ErrInvalidURISize, sz)
		}
		u.Size = n
	}
	return u, nil
}

// String renders u back into its "blossom:<sha256>.<ext>?..." form.
func (u URI) String() string {
	ext := u.Ext
	if ext == "" {
		ext = defaultURIExt
	}

	var b strings.Builder
	b.WriteString(URIScheme)
	b.WriteString(u.Hash)
	b.WriteByte('.')
	b.WriteString(ext)

	values := url.Values{}
	for _, a := range u.Authors {
		values.Add("as", a)
	}
	for _, s := range u.Servers {
		values.Add("xs", s)
	}
	if u.Size > 0 {
		values.Set("sz", strconv.FormatInt(u.Size, 10))
	}
	if len(values) > 0 {
		b.WriteByte('?')
		b.WriteString(values.Encode())
	}
	return b.String()
}
