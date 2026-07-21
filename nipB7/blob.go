package nipB7

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
)

// Failure modes for BlobDescriptor.Validate, for callers that need to
// distinguish them (e.g. via errors.Is) rather than match on message text.
var (
	ErrMissingURL      = errors.New("nipB7: blob descriptor missing url")
	ErrInvalidSize     = errors.New("nipB7: blob descriptor size must be positive")
	ErrInvalidUploaded = errors.New("nipB7: blob descriptor uploaded timestamp must be positive")
)

// BlobDescriptor is the JSON object a Blossom server returns from
// PUT /upload, PUT /mirror, PUT /media, and GET /list/<pubkey> (BUD-02,
// BUD-05, BUD-12).
type BlobDescriptor struct {
	URL      string     `json:"url"`
	Sha256   string     `json:"sha256"`
	Size     int64      `json:"size"`
	Type     string     `json:"type,omitempty"`
	Uploaded int64      `json:"uploaded"`
	NIP94    [][]string `json:"nip94,omitempty"`
}

// Validate checks that d's required fields (BUD-02: url, sha256, size,
// uploaded) are structurally sound. It does not check that URL is actually
// reachable or that Sha256 matches the blob's real content — those require
// network access or the blob bytes, which this pure type doesn't have.
func (d *BlobDescriptor) Validate() error {
	if d.URL == "" {
		return ErrMissingURL
	}
	if !IsSHA256Hex(d.Sha256) {
		return fmt.Errorf("%w: %q", ErrInvalidHash, d.Sha256)
	}
	if d.Size <= 0 {
		return ErrInvalidSize
	}
	if d.Uploaded <= 0 {
		return ErrInvalidUploaded
	}
	return nil
}

// SortDescending sorts descriptors by Uploaded, newest first, per BUD-12's
// requirement that GET /list/<pubkey> results be "sorted by the uploaded
// date in descending order."
func SortDescending(descriptors []BlobDescriptor) {
	sort.SliceStable(descriptors, func(i, j int) bool {
		return descriptors[i].Uploaded > descriptors[j].Uploaded
	})
}

// ListQuery holds the optional GET /list/<pubkey> query parameters (BUD-12).
// Since/Until are marked deprecated by the spec but still accepted by many
// servers; prefer Cursor/Limit for new code.
type ListQuery struct {
	Cursor string
	Limit  int
	Since  int64
	Until  int64
}

// Encode renders q as URL query parameters.
func (q ListQuery) Encode() url.Values {
	values := url.Values{}
	if q.Cursor != "" {
		values.Set("cursor", q.Cursor)
	}
	if q.Limit > 0 {
		values.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.Since > 0 {
		values.Set("since", strconv.FormatInt(q.Since, 10))
	}
	if q.Until > 0 {
		values.Set("until", strconv.FormatInt(q.Until, 10))
	}
	return values
}
