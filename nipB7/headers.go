package nipB7

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// HTTP header names Blossom servers and clients exchange outside the
// signed-event Authorization token: pre-flight blob identification
// (BUD-06/BUD-05) and human-readable error diagnostics (BUD-01).
const (
	HeaderSHA256        = "X-SHA-256"
	HeaderContentLength = "X-Content-Length"
	HeaderContentType   = "X-Content-Type"
	HeaderReason        = "X-Reason"
)

// ErrInvalidContentLength is returned by ParseUploadRequirements when the
// X-Content-Length header isn't a non-negative integer.
var ErrInvalidContentLength = errors.New("nipB7: X-Content-Length is not a valid non-negative integer")

// UploadRequirements is the blob-identifying information a client sends via
// headers to HEAD /upload or HEAD /media for pre-flight validation
// (BUD-06), before committing to the actual PUT.
type UploadRequirements struct {
	SHA256        string
	ContentLength int64
	ContentType   string
}

// ParseUploadRequirements reads a HEAD /upload or HEAD /media request's
// pre-flight headers. SHA256 and ContentType are optional per spec, so an
// empty header value is left as "" rather than treated as an error; only a
// present-but-malformed value is rejected.
func ParseUploadRequirements(h http.Header) (UploadRequirements, error) {
	var req UploadRequirements

	if sha := h.Get(HeaderSHA256); sha != "" {
		if !IsSHA256Hex(sha) {
			return UploadRequirements{}, fmt.Errorf("%w: %q", ErrInvalidHash, sha)
		}
		req.SHA256 = sha
	}

	if v := h.Get(HeaderContentLength); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return UploadRequirements{}, fmt.Errorf("%w: %q", ErrInvalidContentLength, v)
		}
		req.ContentLength = n
	}

	req.ContentType = h.Get(HeaderContentType)
	return req, nil
}

// SetHeaders writes u's fields onto h as the X-SHA-256/X-Content-Length/
// X-Content-Type pre-flight headers, omitting any field left at its zero
// value.
func (u UploadRequirements) SetHeaders(h http.Header) {
	if u.SHA256 != "" {
		h.Set(HeaderSHA256, u.SHA256)
	}
	if u.ContentLength > 0 {
		h.Set(HeaderContentLength, strconv.FormatInt(u.ContentLength, 10))
	}
	if u.ContentType != "" {
		h.Set(HeaderContentType, u.ContentType)
	}
}

// WriteError writes a Blossom-style HTTP error response: the status code
// plus, if reason is non-empty, an X-Reason header. Per BUD-01, X-Reason is
// "a human readable diagnostic message only" — callers on the receiving end
// must not parse it for control flow.
func WriteError(w http.ResponseWriter, status int, reason string) {
	if reason != "" {
		w.Header().Set(HeaderReason, reason)
	}
	w.WriteHeader(status)
}

// ReasonFromResponse extracts the human-readable X-Reason header from an
// HTTP response's headers, if present.
func ReasonFromResponse(h http.Header) string {
	return h.Get(HeaderReason)
}
