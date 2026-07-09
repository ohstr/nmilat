// Package nipB0 implements NIP-B0: Web Bookmarking, editable bookmarks of
// web pages published as kind 39701 parameterized-replaceable events.
package nipB0

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

const (
	KindWebBookmark = 39701
)

// Failure modes for ParseWebBookmark/ValidateWebBookmark, for callers that
// need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrWrongKind          = errors.New("nipB0: wrong kind")
	ErrMissingDTag        = errors.New("nipB0: missing or empty d tag")
	ErrInvalidPublishedAt = errors.New("nipB0: invalid published_at tag")
	ErrInvalidSignature   = errors.New("nipB0: invalid signature")
)

// WebBookmark is a parsed kind:39701 web bookmark event.
type WebBookmark struct {
	*nip01.Event
	// DTag is the raw "d" tag value: the bookmarked URL with its
	// "http://"/"https://" scheme stripped, per spec.
	DTag string
	// URL is DTag reconstructed with a scheme. The scheme itself isn't
	// preserved by the spec's "d" tag format, so "https://" is assumed
	// unless the original event was built with NewWebBookmark from an
	// "http://" URL (tracked via the "url" content is not part of spec;
	// callers that need the exact original scheme should keep it
	// out-of-band).
	URL         string
	Title       string
	Description string
	Hashtags    []string
	PublishedAt *time.Time
}

// stripScheme removes a leading "https://" or "http://" from u.
func stripScheme(u string) string {
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(u, scheme); ok {
			return rest
		}
	}
	return u
}

// ParseWebBookmark parses and structurally validates a kind:39701 event.
func ParseWebBookmark(event *nip01.Event) (*WebBookmark, error) {
	if event.Kind != KindWebBookmark {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongKind, event.Kind, KindWebBookmark)
	}

	dTag, err := utils.FindUniqueEventTagValue(event.Tags, "d")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingDTag, err)
	}
	if dTag == "" {
		return nil, ErrMissingDTag
	}

	wb := &WebBookmark{
		Event:       event,
		DTag:        dTag,
		URL:         "https://" + dTag,
		Description: event.Content,
	}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "title":
			wb.Title = tag[1]
		case "t":
			wb.Hashtags = append(wb.Hashtags, tag[1])
		case "published_at":
			sec, err := strconv.ParseInt(tag[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %q: %w", ErrInvalidPublishedAt, tag[1], err)
			}
			t := time.Unix(sec, 0)
			wb.PublishedAt = &t
		}
	}

	return wb, nil
}

// ValidateWebBookmark checks the signature and structure of a bookmark event.
func ValidateWebBookmark(event *nip01.Event) error {
	if err := event.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	_, err := ParseWebBookmark(event)
	return err
}

// WebBookmarkParams describes a NIP-B0 web bookmark. Pubkey and URL are
// required; Title, Description, Hashtags, and PublishedAt are optional.
type WebBookmarkParams struct {
	Pubkey string
	// URL is the bookmarked page, with or without a scheme.
	URL         string
	Title       string
	Description string
	Hashtags    []string
	PublishedAt *time.Time
}

// NewWebBookmark builds an unsigned kind:39701 bookmark event. Caller must
// sign it.
func NewWebBookmark(p WebBookmarkParams) (*nip01.Event, error) {
	dTag := stripScheme(p.URL)
	if dTag == "" {
		return nil, fmt.Errorf("bookmark url must not be empty")
	}

	tags := [][]string{{"d", dTag}}
	if p.Title != "" {
		tags = append(tags, []string{"title", p.Title})
	}
	if p.PublishedAt != nil {
		tags = append(tags, []string{"published_at", strconv.FormatInt(p.PublishedAt.Unix(), 10)})
	}
	for _, h := range p.Hashtags {
		tags = append(tags, []string{"t", h})
	}

	return nip01.NewUnsignedEvent(KindWebBookmark, p.Pubkey, p.Description, tags...), nil
}
