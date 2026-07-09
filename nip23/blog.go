// Package nip23 implements NIP-23: Long-form Content, articles published as
// kind:30023 parameterized-replaceable events (Markdown content plus
// title/summary/image metadata).
package nip23

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const KindLongFormContent = 30023

// Article is a parsed kind:30023 long-form content event.
type Article struct {
	*nip01.Event
	// Identifier is the "d" tag: a stable identifier the author reuses
	// across edits so a new version replaces this article rather than
	// publishing a new one (NIP-23 is a parameterized-replaceable kind).
	Identifier string
	Title      string
	Summary    string
	Image      string
	Published  uint64
	Tags       []string
}

// ArticleParams describes a NIP-23 long-form article. Identifier, Title,
// and Content are required; Summary, Image, and Tags are optional.
type ArticleParams struct {
	// Identifier is the article's stable "d" tag — reuse the same value
	// across edits to replace the article instead of publishing a new one.
	Identifier string
	Title      string
	Summary    string
	Image      string
	Content    string
	Tags       []string
}

// NewArticle builds an unsigned kind:30023 article event. Caller must sign
// it.
func NewArticle(p ArticleParams) *nip01.Event {
	ev := nip01.NewEvent(KindLongFormContent, p.Content,
		[]string{"d", p.Identifier},
		[]string{"title", p.Title},
		[]string{"summary", p.Summary},
		[]string{"image", p.Image},
		[]string{"published_at", strconv.FormatInt(time.Now().Unix(), 10)},
	)
	for _, t := range p.Tags {
		ev.AddTag([]string{"t", t})
	}
	return ev
}

// ParseArticle parses and structurally validates a kind:30023 event.
func ParseArticle(event *nip01.Event) (*Article, error) {
	if event.Kind != KindLongFormContent {
		return nil, fmt.Errorf("invalid kind %d", event.Kind)
	}

	a := &Article{Event: event}
	a.Published = event.CreatedAt // Default

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "d":
			a.Identifier = tag[1]
		case "title":
			a.Title = tag[1]
		case "summary":
			a.Summary = tag[1]
		case "image":
			a.Image = tag[1]
		case "published_at":
			if ts, err := strconv.ParseUint(tag[1], 10, 64); err == nil {
				a.Published = ts
			}
		case "t":
			a.Tags = append(a.Tags, tag[1])
		}
	}
	return a, nil
}
