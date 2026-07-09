package nipB0

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"

func signed(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func TestNewWebBookmarkAndParse(t *testing.T) {
	publishedAt := time.Unix(1700000000, 0)
	ev, err := NewWebBookmark(WebBookmarkParams{
		URL:         "https://example.com/articles/nostr",
		Title:       "A great article",
		Description: "Worth reading",
		Hashtags:    []string{"nostr", "bitcoin"},
		PublishedAt: &publishedAt,
	})
	if err != nil {
		t.Fatalf("NewWebBookmark() error = %v", err)
	}
	ev = signed(t, ev)

	wb, err := ParseWebBookmark(ev)
	if err != nil {
		t.Fatalf("ParseWebBookmark() error = %v", err)
	}
	if wb.DTag != "example.com/articles/nostr" {
		t.Errorf("DTag = %q", wb.DTag)
	}
	if wb.URL != "https://example.com/articles/nostr" {
		t.Errorf("URL = %q", wb.URL)
	}
	if wb.Title != "A great article" {
		t.Errorf("Title = %q", wb.Title)
	}
	if wb.Description != "Worth reading" {
		t.Errorf("Description = %q", wb.Description)
	}
	if len(wb.Hashtags) != 2 {
		t.Errorf("Hashtags = %v", wb.Hashtags)
	}
	if wb.PublishedAt == nil || !wb.PublishedAt.Equal(publishedAt) {
		t.Errorf("PublishedAt = %v, want %v", wb.PublishedAt, publishedAt)
	}

	if err := ValidateWebBookmark(ev); err != nil {
		t.Errorf("ValidateWebBookmark() error = %v", err)
	}
}

func TestNewWebBookmarkSchemeless(t *testing.T) {
	ev, err := NewWebBookmark(WebBookmarkParams{URL: "example.org/page"})
	if err != nil {
		t.Fatalf("NewWebBookmark() error = %v", err)
	}
	ev = signed(t, ev)

	wb, err := ParseWebBookmark(ev)
	if err != nil {
		t.Fatalf("ParseWebBookmark() error = %v", err)
	}
	if wb.DTag != "example.org/page" {
		t.Errorf("DTag = %q", wb.DTag)
	}
}

func TestNewWebBookmarkEmptyURL(t *testing.T) {
	if _, err := NewWebBookmark(WebBookmarkParams{}); err == nil {
		t.Error("expected error for empty url")
	}
}

func TestParseWebBookmarkErrors(t *testing.T) {
	tests := []struct {
		name string
		kind int
		tags [][]string
	}{
		{name: "wrong kind", kind: 1, tags: [][]string{{"d", "example.com"}}},
		{name: "missing d tag", kind: KindWebBookmark, tags: nil},
		{name: "empty d tag", kind: KindWebBookmark, tags: [][]string{{"d", ""}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			if _, err := ParseWebBookmark(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
