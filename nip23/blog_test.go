package nip23

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func TestNewArticle(t *testing.T) {
	ev := NewArticle(ArticleParams{
		Identifier: "my-slug",
		Title:      "My Article",
		Summary:    "A short summary",
		Image:      "https://example.com/image.png",
		Content:    "# hello",
		Tags:       []string{"nostr", "golang"},
	})

	if ev.Kind != KindLongFormContent {
		t.Errorf("expected kind %d, got %d", KindLongFormContent, ev.Kind)
	}
	if ev.Content != "# hello" {
		t.Errorf("expected content %q, got %q", "# hello", ev.Content)
	}

	a, err := ParseArticle(ev)
	if err != nil {
		t.Fatalf("ParseArticle(NewArticle(...)) failed: %v", err)
	}
	if a.Identifier != "my-slug" {
		t.Errorf("expected identifier %q, got %q", "my-slug", a.Identifier)
	}
	if a.Title != "My Article" || a.Summary != "A short summary" || a.Image != "https://example.com/image.png" {
		t.Errorf("unexpected parsed article: %+v", a)
	}
	if len(a.Tags) != 2 || a.Tags[0] != "nostr" || a.Tags[1] != "golang" {
		t.Errorf("expected tags [nostr golang], got %v", a.Tags)
	}
}

func TestParseArticle(t *testing.T) {
	event := &nip01.Event{
		Kind:      KindLongFormContent,
		CreatedAt: 1000,
		Tags: [][]string{
			{"title", "My Article"},
			{"summary", "A short summary"},
			{"image", "https://example.com/image.png"},
			{"published_at", "2000"},
			{"t", "nostr"},
			{"t", "golang"},
		},
	}

	a, err := ParseArticle(event)
	if err != nil {
		t.Fatalf("ParseArticle failed: %v", err)
	}

	if a.Title != "My Article" {
		t.Errorf("expected title %q, got %q", "My Article", a.Title)
	}
	if a.Summary != "A short summary" {
		t.Errorf("expected summary %q, got %q", "A short summary", a.Summary)
	}
	if a.Image != "https://example.com/image.png" {
		t.Errorf("expected image %q, got %q", "https://example.com/image.png", a.Image)
	}
	if a.Published != 2000 {
		t.Errorf("expected published_at tag to override CreatedAt: want=2000 got=%d", a.Published)
	}
	if len(a.Tags) != 2 || a.Tags[0] != "nostr" || a.Tags[1] != "golang" {
		t.Errorf("expected tags [nostr golang], got %v", a.Tags)
	}
}

func TestParseArticle_DefaultsPublishedToCreatedAt(t *testing.T) {
	event := &nip01.Event{
		Kind:      KindLongFormContent,
		CreatedAt: 1234,
	}

	a, err := ParseArticle(event)
	if err != nil {
		t.Fatalf("ParseArticle failed: %v", err)
	}

	if a.Published != 1234 {
		t.Errorf("expected Published to default to CreatedAt=1234, got %d", a.Published)
	}
}

func TestParseArticle_InvalidPublishedAtIgnored(t *testing.T) {
	event := &nip01.Event{
		Kind:      KindLongFormContent,
		CreatedAt: 1234,
		Tags: [][]string{
			{"published_at", "not-a-number"},
		},
	}

	a, err := ParseArticle(event)
	if err != nil {
		t.Fatalf("ParseArticle failed: %v", err)
	}

	if a.Published != 1234 {
		t.Errorf("expected malformed published_at to be ignored, falling back to CreatedAt=1234, got %d", a.Published)
	}
}

func TestParseArticle_WrongKind(t *testing.T) {
	event := &nip01.Event{Kind: 1}

	if _, err := ParseArticle(event); err == nil {
		t.Fatal("expected error for wrong kind, got nil")
	}
}
