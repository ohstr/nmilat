package nip22

import (
	"errors"
	"strings"
	"testing"

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

var (
	rootPubkey   = strings.Repeat("a", 64)
	parentPubkey = strings.Repeat("b", 64)
	rootEventID  = strings.Repeat("c", 64)
)

func TestNewCommentAndParse_TopLevelOnAddress(t *testing.T) {
	addr := "30023:" + rootPubkey + ":f9347ca7"

	ev, err := NewComment(CommentParams{
		Content: "Great blog post!",
		Root: ScopeParams{
			Pointer:      PointerParams{Type: PointerAddress, Value: addr, RelayHint: "wss://example.relay"},
			Kind:         "30023",
			AuthorPubkey: rootPubkey,
		},
		Parent: ScopeParams{
			Pointer: PointerParams{Type: PointerAddress, Value: addr, RelayHint: "wss://example.relay"},
			Kind:    "30023",
		},
	})
	if err != nil {
		t.Fatalf("NewComment() error = %v", err)
	}
	ev = signed(t, ev)

	c, err := ParseComment(ev)
	if err != nil {
		t.Fatalf("ParseComment() error = %v", err)
	}
	if c.Root.Pointer.Type != PointerAddress || c.Root.Pointer.Value != addr {
		t.Errorf("Root.Pointer = %+v", c.Root.Pointer)
	}
	if c.Root.Kind != "30023" {
		t.Errorf("Root.Kind = %q", c.Root.Kind)
	}
	if c.Root.AuthorPubkey != rootPubkey {
		t.Errorf("Root.AuthorPubkey = %q", c.Root.AuthorPubkey)
	}
	if c.Parent.Pointer.Value != addr {
		t.Errorf("Parent.Pointer.Value = %q", c.Parent.Pointer.Value)
	}

	if err := ValidateComment(ev); err != nil {
		t.Errorf("ValidateComment() error = %v", err)
	}
}

func TestNewCommentAndParse_ReplyOnEvent(t *testing.T) {
	ev, err := NewComment(CommentParams{
		Content: "This is a reply",
		Root: ScopeParams{
			Pointer: PointerParams{Type: PointerEvent, Value: rootEventID, AuthorPubkey: rootPubkey},
			Kind:    "1063",
		},
		Parent: ScopeParams{
			Pointer: PointerParams{Type: PointerEvent, Value: rootEventID, AuthorPubkey: parentPubkey},
			Kind:    "1111",
		},
	})
	if err != nil {
		t.Fatalf("NewComment() error = %v", err)
	}
	ev = signed(t, ev)

	c, err := ParseComment(ev)
	if err != nil {
		t.Fatalf("ParseComment() error = %v", err)
	}
	if c.Root.Pointer.Type != PointerEvent || c.Root.Pointer.AuthorPubkey != rootPubkey {
		t.Errorf("Root.Pointer = %+v", c.Root.Pointer)
	}
	if c.Parent.Kind != "1111" || c.Parent.Pointer.AuthorPubkey != parentPubkey {
		t.Errorf("Parent = %+v", c.Parent)
	}
}

func TestNewCommentAndParse_ExternalIdentifier(t *testing.T) {
	ev, err := NewComment(CommentParams{
		Content: "Nice article!",
		Root: ScopeParams{
			Pointer: PointerParams{Type: PointerExternal, Value: "https://abc.com/articles/1"},
			Kind:    "web",
		},
		Parent: ScopeParams{
			Pointer: PointerParams{Type: PointerExternal, Value: "https://abc.com/articles/1"},
			Kind:    "web",
		},
	})
	if err != nil {
		t.Fatalf("NewComment() error = %v", err)
	}
	ev = signed(t, ev)

	c, err := ParseComment(ev)
	if err != nil {
		t.Fatalf("ParseComment() error = %v", err)
	}
	if c.Root.Pointer.Type != PointerExternal || c.Root.Pointer.Value != "https://abc.com/articles/1" {
		t.Errorf("Root.Pointer = %+v", c.Root.Pointer)
	}
}

func TestParseCommentErrors(t *testing.T) {
	tests := []struct {
		name    string
		kind    int
		tags    [][]string
		wantErr error
	}{
		{name: "wrong kind", kind: 1, tags: nil, wantErr: ErrWrongKind},
		{
			name: "missing root kind",
			kind: KindComment,
			tags: [][]string{
				{"E", rootEventID},
				{"e", rootEventID},
				{"k", "1111"},
			},
			wantErr: ErrMissingRootKind,
		},
		{
			name: "missing parent scope",
			kind: KindComment,
			tags: [][]string{
				{"E", rootEventID},
				{"K", "1"},
				{"k", "1111"},
			},
			wantErr: ErrMissingParentScope,
		},
		{
			name: "two root scopes",
			kind: KindComment,
			tags: [][]string{
				{"E", rootEventID},
				{"I", "https://abc.com"},
				{"K", "1"},
				{"e", rootEventID},
				{"k", "1"},
			},
			wantErr: ErrMultipleRootScopes,
		},
		{
			name: "bad event id",
			kind: KindComment,
			tags: [][]string{
				{"E", "not-an-id"},
				{"K", "1"},
				{"e", "not-an-id"},
				{"k", "1"},
			},
			wantErr: ErrInvalidPointerTag,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			_, err := ParseComment(ev)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestQuoteTag(t *testing.T) {
	tag := QuoteTag(rootEventID, "wss://example.relay", rootPubkey)
	want := []string{"q", rootEventID, "wss://example.relay", rootPubkey}
	if len(tag) != len(want) {
		t.Fatalf("QuoteTag() = %v", tag)
	}
	for i := range want {
		if tag[i] != want[i] {
			t.Errorf("QuoteTag()[%d] = %q, want %q", i, tag[i], want[i])
		}
	}
}
