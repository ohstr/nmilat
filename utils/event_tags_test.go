package utils

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateStrKind(t *testing.T) {
	if k, err := ValidateStrKind("1"); err != nil || k != 1 {
		t.Errorf("expected kind=1, err=nil, got kind=%d err=%v", k, err)
	}
	if _, err := ValidateStrKind("not-a-number"); err == nil {
		t.Error("expected error for non-numeric kind")
	}
	if _, err := ValidateStrKind("70000"); err == nil {
		t.Error("expected error for out-of-range kind")
	}
}

func TestValidateEventTags(t *testing.T) {
	if err := ValidateEventTags([][]string{{"p", "abc"}, {"e", "def"}}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := ValidateEventTags([][]string{{}}); err == nil {
		t.Error("expected error for empty tag")
	}
}

func TestLookupEventTag(t *testing.T) {
	tags := [][]string{{"p", "a"}, {"e", "b"}, {"p", "c"}}

	found, ok := LookupEventTag(tags, "p")
	if !ok || len(found) != 2 {
		t.Fatalf("expected 2 p tags, got %v ok=%v", found, ok)
	}

	_, ok = LookupEventTag(tags, "missing")
	if ok {
		t.Error("expected ok=false for a missing tag name")
	}
}

func TestFindUniqueEventTag(t *testing.T) {
	tags := [][]string{{"p", "a"}, {"e", "b"}}

	found, err := FindUniqueEventTag(tags, "p")
	if err != nil || found[1] != "a" {
		t.Fatalf("expected p tag [p a], got %v err=%v", found, err)
	}

	_, err = FindUniqueEventTag(tags, "missing")
	if !errors.Is(err, ErrTagNotFound) {
		t.Errorf("expected ErrTagNotFound, got %v", err)
	}

	dup := [][]string{{"p", "a"}, {"p", "b"}}
	_, err = FindUniqueEventTag(dup, "p")
	if !errors.Is(err, ErrTagNotUnique) {
		t.Errorf("expected ErrTagNotUnique, got %v", err)
	}
}

func TestFindUniqueEventTagValue(t *testing.T) {
	tags := [][]string{{"p", "pubkey1"}}

	val, err := FindUniqueEventTagValue(tags, "p")
	if err != nil || val != "pubkey1" {
		t.Fatalf("expected pubkey1, got %q err=%v", val, err)
	}

	noValueTags := [][]string{{"p"}}
	if _, err := FindUniqueEventTagValue(noValueTags, "p"); err == nil {
		t.Error("expected error for a tag without a value")
	}

	if _, err := FindUniqueEventTagValue(tags, "missing"); !errors.Is(err, ErrTagNotFound) {
		t.Errorf("expected ErrTagNotFound, got %v", err)
	}
}

func TestValidateIndexableTag(t *testing.T) {
	if err := ValidateIndexableTag("d"); err != nil {
		t.Errorf("unexpected error for valid single-letter tag: %v", err)
	}
	if err := ValidateIndexableTag("dd"); err == nil {
		t.Error("expected error for multi-letter tag name")
	}
	if err := ValidateIndexableTag("1"); err == nil {
		t.Error("expected error for non-letter tag name")
	}
}

func TestValidateFilterTag(t *testing.T) {
	validKey := strings.Repeat("a", 64)

	if err := ValidateFilterTag("e", []string{validKey}); err != nil {
		t.Errorf("unexpected error for valid e tag: %v", err)
	}
	if err := ValidateFilterTag("p", []string{"short"}); err == nil {
		t.Error("expected error for invalid p tag value")
	}
	if err := ValidateFilterTag("d", nil); err == nil {
		t.Error("expected error when no tag values are provided")
	}
	if err := ValidateFilterTag("d", []string{"x"}); err != nil {
		t.Errorf("unexpected error for valid single-letter tag: %v", err)
	}
	if err := ValidateFilterTag("bad", []string{"x"}); err == nil {
		t.Error("expected error for a non-indexable multi-letter tag name")
	}
}

func TestValidateFilterTags(t *testing.T) {
	valid := map[string][]string{"d": {"x"}}
	if err := ValidateFilterTags(valid); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	invalid := map[string][]string{"bad-tag": {"x"}}
	if err := ValidateFilterTags(invalid); err == nil {
		t.Error("expected error for invalid tag name")
	}
}

func TestEscapeJSONString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`hello`, `hello`},
		{`with "quotes"`, `with \"quotes\"`},
		{"line\nbreak", `line\nbreak`},
		{"tab\ttab", `tab\ttab`},
		{"back\\slash", `back\\slash`},
		{"cr\rreturn", `cr\rreturn`},
		// Control characters with no named JSON escape must still come out
		// as exactly 4 hex digits after \u -- a single-nibble value (e.g.
		// 0x0B) needs a leading zero, which a prior version of this
		// function dropped (producing the malformed \u00b instead of
		// the correct \u000b).
		{"\x00", "\\u0000"},
		{"\x0b", "\\u000b"},
		{"\x1f", "\\u001f"},
	}

	for _, tt := range tests {
		if got := EscapeJSONString(tt.in); got != tt.want {
			t.Errorf("EscapeJSONString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMarshalTags(t *testing.T) {
	tags := [][]string{{"p", "abc"}, {"e", "def"}}
	data, err := MarshalTags(tags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `[["p","abc"],["e","def"]]` {
		t.Errorf("unexpected marshaled tags: %s", data)
	}

	empty, err := MarshalTags(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(empty) != "null" {
		t.Errorf("expected \"null\" for nil tags, got %s", empty)
	}
}
