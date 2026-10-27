package niplsp

import (
	"strings"
	"unicode"

	"github.com/rivo/uniseg"
)

// countChars counts user-perceived characters (extended grapheme clusters).
func countChars(s string) int { return uniseg.GraphemeClusterCount(s) }

// stripped reports a rune a client removes from the LSP's text before showing
// it: zero-width characters, bidirectional embeddings, overrides and isolates,
// and check-mark look-alikes that could pose as a verification mark.
func stripped(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF: // zero-width
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi
		return true
	case r == 0x2713, r == 0x2714, r == 0x2705, r == 0x2611, r == 0x1F5F8, r == 0x221A: // check marks
		return true
	}
	return false
}

// sanitizeText strips control and zero-width characters, turns line breaks
// and tabs into one space (all of them when oneLine, else only tabs and the
// rarer breaks, keeping "\n"), and keeps at most maxChars user-perceived
// characters. It parses no link: the result is plain text.
func sanitizeText(s string, maxChars int, oneLine bool) string {
	var b strings.Builder
	for _, r := range strings.ReplaceAll(s, "\r\n", "\n") {
		switch {
		case r == '\n' && !oneLine:
			b.WriteRune(r)
		case r == '\t', r == '\n', r == '\r', r == '\v', r == '\f', r == 0x85, r == 0x2028, r == 0x2029:
			b.WriteByte(' ')
		case unicode.IsControl(r), stripped(r):
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if oneLine {
		out = strings.TrimSpace(out)
	}
	rest, n := out, 0
	for len(rest) > 0 {
		if n == maxChars {
			return out[:len(out)-len(rest)]
		}
		_, rest, _, _ = uniseg.FirstGraphemeClusterInString(rest, -1)
		n++
	}
	return out
}
