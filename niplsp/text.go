package niplsp

import (
	"github.com/ohstr/nmilat/internal/textsan"
	"github.com/rivo/uniseg"
)

// countChars counts user-perceived characters (extended grapheme clusters).
func countChars(s string) int { return uniseg.GraphemeClusterCount(s) }

// sanitizeText strips control and zero-width characters, bidirectional
// controls and check-mark look-alikes that could pose as a verification mark,
// turns line breaks and tabs into one space (all of them, then trims, when
// oneLine; else only tabs and the rarer breaks, keeping "\n"), and keeps at
// most maxChars user-perceived characters. It parses no link: the result is
// plain text.
func sanitizeText(s string, maxChars int, oneLine bool) string {
	return textsan.Sanitize(s, maxChars, textsan.Options{KeepNewlines: !oneLine, StripControls: true, TrimSpace: oneLine})
}
