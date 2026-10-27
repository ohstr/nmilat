// Package textsan prepares untrusted text (a lister's or an LSP's claims) for
// display: it strips characters that could pose as a wallet's own marks or
// reorder what is shown, flattens line breaks, and caps the result in
// user-perceived characters (extended grapheme clusters). It parses and
// renders no link.
package textsan

import (
	"strings"
	"unicode"

	"github.com/rivo/uniseg"
)

// Options tunes Sanitize beyond what it always does.
type Options struct {
	// KeepNewlines keeps "\n" (and turns CR LF into one "\n"); every other line
	// break and tab still becomes one space.
	KeepNewlines bool
	// StripControls also removes the other control characters (Unicode Cc).
	StripControls bool
	// TrimSpace trims leading and trailing white space before the cap.
	TrimSpace bool
}

// checkMark reports a check-mark look-alike: U+2713, U+2714, U+2705, U+2611,
// U+1F5F8 and U+221A.
func checkMark(r rune) bool {
	return r == 0x2713 || r == 0x2714 || r == 0x2705 || r == 0x2611 || r == 0x1F5F8 || r == 0x221A
}

// stripped reports a code point Sanitize always removes: the check-mark
// look-alikes, the bidirectional controls U+202A–U+202E and U+2066–U+2069, and
// the zero-width U+200B–U+200D, U+2060 and U+FEFF.
func stripped(r rune) bool {
	switch {
	case checkMark(r):
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return true
	}
	return false
}

func lineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\t', '\v', '\f', 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// Sanitize strips the code points stripped reports (and an emoji variation
// selector U+FE0F right after a check-mark look-alike), turns every line break and tab
// into one space (CR LF counts once), and caps the result at maxClusters
// extended grapheme clusters (none when maxClusters <= 0), never cutting
// inside one. o adds to it.
func Sanitize(s string, maxClusters int, o Options) string {
	var b strings.Builder
	b.Grow(len(s))
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case stripped(r):
			if checkMark(r) && i+1 < len(rs) && rs[i+1] == 0xFE0F {
				i++
			}
		case r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
			if o.KeepNewlines {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
			i++
		case r == '\n' && o.KeepNewlines:
			b.WriteByte('\n')
		case lineBreak(r):
			b.WriteByte(' ')
		case o.StripControls && unicode.IsControl(r):
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if o.TrimSpace {
		out = strings.TrimSpace(out)
	}
	if maxClusters <= 0 {
		return out
	}
	g := uniseg.NewGraphemes(out)
	n, end := 0, 0
	for g.Next() {
		if n == maxClusters {
			return out[:end]
		}
		_, end = g.Positions()
		n++
	}
	return out
}
