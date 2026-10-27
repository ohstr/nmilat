package listing

import (
	"strings"

	"github.com/rivo/uniseg"
)

// stripped reports a code point SanitizeText removes: the check-mark
// look-alikes (U+2713, U+2714, U+2705, U+2611, U+1F5F8, U+221A), the
// bidirectional controls U+202A–U+202E and U+2066–U+2069, and the zero-width
// U+200B–U+200D, U+2060 and U+FEFF.
func stripped(r rune) bool {
	switch {
	case r == 0x2713, r == 0x2714, r == 0x2705, r == 0x2611, r == 0x1F5F8, r == 0x221A:
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return true
	}
	return false
}

func checkMark(r rune) bool {
	return r == 0x2713 || r == 0x2714 || r == 0x2705 || r == 0x2611 || r == 0x1F5F8 || r == 0x221A
}

func lineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\t', '\v', '\f', 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// SanitizeText prepares a lister's text for display (§Wallet Rules "Untrusted
// text"): it strips check-mark look-alikes (and an emoji variation selector
// right after one), bidirectional controls and zero-width characters, turns
// every line break and tab into one space (CR LF counts once), and caps the
// result at maxClusters extended grapheme clusters (none when maxClusters <=
// 0), never cutting inside one. It parses and renders no link; a wallet draws
// its own marks outside the returned text.
func SanitizeText(s string, maxClusters int) string {
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
			b.WriteByte(' ')
			i++
		case lineBreak(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
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
