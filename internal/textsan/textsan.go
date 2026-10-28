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

// MaxClusterBytes is the default byte budget per user-perceived character:
// with a cluster cap n and no Options.MaxBytes, Sanitize also caps the result
// at n*MaxClusterBytes bytes, so a run of combining marks or joined emoji can't
// grow one character without bound.
const MaxClusterBytes = 32

// Options tunes Sanitize beyond what it always does.
type Options struct {
	// MaxBytes caps the result in bytes, never cutting inside a cluster: 0
	// means maxClusters*MaxClusterBytes (no byte cap when maxClusters <= 0),
	// and a negative value means no byte cap.
	MaxBytes int
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
// look-alikes and every format character (Unicode Cf), which includes the
// bidirectional controls U+202A–U+202E and U+2066–U+2069, the directional
// marks U+200E, U+200F and U+061C, the zero-width U+200B–U+200D, U+2060 and
// U+FEFF, the invisible U+00AD, U+180E, U+2061–U+2064 and U+206A–U+206F, the
// interlinear annotations U+FFF9–U+FFFB and the tag characters U+E0001 and
// U+E0020–U+E007F. Sanitize keeps a zero-width joiner U+200D only inside an
// emoji sequence (keepJoiner).
func stripped(r rune) bool {
	switch {
	case checkMark(r):
		return true
	case unicode.Is(unicode.Cf, r):
		return true
	case r == 0x180E:
		// Cf before Unicode 6.3; still invisible.
		return true
	}
	return false
}

// emoji reports a code point that starts or continues an emoji ZWJ sequence:
// roughly Unicode's Extended_Pictographic, never a check-mark look-alike.
func emoji(r rune) bool {
	if checkMark(r) {
		return false
	}
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF, r >= 0x2600 && r <= 0x27BF, r >= 0x2300 && r <= 0x23FF,
		r >= 0x2B00 && r <= 0x2BFF, r >= 0x2190 && r <= 0x21FF,
		r == 0x00A9, r == 0x00AE, r == 0x203C, r == 0x2049, r == 0x2122, r == 0x2139:
		return true
	}
	return false
}

// emojiTail reports a code point that may follow an emoji inside its cluster:
// the emoji variation selector U+FE0F and the skin-tone modifiers.
func emojiTail(r rune) bool {
	return r == 0xFE0F || (r >= 0x1F3FB && r <= 0x1F3FF)
}

// keepJoiner reports whether the zero-width joiner at rs[i] joins two emoji:
// the last code point kept (skipping a variation selector or skin tone) and
// the next one are both emoji.
func keepJoiner(kept []rune, rs []rune, i int) bool {
	j := len(kept) - 1
	for j >= 0 && emojiTail(kept[j]) {
		j--
	}
	return j >= 0 && emoji(kept[j]) && i+1 < len(rs) && emoji(rs[i+1])
}

func lineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\t', '\v', '\f', 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// Sanitize strips the code points stripped reports (and an emoji variation
// selector U+FE0F right after a check-mark look-alike), keeping a zero-width
// joiner only between two emoji, turns every line break and tab into one space
// (CR LF counts once), and caps the result at maxClusters extended grapheme
// clusters (none when maxClusters <= 0) and at Options.MaxBytes bytes, never
// cutting inside a cluster. o adds to it.
func Sanitize(s string, maxClusters int, o Options) string {
	rs := []rune(s)
	kept := make([]rune, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x200D && keepJoiner(kept, rs, i):
			kept = append(kept, r)
		case stripped(r):
			if checkMark(r) && i+1 < len(rs) && rs[i+1] == 0xFE0F {
				i++
			}
		case r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
			if o.KeepNewlines {
				kept = append(kept, '\n')
			} else {
				kept = append(kept, ' ')
			}
			i++
		case r == '\n' && o.KeepNewlines:
			kept = append(kept, '\n')
		case lineBreak(r):
			kept = append(kept, ' ')
		case o.StripControls && unicode.IsControl(r):
		default:
			kept = append(kept, r)
		}
	}
	out := string(kept)
	if o.TrimSpace {
		out = strings.TrimSpace(out)
	}
	maxBytes := o.MaxBytes
	if maxBytes == 0 && maxClusters > 0 {
		maxBytes = maxClusters * MaxClusterBytes
	}
	if maxClusters <= 0 && maxBytes <= 0 {
		return out
	}
	g := uniseg.NewGraphemes(out)
	n, end := 0, 0
	for g.Next() {
		_, next := g.Positions()
		if (maxClusters > 0 && n == maxClusters) || (maxBytes > 0 && next > maxBytes) {
			return out[:end]
		}
		end = next
		n++
	}
	return out
}
