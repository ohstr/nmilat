package listing

import "github.com/ohstr/nmilat/internal/textsan"

// SanitizeText prepares a lister's text for display (§Wallet Rules "Untrusted
// text"): it strips check-mark look-alikes (U+2713, U+2714, U+2705, U+2611,
// U+1F5F8, U+221A, and an emoji variation selector right after one),
// bidirectional controls (U+202A–U+202E, U+2066–U+2069), zero-width characters
// (U+200B–U+200D, U+2060, U+FEFF) and every other control character (Unicode
// Cc: NUL, ESC and the C1 range, so no terminal escape survives), turns every
// line break and tab into one space (CR LF counts once), and caps the result at
// maxClusters extended grapheme clusters (none when maxClusters <= 0), never
// cutting inside one. It parses and renders no link; a wallet draws its own
// marks outside the returned text.
func SanitizeText(s string, maxClusters int) string {
	return textsan.Sanitize(s, maxClusters, textsan.Options{StripControls: true})
}
