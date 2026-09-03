package ranking

import (
	"regexp"
	"strings"

	"github.com/ohstr/nmilat/config"
)

var (
	// Basic regex for email-like format: user@domain.tld
	nip05Regex = regexp.MustCompile(`^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$`)
	// Basic regex for Lightning Address (email-like)
	lud16Regex = regexp.MustCompile(`^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$`)
)

func IsValidNip05Format(s string) bool {
	return nip05Regex.MatchString(s)
}

func IsValidLud16Format(s string) bool {
	return lud16Regex.MatchString(s)
}

// CalculateScore computes the relevance score for a profile based on heuristics.
// Score = Base + (Completeness * 10) + (Signals * 20) - Penalties
func CalculateScore(name, displayName, about, nip05, lud16, picture string) int64 {
	cfg := config.Get().Search.Scoring
	var score int64 = 0

	// 1. Identity Base
	if name != "" || displayName != "" {
		score += cfg.IdentityBase
	}

	// 2. Completeness Signals
	if len(about) > cfg.MinAboutLength {
		score += cfg.AboutBonus
	}
	if strings.HasPrefix(picture, "http") {
		score += cfg.PictureBonus
	}

	// 3. Verification Signals
	// Points for NIP-05 and LUD16 are awarded asynchronously
	// by the relay VerificationWorker after successful online verification.

	// 4. Penalties

	// Hex Name (Lazy Bot) - exactly 64 hex chars
	if len(name) == 64 && isHex(name) {
		score += cfg.HexNamePenalty
	}

	// Gibberish / Spam filter
	if len(name) > cfg.MinGibberishLen && !hasVowels(name) {
		score += cfg.GibberishPenalty
	}

	// Empty Shell (The ghost profile)
	if name == "" && about == "" && picture == "" {
		score += cfg.GhostPenalty
	}

	return score
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func hasVowels(s string) bool {
	vowels := "aeiouAEIOU"
	return strings.ContainsAny(s, vowels)
}
