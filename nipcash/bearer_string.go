package nipcash

import "strings"

// SplitBearerSliceString splits a bearer slice's optional "<token>#<bearer_secret>"
// combined presentation (§Presenting a Bearer Slice as One String) back
// into its two parts. "#" never appears in a bech32 charset, so splitting
// on the first one is always unambiguous — a display-layer convenience
// only, not a new wire format. A string with no "#" at all (every
// identity-bound token, or a bearer token whose sender chose to hand the
// two values over separately — still explicitly allowed by the spec)
// returns unchanged, with an empty secret.
//
// Every caller MUST use the returned token — never the original combined
// string — in any error message, --json "input" field, or other output:
// the whole point of accepting this format is convenience, not making it
// easier to accidentally echo a spending credential back to a terminal,
// log, or JSON response.
func SplitBearerSliceString(s string) (token, bearerSecret string) {
	token, bearerSecret, _ = strings.Cut(s, "#")
	return token, bearerSecret
}
