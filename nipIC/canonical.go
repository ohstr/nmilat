package nipIC

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

var (
	// ErrNotCanonical is a typed user id that canonicalization would have to
	// change, or that it refuses outright (NIP-IC §Canonical Platform User IDs).
	// A refused value has no ConnectionKey; it is never repaired.
	ErrNotCanonical = errors.New("nipIC: user id is not in canonical form")
	// ErrTypedInputNotCanonical is typed input for a platform with no canonical
	// form: its key comes from the recipient's attestation or nconnection.
	ErrTypedInputNotCanonical = errors.New("nipIC: this platform has no canonical form; take the key from the recipient's attestation or nconnection")
	// ErrPlatformName is a platform name outside [a-z0-9._-]+.
	ErrPlatformName = errors.New("nipIC: platform name must match [a-z0-9._-]+")
	// ErrConnectionKey is a ConnectionKey that is not 64 lowercase hex.
	ErrConnectionKey = errors.New("nipIC: a ConnectionKey is 64 lowercase hex characters")
)

// The platforms with a canonical form (NIP-IC §Canonical Platform User IDs).
const (
	PlatformX       WebIdentity = "x"
	PlatformDiscord WebIdentity = "discord"
	PlatformEmail   WebIdentity = "email"
	PlatformDNS     WebIdentity = "dns"
)

// ValidPlatformName reports a platform name of one or more of a-z, 0-9, '.',
// '_' and '-'. It is never lowercased for the caller.
func ValidPlatformName(p WebIdentity) bool {
	if p == "" {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// HasCanonicalForm reports the platforms a sender may derive a ConnectionKey for
// from typed input: x, discord, email and dns.
func HasCanonicalForm(p WebIdentity) bool {
	switch p {
	case PlatformX, PlatformDiscord, PlatformEmail, PlatformDNS:
		return true
	}
	return false
}

// CanonicalUserID brings typed input to the canonical user id of p, or refuses
// it (ErrNotCanonical; ErrTypedInputNotCanonical for a platform with no
// canonical form). The error never echoes the input.
func CanonicalUserID(p WebIdentity, typed string) (string, error) {
	if !ValidPlatformName(p) {
		return "", ErrPlatformName
	}
	switch p {
	case PlatformX, PlatformDiscord:
		return canonicalNumericID(typed)
	case PlatformEmail:
		if !utf8.ValidString(typed) {
			return "", ErrNotCanonical
		}
		return canonicalEmail(typed)
	case PlatformDNS:
		if !utf8.ValidString(typed) {
			return "", ErrNotCanonical
		}
		return canonicalDomain(trimASCII(typed), true)
	default:
		return "", ErrTypedInputNotCanonical
	}
}

// NewConnectionKey is the ConnectionKey of typed input on a platform with a
// canonical form: hex(SHA256(p ":" CanonicalUserID(p, typed))).
func NewConnectionKey(p WebIdentity, typed string) (ConnectionKey, error) {
	id, err := CanonicalUserID(p, typed)
	if err != nil {
		return "", err
	}
	return hashKey(p, id), nil
}

// ConnectionKeyFromAttested is the ConnectionKey of a user id exactly as an IA
// attested it (a 35522's platform tag and evidence.user_id), hashed byte for
// byte with no normalization. Any valid platform name; on a platform with a
// canonical form the user id must already be canonical (ErrNotCanonical), since
// every client hashes that form (NIP-IC §Terminology).
func ConnectionKeyFromAttested(p WebIdentity, userID string) (ConnectionKey, error) {
	if !ValidPlatformName(p) {
		return "", ErrPlatformName
	}
	if HasCanonicalForm(p) {
		if c, err := CanonicalUserID(p, userID); err != nil || c != userID {
			return "", ErrNotCanonical
		}
	}
	return hashKey(p, userID), nil
}

// ParseConnectionKey checks s is 64 lowercase hex.
func ParseConnectionKey(s string) (ConnectionKey, error) {
	if !isLowerHex64(s) {
		return "", ErrConnectionKey
	}
	return ConnectionKey(s), nil
}

func hashKey(p WebIdentity, id string) ConnectionKey {
	sum := sha256.Sum256([]byte(string(p) + ":" + id))
	return ConnectionKey(hex.EncodeToString(sum[:]))
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// canonicalNumericID: 1 to 20 ASCII digits, no leading zero, below 2^64; nothing
// trimmed.
func canonicalNumericID(s string) (string, error) {
	if len(s) < 1 || len(s) > 20 || s[0] == '0' {
		return "", ErrNotCanonical
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", ErrNotCanonical
		}
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return "", ErrNotCanonical
	}
	return s, nil
}

func trimASCII(s string) string { return strings.Trim(s, " \t\n\v\f\r") }

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// canonicalEmail trims, splits at the last '@', ASCII-lowercases the whole
// address, keeps a local part only if NFC leaves it unchanged, and converts the
// domain part to A-labels.
func canonicalEmail(s string) (string, error) {
	s = asciiLower(trimASCII(s))
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return "", ErrNotCanonical
	}
	local := s[:at]
	if norm.NFC.String(local) != local {
		return "", ErrNotCanonical
	}
	domain, err := canonicalDomain(s[at+1:], false)
	if err != nil {
		return "", err
	}
	return local + "@" + domain, nil
}

// deviation characters, which UTS #46 processing modes convert differently.
const deviations = "ßς‌‍"

var (
	mapProfile   = idna.New(idna.MapForLookup(), idna.Transitional(false))
	asciiProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.CheckHyphens(true),
		idna.BidiRule(), idna.CheckJoiners(true), idna.StrictDomainName(true), idna.VerifyDNSLength(true))
	punyProfile = idna.New()
)

// canonicalDomain applies NIP-IC's domain processing: ASCII lowercase, refuse a
// leading '@' or trailing '.', refuse a deviation character, a value NFC or the
// UTS #46 mapping would change, then UTS #46 ToASCII (non-transitional,
// CheckHyphens, CheckBidi, CheckJoiners, STD3 rules, DNS length), refusing
// anything ToASCII rejects. An input A-label that decodes to a deviation
// character is refused too.
func canonicalDomain(s string, _ bool) (string, error) {
	s = asciiLower(s)
	if s == "" || strings.HasPrefix(s, "@") || strings.HasSuffix(s, ".") {
		return "", ErrNotCanonical
	}
	if strings.ContainsAny(s, deviations) || norm.NFC.String(s) != s {
		return "", ErrNotCanonical
	}
	for _, label := range strings.Split(s, ".") {
		if strings.HasPrefix(label, "xn--") {
			u, err := punyProfile.ToUnicode(label)
			if err != nil || strings.ContainsAny(u, deviations) {
				return "", ErrNotCanonical
			}
			continue
		}
		mapped, err := mapProfile.ToUnicode(label)
		if err != nil || mapped != label {
			return "", ErrNotCanonical
		}
	}
	out, err := asciiProfile.ToASCII(s)
	if err != nil || out != asciiLower(out) {
		return "", ErrNotCanonical
	}
	for i := 0; i < len(out); i++ {
		if out[i] > 0x7f {
			return "", ErrNotCanonical
		}
	}
	return out, nil
}
