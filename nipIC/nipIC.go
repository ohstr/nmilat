// Package nipIC implements NIP-IC (Identity Connection): binding a Nostr
// public key to an account on a non-Nostr platform, witnessed by a
// permissionless network of Identity Authorities (IAs). It defines Kind
// 35521 (Identity Connection) and Kind 35522 (IA Attestation), plus the
// supporting ConnectionKey / npv1 challenge-token / nconnection primitives
// NIP-AZ (github.com/ohstr/nmilat/nipAZ) uses to address a recipient who has
// no Nostr keypair yet.
//
// This package defines no platform or chain names of its own — see the
// WebIdentity doc comment. A caller (or an application built on this SDK)
// supplies whatever platform string its own deployment uses.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-IC.md
package nipIC

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

const (
	// KindIdentityConnection is the parameterized-replaceable event a user
	// publishes to claim a connection between a ConnectionKey and their
	// Nostr pubkey (Kind 35521).
	KindIdentityConnection = 35521

	// KindAttestation is the parameterized-replaceable event an Identity
	// Authority publishes to witness a Kind 35521 claim (Kind 35522).
	KindAttestation = 35522

	// KindAttestationRevocation is the standard NIP-09 deletion kind, used
	// here specifically to revoke a previously published Kind 35522.
	KindAttestationRevocation = 5
)

// Wire tag names, exported so callers building custom tooling around raw
// events don't have to hardcode these strings themselves.
const (
	TagDTag       = "d"
	TagRecipient  = "p"
	TagPlatform   = "platform"
	TagEvidence   = "evidence"
	TagExpiration = "expiration"
	TagEventRef   = "e"
)

var (
	// ErrInvalidTag is returned for a structurally malformed tag (wrong
	// element count, empty required value, etc.).
	ErrInvalidTag = errors.New("nipIC: invalid tag")
	// ErrMissingTag is returned when a required tag is absent entirely.
	ErrMissingTag = errors.New("nipIC: missing required tag")
	// ErrPlatformPrefixed is returned when a #d tag carries a "platform:"
	// prefix — NIP-IC requires the bare ConnectionKey so #d relay filters
	// from third-party clients keep working.
	ErrPlatformPrefixed = errors.New("nipIC: #d tag must be a bare ConnectionKey, not platform-prefixed")
	// ErrWrongKind is returned when parsing an event of the wrong Nostr kind.
	ErrWrongKind = errors.New("nipIC: unexpected event kind")
	// ErrInvalidSignature is returned when an event's signature does not verify.
	ErrInvalidSignature = errors.New("nipIC: invalid event signature")
	// ErrChallengeMismatch is returned by ChallengeToken.Verify when the
	// token does not match the given pubkey/pre-auth code pair.
	ErrChallengeMismatch = errors.New("nipIC: challenge does not match pubkey/pre-auth code")
	// ErrInvalidChallengeToken is returned for a malformed npv1 token
	// (wrong bech32 prefix, corrupt TLV payload, etc.).
	ErrInvalidChallengeToken = errors.New("nipIC: malformed challenge token")
)

// WebIdentity names the platform a ConnectionKey is scoped to — e.g. an
// application chooses "discord" or "email". This package defines no
// predefined values: a different consumer of nipIC may support an entirely
// different set of platforms, and every one of them can define its own
// ConnectionKeys. An application that wants named constants for its own
// known platforms defines them itself, on top of this type.
//
// The Go zero value WebIdentity("") is the one value this package does give
// meaning to: NIP-AZ's wire rule is that an omitted or empty platform
// element on a p/P identity tag MUST be read as "native Nostr pubkey", so
// the zero value already carries that meaning for free.
type WebIdentity string

// ConnectionKey is the hash standing in for a Nostr pubkey when the recipient
// has no keypair yet: hex(SHA256("<platform>:<platform-user-id>")). Build one
// with NewConnectionKey (canonical platforms, typed input) or
// ConnectionKeyFromAttested (an IA's attested user id, byte for byte).
type ConnectionKey string

// String returns the hex-encoded ConnectionKey.
func (k ConnectionKey) String() string { return string(k) }

const (
	challengeTokenPrefix   = "npv1"
	tlvTypeSessionHash     = byte(0)
	preAuthCodeRandomBytes = 16 // 32 hex chars — this code is embedded in a publicly posted token, never hand-typed, so it favors entropy over brevity
)

// ChallengeToken is a bech32-encoded, session-bound proof string
// (npv1-prefixed) a user publishes publicly on a web identity platform as
// evidence of control. It binds SHA256(pubkey || preAuthCode) into a TLV
// payload, so a token minted for one user/session cannot be replayed for
// another — see Verify.
type ChallengeToken string

// NewChallenge mints a fresh challenge token for pubkeyHex, generating and
// returning the random pre-auth code that backs it (32-char hex — this code
// is embedded in the token and posted publicly by the user, not hand-typed,
// so it favors entropy over brevity; a caller whose flow instead needs a
// short, human-typeable code, e.g. "/verify <code>", should generate that
// code itself and call NewChallengeToken directly once bound). The token and
// pre-auth code are minted together so they can never end up mismatched or
// under-entropy; the caller must persist PreAuthCode (it's required again by
// Verify, and belongs in the eventual Evidence.PreAuthCode once the
// challenge is fulfilled).
func NewChallenge(pubkeyHex string) (token ChallengeToken, preAuthCode string, err error) {
	buf := make([]byte, preAuthCodeRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("nipIC: generate pre-auth code: %w", err)
	}
	preAuthCode = hex.EncodeToString(buf)
	token, err = NewChallengeToken(pubkeyHex, preAuthCode)
	if err != nil {
		return "", "", err
	}
	return token, preAuthCode, nil
}

// NewChallengeToken rebuilds the challenge token for a pubkey/pre-auth-code
// pair that already exists (e.g. resuming a session whose pre-auth code was
// already minted and persisted) — no fresh code is generated.
func NewChallengeToken(pubkeyHex, preAuthCode string) (ChallengeToken, error) {
	sessionHash, err := sessionHash(pubkeyHex, preAuthCode)
	if err != nil {
		return "", err
	}

	tlv := make([]byte, 0, 34)
	tlv = append(tlv, tlvTypeSessionHash, byte(len(sessionHash)))
	tlv = append(tlv, sessionHash...)

	bits5, err := bech32.ConvertBits(tlv, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipIC: bech32 convert: %w", err)
	}
	encoded, err := bech32.Encode(challengeTokenPrefix, bits5)
	if err != nil {
		return "", fmt.Errorf("nipIC: bech32 encode: %w", err)
	}
	return ChallengeToken(encoded), nil
}

// Verify confirms t was genuinely minted for pubkeyHex bound to preAuthCode
// — i.e. that t decodes to SHA256(pubkeyHex-bytes || preAuthCode). Returns
// ErrInvalidChallengeToken if t is malformed, ErrChallengeMismatch if it
// decodes fine but doesn't match the given pubkey/pre-auth-code pair.
func (t ChallengeToken) Verify(pubkeyHex, preAuthCode string) error {
	got, err := t.decode()
	if err != nil {
		return err
	}
	want, err := sessionHash(pubkeyHex, preAuthCode)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrChallengeMismatch
	}
	return nil
}

func sessionHash(pubkeyHex, preAuthCode string) ([]byte, error) {
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("nipIC: decode pubkey: %w", err)
	}
	h := sha256.New()
	h.Write(pubkeyBytes)
	h.Write([]byte(preAuthCode))
	return h.Sum(nil), nil
}

// decode unwraps the bech32/TLV envelope and returns the raw 32-byte session
// hash. Unexported: callers verify a claimed (pubkey, preAuthCode) pair via
// Verify, they never need the raw hash — see the design rubric's "no bare
// wire-format decoding at the call site" rule.
//
// The payload must be exactly the 34-byte TLV the spec defines, 0x00 0x20 then
// the 32-byte hash: any other type, length or size is refused.
func (t ChallengeToken) decode() ([]byte, error) {
	prefix, bits5, err := bech32.DecodeNoLimit(string(t))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChallengeToken, err)
	}
	if prefix != challengeTokenPrefix {
		return nil, fmt.Errorf("%w: expected prefix %q, got %q", ErrInvalidChallengeToken, challengeTokenPrefix, prefix)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChallengeToken, err)
	}
	if len(data) != 34 || data[0] != tlvTypeSessionHash || data[1] != 0x20 {
		return nil, fmt.Errorf("%w: the payload is not one 32-byte session hash", ErrInvalidChallengeToken)
	}
	return data[2:], nil
}

// AuthTypePublicPost is the auth_type whose evidence any IA can re-verify: a
// public post carrying an npv1 challenge.
const AuthTypePublicPost = "public_post"

// Evidence is the cleartext v1 "evidence" tag payload of a Kind 35522
// attestation (NIP-IC §The evidence Tag).
type Evidence struct {
	Version     int            // always 1
	Platform    WebIdentity    // duplicated from the outer "platform" tag
	AuthType    string         // how the IA verified control; "public_post" or an IA's own value
	UserID      string         // the platform account identifier; d is the ConnectionKey of platform and this
	Username    string         // provider handle at verification time; never an input to the key
	VerifiedAt  int64          // unix timestamp of successful verification
	EvidenceURL string         // public_post only: URL of the post carrying the challenge
	Challenge   ChallengeToken // public_post only: the npv1 token published at EvidenceURL
	// PreAuthCode enables cross-IA re-verification (public_post only, REQUIRED there).
	PreAuthCode string
}
