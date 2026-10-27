package nipIC

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// DefaultExpirationDays is the attestation lifetime NewAttestation writes unless
// told otherwise; NIP-IC recommends 90 days.
const DefaultExpirationDays = 90

// ErrNotReverifiable is evidence another IA cannot re-verify: its auth_type is
// not public_post.
var ErrNotReverifiable = errors.New("nipIC: only public_post evidence can be re-verified by another IA")

// evidenceWire is the on-the-wire JSON of the "evidence" tag. Version is a
// pointer so a missing one is told from 0.
type evidenceWire struct {
	Version     *int   `json:"version"`
	Platform    string `json:"platform"`
	AuthType    string `json:"auth_type"`
	UserID      string `json:"user_id"`
	Username    string `json:"username,omitempty"`
	VerifiedAt  int64  `json:"verified_at"`
	EvidenceURL string `json:"evidence_url,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
	PreAuthCode string `json:"pre_auth_code,omitempty"`
}

// AttestationParams describes a Kind 35522 IA Attestation.
//
// ConnectionKey may be left empty: NewAttestation computes it from Platform and
// Evidence.UserID (the canonical form on a canonical platform, the attested id
// byte for byte otherwise) and refuses a given one that differs.
type AttestationParams struct {
	PrivateKey    string // IA's private key hex, signs internally
	ConnectionKey ConnectionKey
	UserPubkey    string
	Platform      WebIdentity
	Evidence      Evidence
	// AuthType is the evidence's auth_type; empty means public_post, whose
	// EvidenceURL, Challenge and PreAuthCode are then required. Any other value
	// carries none of the three.
	AuthType string
	// ExpirationDays sets the expiration tag; 0 means DefaultExpirationDays.
	ExpirationDays int
	// NoExpiry omits the expiration tag (and refuses an ExpirationDays > 0).
	NoExpiry bool
}

// NewAttestation creates and signs a Kind 35522 attestation. It refuses a
// platform outside ValidPlatformName (ErrPlatformName), a user id that is not
// canonical on a canonical platform, a ConnectionKey other than the one of
// platform and user id, a non-hex user pubkey and incomplete public_post
// evidence; nothing is signed then. created_at is now.
func NewAttestation(p AttestationParams) (*nip01.Event, error) {
	if !ValidPlatformName(p.Platform) {
		return nil, ErrPlatformName
	}
	if !isLowerHex64(p.UserPubkey) {
		return nil, fmt.Errorf("%w: user pubkey must be 64 lowercase hex", ErrInvalidTag)
	}
	if HasCanonicalForm(p.Platform) {
		canonical, err := CanonicalUserID(p.Platform, p.Evidence.UserID)
		if err != nil {
			return nil, err
		}
		if canonical != p.Evidence.UserID {
			return nil, ErrNotCanonical
		}
	}
	key, err := ConnectionKeyFromAttested(p.Platform, p.Evidence.UserID)
	if err != nil {
		return nil, err
	}
	if p.ConnectionKey != "" && p.ConnectionKey != key {
		return nil, fmt.Errorf("%w: d must be the ConnectionKey of platform and user_id", ErrInvalidTag)
	}
	authType := p.AuthType
	if authType == "" {
		authType = AuthTypePublicPost
	}
	ev := p.Evidence
	if authType == AuthTypePublicPost {
		if ev.EvidenceURL == "" || ev.Challenge == "" || ev.PreAuthCode == "" {
			return nil, fmt.Errorf("%w: public_post evidence needs evidence_url, challenge and pre_auth_code", ErrInvalidTag)
		}
	} else if ev.EvidenceURL != "" || ev.Challenge != "" || ev.PreAuthCode != "" {
		return nil, fmt.Errorf("%w: evidence_url, challenge and pre_auth_code are public_post only", ErrInvalidTag)
	}
	if p.NoExpiry && p.ExpirationDays > 0 {
		return nil, errors.New("nipIC: NoExpiry with an ExpirationDays")
	}

	version := 1
	raw, err := json.Marshal(evidenceWire{
		Version: &version, Platform: string(p.Platform), AuthType: authType, UserID: ev.UserID,
		Username: ev.Username, VerifiedAt: ev.VerifiedAt, EvidenceURL: ev.EvidenceURL,
		Challenge: string(ev.Challenge), PreAuthCode: ev.PreAuthCode,
	})
	if err != nil {
		return nil, fmt.Errorf("nipIC: marshal evidence: %w", err)
	}
	tags := [][]string{
		{TagDTag, string(key)},
		{TagRecipient, p.UserPubkey},
		{TagPlatform, string(p.Platform)},
		{TagEvidence, string(raw)},
	}
	now := time.Now()
	if !p.NoExpiry {
		days := p.ExpirationDays
		if days == 0 {
			days = DefaultExpirationDays
		}
		tags = append(tags, []string{TagExpiration, strconv.FormatInt(now.Unix()+int64(days)*86400, 10)})
	}
	event := &nip01.Event{Kind: KindAttestation, CreatedAt: uint64(now.Unix()), Tags: tags} //nolint:gosec // a unix time is positive
	if err := event.Sign(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("nipIC: sign attestation: %w", err)
	}
	return event, nil
}

// NewAttestationRevocation creates and signs a NIP-09 Kind 5 deletion event
// targeting a previously published Kind 35522 attestation.
func NewAttestationRevocation(privateKeyHex, attestationEventID string) (*nip01.Event, error) {
	event := &nip01.Event{
		Kind:      KindAttestationRevocation,
		CreatedAt: uint64(time.Now().Unix()), //nolint:gosec // a unix time is positive
		Tags:      [][]string{{TagEventRef, attestationEventID}},
		Content:   "revoked",
	}
	if err := event.Sign(privateKeyHex); err != nil {
		return nil, fmt.Errorf("nipIC: sign attestation revocation: %w", err)
	}
	return event, nil
}

// Attestation is a parsed and validated Kind 35522 event.
type Attestation struct {
	*nip01.Event
	ConnectionKey ConnectionKey
	UserPubkey    string
	Platform      WebIdentity
	Evidence      Evidence
	ExpiresAt     *time.Time // nil = no expiry
}

// singleTags collects the listed tags, refusing a repeated one.
func singleTags(ev *nip01.Event, names ...string) (map[string]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string]string{}
	for _, tag := range ev.Tags {
		if len(tag) < 2 || !want[tag[0]] {
			continue
		}
		if _, dup := out[tag[0]]; dup {
			return nil, fmt.Errorf("%w: %q tag repeated", ErrInvalidTag, tag[0])
		}
		out[tag[0]] = tag[1]
	}
	return out, nil
}

// ParseAttestation parses and validates a Kind 35522 attestation: kind,
// signature, every required tag exactly once, d and p as 64 lowercase hex,
// platform a valid name, an empty content, a decimal expiration when present
// (a malformed one is invalid, never "no expiry"), and v1 evidence with an
// auth_type (public_post evidence carries evidence_url, challenge and
// pre_auth_code). An expired attestation still parses; callers decide.
func ParseAttestation(event *nip01.Event) (*Attestation, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: event is nil", ErrInvalidTag)
	}
	if event.Kind != KindAttestation {
		return nil, fmt.Errorf("%w: expected kind %d, got %d", ErrWrongKind, KindAttestation, event.Kind)
	}
	if err := event.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if event.Content != "" {
		return nil, fmt.Errorf("%w: a 35522's content is empty", ErrInvalidTag)
	}
	tags, err := singleTags(event, TagDTag, TagRecipient, TagPlatform, TagEvidence, TagExpiration)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{TagDTag, TagRecipient, TagPlatform, TagEvidence} {
		if tags[name] == "" {
			return nil, fmt.Errorf("%w: %q tag is required for Kind 35522", ErrMissingTag, name)
		}
	}
	d := tags[TagDTag]
	if strings.Contains(d, ":") {
		return nil, fmt.Errorf("%w: %q", ErrPlatformPrefixed, d)
	}
	if !isLowerHex64(d) {
		return nil, fmt.Errorf("%w: d is not a ConnectionKey", ErrInvalidTag)
	}
	if !isLowerHex64(tags[TagRecipient]) {
		return nil, fmt.Errorf("%w: p is not a pubkey", ErrInvalidTag)
	}
	platform := WebIdentity(tags[TagPlatform])
	if !ValidPlatformName(platform) {
		return nil, ErrPlatformName
	}
	ev, err := parseEvidence(tags[TagEvidence])
	if err != nil {
		return nil, err
	}
	ev.Platform = platform
	att := &Attestation{Event: event, ConnectionKey: ConnectionKey(d), UserPubkey: tags[TagRecipient], Platform: platform, Evidence: ev}
	if expValue, ok := tags[TagExpiration]; ok {
		ts, err := strconv.ParseUint(expValue, 10, 63)
		if err != nil {
			return nil, fmt.Errorf("%w: expiration %q", ErrInvalidTag, expValue)
		}
		expiresAt := time.Unix(int64(ts), 0) //nolint:gosec // bounded to 63 bits above
		att.ExpiresAt = &expiresAt
	}
	return att, nil
}

func parseEvidence(raw string) (Evidence, error) {
	var wire evidenceWire
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return Evidence{}, fmt.Errorf("%w: evidence tag is not valid JSON: %v", ErrInvalidTag, err)
	}
	if wire.Version == nil || *wire.Version != 1 {
		return Evidence{}, fmt.Errorf("%w: evidence version must be 1", ErrInvalidTag)
	}
	if wire.AuthType == "" {
		return Evidence{}, fmt.Errorf("%w: evidence auth_type is empty", ErrInvalidTag)
	}
	if wire.AuthType == AuthTypePublicPost && (wire.EvidenceURL == "" || wire.Challenge == "" || wire.PreAuthCode == "") {
		return Evidence{}, fmt.Errorf("%w: public_post evidence needs evidence_url, challenge and pre_auth_code", ErrInvalidTag)
	}
	return Evidence{
		Version: 1, AuthType: wire.AuthType, UserID: wire.UserID, Username: wire.Username,
		VerifiedAt: wire.VerifiedAt, EvidenceURL: wire.EvidenceURL, Challenge: ChallengeToken(wire.Challenge),
		PreAuthCode: wire.PreAuthCode,
	}, nil
}

// Reverify runs the cross-IA re-verification of public_post evidence (NIP-IC
// §The npv1 Challenge Token, steps 1-4): the challenge must decode to
// SHA256(p || pre_auth_code). Fetching evidence_url and finding the challenge
// there stays with the caller. Other auth types return ErrNotReverifiable.
func (a *Attestation) Reverify() error {
	if a.Evidence.AuthType != AuthTypePublicPost {
		return ErrNotReverifiable
	}
	return a.Evidence.Challenge.Verify(a.UserPubkey, a.Evidence.PreAuthCode)
}

// ValidateAttestation is a convenience wrapper for callers that only need a
// pass/fail check and don't need the parsed Attestation itself.
func ValidateAttestation(event *nip01.Event) error {
	_, err := ParseAttestation(event)
	return err
}
