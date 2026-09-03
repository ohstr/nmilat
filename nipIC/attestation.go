package nipIC

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// evidenceWire is the on-the-wire JSON shape of the "evidence" tag content —
// includes Version/AuthType, which Evidence deliberately omits since they're
// always 1/"public_post" for v1 and never a meaningful caller input.
type evidenceWire struct {
	Version     int    `json:"version"`
	Platform    string `json:"platform"`
	AuthType    string `json:"auth_type"`
	UserID      string `json:"user_id"`
	Username    string `json:"username,omitempty"`
	VerifiedAt  int64  `json:"verified_at"`
	EvidenceURL string `json:"evidence_url,omitempty"`
	Challenge   string `json:"challenge,omitempty"`
	PreAuthCode string `json:"pre_auth_code,omitempty"`
}

// AttestationParams describes a Kind 35522 IA Attestation. PrivateKey,
// ConnectionKey, UserPubkey, and Platform are required.
type AttestationParams struct {
	PrivateKey     string // IA's nsec hex — required, signs internally
	ConnectionKey  ConnectionKey
	UserPubkey     string
	Platform       WebIdentity
	Evidence       Evidence
	ExpirationDays int // 0 = no expiry; NIP-IC.md recommends 90
}

// NewAttestation creates and signs a Kind 35522 attestation event.
func NewAttestation(p AttestationParams) (*nip01.Event, error) {
	wire := evidenceWire{
		Version:     1,
		Platform:    string(p.Platform),
		AuthType:    "public_post",
		UserID:      p.Evidence.UserID,
		Username:    p.Evidence.Username,
		VerifiedAt:  p.Evidence.VerifiedAt,
		EvidenceURL: p.Evidence.EvidenceURL,
		Challenge:   string(p.Evidence.Challenge),
		PreAuthCode: p.Evidence.PreAuthCode,
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("nipIC: marshal evidence: %w", err)
	}

	tags := [][]string{
		{TagDTag, string(p.ConnectionKey)},
		{TagRecipient, p.UserPubkey},
		{TagPlatform, string(p.Platform)},
		{TagEvidence, string(raw)},
	}

	now := time.Now()
	if p.ExpirationDays > 0 {
		expiresAt := now.AddDate(0, 0, p.ExpirationDays).Unix()
		tags = append(tags, []string{TagExpiration, strconv.FormatInt(expiresAt, 10)})
	}

	event := &nip01.Event{
		Kind:      KindAttestation,
		CreatedAt: uint64(now.Unix()),
		Tags:      tags,
		Content:   "",
	}
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
		CreatedAt: uint64(time.Now().Unix()),
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

// ParseAttestation parses and validates a Kind 35522 attestation event:
// correct kind, valid signature, required tags present, #d not
// platform-prefixed, and evidence tag content is valid v1 JSON. An expired
// ExpiresAt does not itself cause an error — an expired attestation is still
// structurally valid; callers decide what to do with an expired one.
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

	var dValue, pValue, platformValue, evidenceValue, expValue string
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case TagDTag:
			dValue = tag[1]
		case TagRecipient:
			pValue = tag[1]
		case TagPlatform:
			platformValue = tag[1]
		case TagEvidence:
			evidenceValue = tag[1]
		case TagExpiration:
			expValue = tag[1]
		}
	}

	if dValue == "" {
		return nil, fmt.Errorf("%w: #d tag is required for Kind 35522", ErrMissingTag)
	}
	if strings.Contains(dValue, ":") {
		return nil, fmt.Errorf("%w: %q", ErrPlatformPrefixed, dValue)
	}
	if pValue == "" {
		return nil, fmt.Errorf("%w: #p tag (user pubkey) is required for Kind 35522", ErrMissingTag)
	}
	if platformValue == "" {
		return nil, fmt.Errorf("%w: #platform tag is required for Kind 35522", ErrMissingTag)
	}
	if evidenceValue == "" {
		return nil, fmt.Errorf("%w: #evidence tag is required for Kind 35522", ErrMissingTag)
	}

	var wire evidenceWire
	if err := json.Unmarshal([]byte(evidenceValue), &wire); err != nil {
		return nil, fmt.Errorf("%w: evidence tag is not valid JSON: %v", ErrInvalidTag, err)
	}

	att := &Attestation{
		Event:         event,
		ConnectionKey: ConnectionKey(dValue),
		UserPubkey:    pValue,
		Platform:      WebIdentity(platformValue),
		Evidence: Evidence{
			Platform:    WebIdentity(platformValue),
			UserID:      wire.UserID,
			Username:    wire.Username,
			VerifiedAt:  wire.VerifiedAt,
			EvidenceURL: wire.EvidenceURL,
			Challenge:   ChallengeToken(wire.Challenge),
			PreAuthCode: wire.PreAuthCode,
		},
	}
	if expValue != "" {
		if ts, err := strconv.ParseInt(expValue, 10, 64); err == nil {
			expiresAt := time.Unix(ts, 0)
			att.ExpiresAt = &expiresAt
		}
	}
	return att, nil
}

// ValidateAttestation is a convenience wrapper for callers that only need a
// pass/fail check and don't need the parsed Attestation itself.
func ValidateAttestation(event *nip01.Event) error {
	_, err := ParseAttestation(event)
	return err
}
