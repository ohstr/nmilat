package nipIC

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const (
	testIAPrivKey  = "67dea2ed018072d675f5415ecfa0a3f99969a5db773c2583831a29779c58155b"
	testUserPubKey = "d80a8834fbab8b33adae2e1e78f5e2e30d42df72b4881f87920ee33dd9fc2a97"
)

func findTag(event *nip01.Event, name string) []string {
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag
		}
	}
	return nil
}

func makeAttestationParams() AttestationParams {
	return AttestationParams{
		PrivateKey:    testIAPrivKey,
		ConnectionKey: ConnectionKey("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		UserPubkey:    testUserPubKey,
		Platform:      "github",
		Evidence: Evidence{
			UserID:      "user42",
			Username:    "alice",
			EvidenceURL: "https://gist.github.com/alice/abc123",
			Challenge:   "npv11qqsddvq9arp",
			VerifiedAt:  1700000000,
		},
		ExpirationDays: 90,
	}
}

// ── NewAttestation: evidence tag structure ──────────────────────────────────
// Ported from zapf's attestation_event_test.go (T-13b.1 .. T-13b.7).

func TestNewAttestation_EvidenceTagIsJSON(t *testing.T) {
	event, err := NewAttestation(makeAttestationParams())
	if err != nil {
		t.Fatalf("NewAttestation failed: %v", err)
	}
	tag := findTag(event, TagEvidence)
	if len(tag) < 2 {
		t.Fatal("missing evidence tag")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(tag[1]), &parsed); err != nil {
		t.Errorf("evidence tag must be valid JSON, got: %q", tag[1])
	}
}

func TestNewAttestation_EvidenceHasVersion1(t *testing.T) {
	event, _ := NewAttestation(makeAttestationParams())
	tag := findTag(event, TagEvidence)
	var parsed map[string]any
	json.Unmarshal([]byte(tag[1]), &parsed) //nolint:errcheck
	if parsed["version"].(float64) != 1 {
		t.Errorf("expected version=1, got %v", parsed["version"])
	}
}

func TestNewAttestation_EvidenceAuthTypeIsPublicPost(t *testing.T) {
	event, _ := NewAttestation(makeAttestationParams())
	tag := findTag(event, TagEvidence)
	var parsed map[string]any
	json.Unmarshal([]byte(tag[1]), &parsed) //nolint:errcheck
	if parsed["auth_type"] != "public_post" {
		t.Errorf("expected auth_type='public_post', got %q", parsed["auth_type"])
	}
}

func TestNewAttestation_EvidenceFieldsRoundTrip(t *testing.T) {
	event, _ := NewAttestation(makeAttestationParams())
	tag := findTag(event, TagEvidence)
	var parsed map[string]any
	json.Unmarshal([]byte(tag[1]), &parsed) //nolint:errcheck

	if parsed["evidence_url"] != "https://gist.github.com/alice/abc123" {
		t.Errorf("unexpected evidence_url: %v", parsed["evidence_url"])
	}
	if parsed["challenge"] != "npv11qqsddvq9arp" {
		t.Errorf("unexpected challenge: %v", parsed["challenge"])
	}
	if parsed["user_id"] != "user42" {
		t.Errorf("unexpected user_id: %v", parsed["user_id"])
	}
	if parsed["username"] != "alice" {
		t.Errorf("unexpected username: %v", parsed["username"])
	}
	if parsed["verified_at"].(float64) != 1700000000 {
		t.Errorf("unexpected verified_at: %v", parsed["verified_at"])
	}
	if parsed["platform"] != "github" {
		t.Errorf("unexpected platform: %v", parsed["platform"])
	}
}

// Version/AuthType are not caller-settable — confirm a caller "trying" to
// override them has no effect, since Evidence has no such fields at all
// (this is enforced at compile time, but we still assert the wire output).
func TestNewAttestation_VersionAuthTypeAlwaysCanonical(t *testing.T) {
	p := makeAttestationParams()
	event, err := NewAttestation(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tag := findTag(event, TagEvidence)
	var parsed map[string]any
	json.Unmarshal([]byte(tag[1]), &parsed) //nolint:errcheck
	if parsed["version"].(float64) != 1 || parsed["auth_type"] != "public_post" {
		t.Error("version/auth_type must always be canonical, regardless of caller input")
	}
}

// ── Signing (new behavior — construction+signing is now one call) ──────────

func TestNewAttestation_IsSigned(t *testing.T) {
	event, err := NewAttestation(makeAttestationParams())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.ID == "" || event.Sig == "" {
		t.Error("expected NewAttestation to return an already-signed event")
	}
	if err := event.Verify(); err != nil {
		t.Errorf("expected a valid signature, got: %v", err)
	}
}

func TestNewAttestation_InvalidPrivateKeyErrors(t *testing.T) {
	p := makeAttestationParams()
	p.PrivateKey = "not-a-valid-key"
	if _, err := NewAttestation(p); err == nil {
		t.Error("expected error for invalid private key")
	}
}

// ── Expiration — ported from attestation_critical_test.go (A6) ─────────────

func TestNewAttestation_ExpirationPrecision(t *testing.T) {
	p := makeAttestationParams()
	p.ExpirationDays = 90

	beforeCreate := time.Now()
	event, err := NewAttestation(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	afterCreate := time.Now()

	expTag := findTag(event, TagExpiration)
	if expTag == nil {
		t.Fatal("missing expiration tag")
	}
	expTs, _ := strconv.ParseInt(expTag[1], 10, 64)
	expectedMin := beforeCreate.AddDate(0, 0, 90).Unix()
	expectedMax := afterCreate.AddDate(0, 0, 90).Unix()
	if expTs < expectedMin || expTs > expectedMax {
		t.Errorf("expiration %d not in expected range [%d, %d]", expTs, expectedMin, expectedMax)
	}
}

func TestNewAttestation_NoExpirationWhenZero(t *testing.T) {
	p := makeAttestationParams()
	p.ExpirationDays = 0

	event, err := NewAttestation(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag := findTag(event, TagExpiration); tag != nil {
		t.Errorf("expected no expiration tag when ExpirationDays=0, found: %v", tag)
	}
}

// ── NewAttestationRevocation (new — wasn't a testable public path before) ──

func TestNewAttestationRevocation(t *testing.T) {
	deletion, err := NewAttestationRevocation(testIAPrivKey, "some-attestation-event-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletion.Kind != KindAttestationRevocation {
		t.Errorf("expected kind %d, got %d", KindAttestationRevocation, deletion.Kind)
	}
	if err := deletion.Verify(); err != nil {
		t.Errorf("expected a validly signed deletion event, got: %v", err)
	}
	tag := findTag(deletion, TagEventRef)
	if tag == nil || tag[1] != "some-attestation-event-id" {
		t.Errorf("expected e-tag referencing the attestation, got: %v", tag)
	}
}

// ── ParseAttestation / ValidateAttestation ──────────────────────────────────
// Ported from zapf's internal/nostr/validator_identity_test.go 35522 cases
// (D4-D6, D11, D12, D15, C6, wrong-kind, missing-platform).

func signedAttestationEvent(t *testing.T, dValue string, extraTags ...[]string) *nip01.Event {
	t.Helper()
	tags := [][]string{
		{TagDTag, dValue},
		{TagRecipient, testUserPubKey},
		{TagPlatform, "discord"},
		{TagEvidence, `{"version":1,"platform":"discord","auth_type":"public_post","evidence_url":"https://discord.com/channels/1/2/3","challenge":"npv1qqpx9er9wehxumq78f5k4q8"}`},
	}
	tags = append(tags, extraTags...)
	evt := &nip01.Event{Kind: KindAttestation, Tags: tags}
	if err := evt.Sign(testIAPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return evt
}

const testConnKeyHex = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func TestParseAttestation_BareConnectionKeyPasses(t *testing.T) {
	evt := signedAttestationEvent(t, testConnKeyHex)
	att, err := ParseAttestation(evt)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if att.ConnectionKey != ConnectionKey(testConnKeyHex) {
		t.Errorf("unexpected ConnectionKey: %v", att.ConnectionKey)
	}
	if att.Platform != "discord" {
		t.Errorf("unexpected Platform: %v", att.Platform)
	}
	if att.UserPubkey != testUserPubKey {
		t.Errorf("unexpected UserPubkey: %v", att.UserPubkey)
	}
}

func TestParseAttestation_PlatformPrefixedDTagRejected(t *testing.T) {
	evt := signedAttestationEvent(t, "discord:"+testConnKeyHex)
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for platform-prefixed #d tag")
	}
}

func TestParseAttestation_MissingPTagRejected(t *testing.T) {
	evt := &nip01.Event{
		Kind: KindAttestation,
		Tags: [][]string{
			{TagDTag, testConnKeyHex},
			{TagPlatform, "discord"},
			{TagEvidence, "proof"},
		},
	}
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for missing p-tag")
	}
}

func TestParseAttestation_MissingEvidenceTagRejected(t *testing.T) {
	evt := &nip01.Event{
		Kind: KindAttestation,
		Tags: [][]string{
			{TagDTag, testConnKeyHex},
			{TagRecipient, testUserPubKey},
			{TagPlatform, "discord"},
		},
	}
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for missing evidence tag")
	}
}

func TestParseAttestation_MissingPlatformTagRejected(t *testing.T) {
	evt := &nip01.Event{
		Kind: KindAttestation,
		Tags: [][]string{
			{TagDTag, testConnKeyHex},
			{TagRecipient, testUserPubKey},
			{TagEvidence, `{"version":1}`},
		},
	}
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for missing platform tag")
	}
}

func TestParseAttestation_NilEventRejected(t *testing.T) {
	if _, err := ParseAttestation(nil); err == nil {
		t.Error("expected error for nil event")
	}
}

func TestParseAttestation_WrongKindRejected(t *testing.T) {
	evt := signedAttestationEvent(t, testConnKeyHex)
	evt.Kind = KindIdentityConnection
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for wrong kind (35521 passed as 35522)")
	}
}

func TestParseAttestation_ExpiredAttestationStructurallyValid(t *testing.T) {
	pastExp := strconv.FormatInt(time.Now().Add(-24*time.Hour).Unix(), 10)
	evt := signedAttestationEvent(t, testConnKeyHex, []string{TagExpiration, pastExp})
	att, err := ParseAttestation(evt)
	if err != nil {
		t.Fatalf("expired attestation should still pass structural validation, got: %v", err)
	}
	if att.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be populated")
	}
	if !att.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the past")
	}
}

func TestParseAttestation_NoExpirationTagValid(t *testing.T) {
	evt := signedAttestationEvent(t, testConnKeyHex)
	att, err := ParseAttestation(evt)
	if err != nil {
		t.Fatalf("attestation without expiration should be valid: %v", err)
	}
	if att.ExpiresAt != nil {
		t.Error("expected nil ExpiresAt when no expiration tag present")
	}
}

func TestParseAttestation_Npv1ChallengeInEvidenceValid(t *testing.T) {
	evt := signedAttestationEvent(t, testConnKeyHex)
	att, err := ParseAttestation(evt)
	if err != nil {
		t.Fatalf("npv1 challenge in evidence should pass validation, got: %v", err)
	}
	if att.Evidence.Challenge != "npv1qqpx9er9wehxumq78f5k4q8" {
		t.Errorf("unexpected Challenge: %v", att.Evidence.Challenge)
	}
}

func TestParseAttestation_ForgedSignatureRejected(t *testing.T) {
	evt := signedAttestationEvent(t, testConnKeyHex)
	evt.Tags = append(evt.Tags, []string{"extra", "tampered"}) // modify after signing
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for tampered event (invalid signature)")
	}
}

// New coverage: malformed evidence JSON is now caught by Parse (the old
// zapf validator only checked tag *presence*, not JSON validity).
func TestParseAttestation_MalformedEvidenceJSONRejected(t *testing.T) {
	evt := &nip01.Event{
		Kind: KindAttestation,
		Tags: [][]string{
			{TagDTag, testConnKeyHex},
			{TagRecipient, testUserPubKey},
			{TagPlatform, "discord"},
			{TagEvidence, "{not valid json"},
		},
	}
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseAttestation(evt); err == nil {
		t.Error("expected error for malformed evidence JSON")
	}
}

func TestValidateAttestation_MatchesParseAttestation(t *testing.T) {
	valid := signedAttestationEvent(t, testConnKeyHex)
	if err := ValidateAttestation(valid); err != nil {
		t.Errorf("expected valid attestation to pass, got: %v", err)
	}

	invalid := signedAttestationEvent(t, "discord:"+testConnKeyHex)
	if err := ValidateAttestation(invalid); err == nil {
		t.Error("expected platform-prefixed attestation to fail")
	}
}

// D-tag format coverage across several platform-prefix shapes.
func TestParseAttestation_DTagFormatCoverage(t *testing.T) {
	tests := []struct {
		name      string
		dValue    string
		wantError bool
	}{
		{"bare_hex_passes", testConnKeyHex, false},
		{"discord_prefix_fails", "discord:" + testConnKeyHex, true},
		{"telegram_prefix_fails", "telegram:" + testConnKeyHex, true},
		{"x_prefix_fails", "x:" + testConnKeyHex, true},
		{"github_prefix_fails", "github:" + testConnKeyHex, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := signedAttestationEvent(t, tt.dValue)
			_, err := ParseAttestation(evt)
			if tt.wantError && err == nil {
				t.Errorf("expected error for d-tag %q, got nil", tt.dValue)
			}
			if !tt.wantError && err != nil {
				t.Errorf("expected no error for d-tag %q, got: %v", tt.dValue, err)
			}
		})
	}
}
