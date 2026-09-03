package nipIC

import (
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// Ported from zapf's internal/nostr/validator_identity_test.go 35521 cases
// (D1, D2, wrong-kind, missing-d-tag, nil-event, forged-signature).

func signedIdentityConnectionEvent(t *testing.T, dValue string, extraTags ...[]string) *nip01.Event {
	t.Helper()
	tags := [][]string{
		{TagDTag, dValue},
		{TagPlatform, "discord"},
	}
	tags = append(tags, extraTags...)
	evt := &nip01.Event{Kind: KindIdentityConnection, Tags: tags}
	if err := evt.Sign(testIAPrivKey); err != nil {
		t.Fatalf("failed to sign event: %v", err)
	}
	return evt
}

func TestParseIdentityConnection_BareConnectionKeyPasses(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, testConnKeyHex)
	conn, err := ParseIdentityConnection(evt)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if conn.ConnectionKey != ConnectionKey(testConnKeyHex) {
		t.Errorf("unexpected ConnectionKey: %v", conn.ConnectionKey)
	}
	if conn.Platform != "discord" {
		t.Errorf("unexpected Platform: %v", conn.Platform)
	}
}

func TestParseIdentityConnection_PlatformPrefixedDTagRejected(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, fmt.Sprintf("discord:%s", testConnKeyHex))
	if _, err := ParseIdentityConnection(evt); err == nil {
		t.Error("expected error for 'discord:' prefixed d-tag")
	}
}

func TestParseIdentityConnection_WrongKindRejected(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, testConnKeyHex)
	evt.Kind = 1            // text note
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseIdentityConnection(evt); err == nil {
		t.Error("expected error for wrong kind")
	}
}

func TestParseIdentityConnection_MissingDTagRejected(t *testing.T) {
	evt := &nip01.Event{
		Kind: KindIdentityConnection,
		Tags: [][]string{{TagPlatform, "discord"}},
	}
	evt.Sign(testIAPrivKey) //nolint:errcheck
	if _, err := ParseIdentityConnection(evt); err == nil {
		t.Error("expected error for missing d-tag")
	}
}

func TestParseIdentityConnection_NilEventRejected(t *testing.T) {
	if _, err := ParseIdentityConnection(nil); err == nil {
		t.Error("expected error for nil event")
	}
}

func TestParseIdentityConnection_PrefixVariants(t *testing.T) {
	for _, prefix := range []string{"discord", "telegram", "x", "github", "email"} {
		t.Run(prefix+"_prefix_rejected", func(t *testing.T) {
			evt := signedIdentityConnectionEvent(t, prefix+":abc123def456")
			if _, err := ParseIdentityConnection(evt); err == nil {
				t.Errorf("expected error for %q prefixed d-tag", prefix)
			}
		})
	}
}

func TestParseIdentityConnection_ForgedSignatureRejected(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, testConnKeyHex)
	evt.Tags = append(evt.Tags, []string{"extra", "tampered"})
	if _, err := ParseIdentityConnection(evt); err == nil {
		t.Error("expected error for tampered event (invalid signature)")
	}
}

func TestValidateIdentityConnection_MatchesParseIdentityConnection(t *testing.T) {
	valid := signedIdentityConnectionEvent(t, testConnKeyHex)
	if err := ValidateIdentityConnection(valid); err != nil {
		t.Errorf("expected valid connection to pass, got: %v", err)
	}

	invalid := signedIdentityConnectionEvent(t, "discord:"+testConnKeyHex)
	if err := ValidateIdentityConnection(invalid); err == nil {
		t.Error("expected platform-prefixed connection to fail")
	}
}

// New coverage: AttestationRef parsing from e-tags (not covered by zapf's
// validator, which never parsed 35521 into a typed struct).
func TestParseIdentityConnection_AttestationRefs(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, testConnKeyHex,
		[]string{TagEventRef, "event-id-1", "wss://relay-one.example.com"},
		[]string{TagEventRef, "event-id-2", "wss://relay-two.example.com"},
	)
	conn, err := ParseIdentityConnection(evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conn.Attestations) != 2 {
		t.Fatalf("expected 2 attestation refs (multi-IA stacking), got %d", len(conn.Attestations))
	}
	if conn.Attestations[0].EventID != "event-id-1" || conn.Attestations[0].RelayURL != "wss://relay-one.example.com" {
		t.Errorf("unexpected first ref: %+v", conn.Attestations[0])
	}
	if conn.Attestations[1].EventID != "event-id-2" || conn.Attestations[1].RelayURL != "wss://relay-two.example.com" {
		t.Errorf("unexpected second ref: %+v", conn.Attestations[1])
	}
}

func TestParseIdentityConnection_NoAttestationRefsIsEmptyNotNilPanic(t *testing.T) {
	evt := signedIdentityConnectionEvent(t, testConnKeyHex)
	conn, err := ParseIdentityConnection(evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conn.Attestations) != 0 {
		t.Errorf("expected no attestation refs, got %d", len(conn.Attestations))
	}
}
