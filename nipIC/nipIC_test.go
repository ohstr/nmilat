package nipIC

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ── ConnectionKey ──────────────────────────────────────────────────────────
// Ported from zapf's TestGenerateConnectionKey_Deterministic.

func TestNewConnectionKey_Deterministic(t *testing.T) {
	key1 := NewConnectionKey("discord", "123456")
	key2 := NewConnectionKey("discord", "123456")
	if key1 != key2 {
		t.Error("NewConnectionKey should be deterministic")
	}

	key3 := NewConnectionKey("discord", "999999")
	if key1 == key3 {
		t.Error("different external IDs should produce different keys")
	}

	key4 := NewConnectionKey("x", "123456")
	if key1 == key4 {
		t.Error("different platforms should produce different keys")
	}

	if len(key1.String()) != 64 {
		t.Errorf("ConnectionKey should be 64 hex chars, got %d", len(key1.String()))
	}
}

func TestNewConnectionKey_NoPredefinedPlatforms(t *testing.T) {
	// The whole point of the open-string design: a platform this package has
	// never heard of works exactly the same as a "known" one.
	key := NewConnectionKey("mastodon", "@alice@example.social")
	if key.String() == "" {
		t.Error("expected a non-empty key for an arbitrary platform string")
	}
	if key != NewConnectionKey("mastodon", "@alice@example.social") {
		t.Error("expected determinism for an arbitrary platform string too")
	}
}

// ── ChallengeToken ──────────────────────────────────────────────────────────
// Ported from zapf's pkg/nostr/challenge_token_test.go, adapted to the new
// public-contract API (NewChallenge/NewChallengeToken/Verify instead of raw
// Generate/Decode).

const (
	testPubkeyHex   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	altPubkeyHex    = "112233445566778899001122334455667788990011223344556677889900112233"
	testPreAuthCode = "abc123preauth"
	altPreAuthCode  = "xyz789preauth"
)

func TestNewChallengeToken_HasNpv1Prefix(t *testing.T) {
	token, err := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(string(token), "npv1") {
		t.Errorf("expected npv1 prefix, got: %s", token)
	}
}

func TestNewChallengeToken_DifferentPubkeysProduceDifferentTokens(t *testing.T) {
	t1, err := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t2, err := NewChallengeToken(altPubkeyHex, testPreAuthCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1 == t2 {
		t.Error("different pubkeys must produce different tokens")
	}
}

func TestNewChallengeToken_Deterministic(t *testing.T) {
	t1, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	t2, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if t1 != t2 {
		t.Error("same inputs must produce identical tokens")
	}
}

func TestNewChallengeToken_DifferentPreAuthCodeProducesDifferentToken(t *testing.T) {
	t1, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	t2, _ := NewChallengeToken(testPubkeyHex, altPreAuthCode)
	if t1 == t2 {
		t.Error("different pre-auth codes must produce different tokens")
	}
}

func TestNewChallengeToken_ReasonableLength(t *testing.T) {
	token, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	// bech32 of 34 TLV bytes ≈ 68 chars including prefix — fits in a
	// Twitter/GitHub bio (160 chars).
	if len(token) > 80 {
		t.Errorf("token must fit in a bio field, got len=%d: %s", len(token), token)
	}
}

func TestNewChallengeToken_InvalidPubkeyHex(t *testing.T) {
	if _, err := NewChallengeToken("not-hex!!", testPreAuthCode); err == nil {
		t.Error("expected error for invalid pubkey hex")
	}
}

// ── Verify (the primitive that never had a real caller before this package) ─

func TestChallengeToken_Verify_Success(t *testing.T) {
	token, err := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := token.Verify(testPubkeyHex, testPreAuthCode); err != nil {
		t.Errorf("expected verification to succeed, got: %v", err)
	}
}

func TestChallengeToken_Verify_WrongPubkeyFails(t *testing.T) {
	token, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err := token.Verify(altPubkeyHex, testPreAuthCode); err == nil {
		t.Error("expected verification to fail for a different pubkey")
	}
}

func TestChallengeToken_Verify_WrongPreAuthCodeFails(t *testing.T) {
	token, _ := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err := token.Verify(testPubkeyHex, altPreAuthCode); err == nil {
		t.Error("expected verification to fail for a different pre-auth code")
	}
}

func TestChallengeToken_Verify_MalformedTokenFails(t *testing.T) {
	if err := ChallengeToken("not-a-token-at-all").Verify(testPubkeyHex, testPreAuthCode); err == nil {
		t.Error("expected verification to fail for a malformed token")
	}
}

func TestChallengeToken_Verify_WrongPrefixFails(t *testing.T) {
	if err := ChallengeToken("nprofile1qqsxxx").Verify(testPubkeyHex, testPreAuthCode); err == nil {
		t.Error("expected verification to fail for a non-npv1 bech32 string")
	}
}

// Security properties — ported from challenge_token_test.go's replay-resistance
// section, expressed against Verify (the actual attack surface: an IA calling
// Verify on an evidence payload) instead of raw token equality.

func TestChallengeToken_AttackerCannotReplayAcrossSessions(t *testing.T) {
	attackerCode := "attacker-session-001"
	victimCode := "victim-session-002"

	victimToken, err := NewChallengeToken(testPubkeyHex, victimCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Attacker took a token minted for their own session and tries to pass
	// it off as proof for the victim's session (same pubkey, different code).
	attackerToken, _ := NewChallengeToken(testPubkeyHex, attackerCode)
	if err := attackerToken.Verify(testPubkeyHex, victimCode); err == nil {
		t.Error("attacker's token must not verify against the victim's session pre-auth code")
	}
	if attackerToken == victimToken {
		t.Error("tokens for different sessions must differ")
	}
}

func TestChallengeToken_AttackerCannotForgeVictimPubkey(t *testing.T) {
	// Attacker has their own valid token but tries to claim it proves
	// control of the victim's pubkey.
	attackerToken, _ := NewChallengeToken(altPubkeyHex, testPreAuthCode)
	if err := attackerToken.Verify(testPubkeyHex, testPreAuthCode); err == nil {
		t.Error("a token minted for one pubkey must not verify against a different pubkey")
	}
}

// ── NewChallenge (mint token + pre-auth code together) ──────────────────────

func TestNewChallenge_ReturnsVerifiableToken(t *testing.T) {
	token, preAuthCode, err := NewChallenge(testPubkeyHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if preAuthCode == "" {
		t.Fatal("expected a non-empty pre-auth code")
	}
	if len(preAuthCode) != 32 {
		t.Errorf("expected a 32-char hex pre-auth code, got %d chars: %q", len(preAuthCode), preAuthCode)
	}
	if err := token.Verify(testPubkeyHex, preAuthCode); err != nil {
		t.Errorf("expected the minted token to verify against its own pre-auth code, got: %v", err)
	}
}

func TestNewChallenge_DifferentCallsProduceDifferentCodes(t *testing.T) {
	_, code1, err := NewChallenge(testPubkeyHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, code2, err := NewChallenge(testPubkeyHex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code1 == code2 {
		t.Error("expected fresh randomness on each call, got identical pre-auth codes")
	}
}

func TestNewChallenge_InvalidPubkeyHex(t *testing.T) {
	if _, _, err := NewChallenge("not-hex!!"); err == nil {
		t.Error("expected error for invalid pubkey hex")
	}
}

// ── White-box: confirm the TLV really carries SHA256(pubkey||preAuthCode) ───
// (same-package test, exercising the unexported decode() the way
// challenge_token_test.go's TestGenerateChallengeToken_HashMatchesPubkeyAndPreAuthCode did.)

func TestChallengeToken_decode_MatchesRawHash(t *testing.T) {
	token, err := NewChallengeToken(testPubkeyHex, testPreAuthCode)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := token.decode()
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("expected a 32-byte session hash, got %d bytes", len(got))
	}

	pubkeyBytes, err := hex.DecodeString(testPubkeyHex)
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	h := sha256.New()
	h.Write(pubkeyBytes)
	h.Write([]byte(testPreAuthCode))
	want := h.Sum(nil)

	if string(got) != string(want) {
		t.Error("decoded session hash must equal SHA256(pubkey || preAuthCode)")
	}
}
