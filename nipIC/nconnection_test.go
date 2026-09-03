package nipIC

import (
	"strings"
	"testing"
)

// Ported from bot/pkg/nconnection/nconnection_test.go — same TLV wire
// format, now exercised through the SDK's typed ConnectionKey/WebIdentity.

func TestEncodeDecodeNConnection_Roundtrip(t *testing.T) {
	key := ConnectionKey("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	relays := []string{"wss://relay.zapf.app/v1", "wss://relay.damus.io"}

	encoded, err := EncodeNConnection(key, relays, "discord")
	if err != nil {
		t.Fatalf("EncodeNConnection failed: %v", err)
	}
	if !strings.HasPrefix(encoded, NConnectionPrefix+"1") {
		t.Errorf("expected prefix %q, got %q", NConnectionPrefix+"1", encoded[:len(NConnectionPrefix)+1])
	}

	gotKey, gotRelays, gotPlatform, err := DecodeNConnection(encoded)
	if err != nil {
		t.Fatalf("DecodeNConnection failed: %v", err)
	}
	if gotKey != key {
		t.Errorf("key mismatch: got %q, want %q", gotKey, key)
	}
	if len(gotRelays) != 2 || gotRelays[0] != relays[0] || gotRelays[1] != relays[1] {
		t.Errorf("relay mismatch: got %v, want %v", gotRelays, relays)
	}
	if gotPlatform != "discord" {
		t.Errorf("platform mismatch: got %q, want %q", gotPlatform, "discord")
	}
}

func TestEncodeNConnection_NoRelaysNoPlatform(t *testing.T) {
	key := ConnectionKey("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")

	encoded, err := EncodeNConnection(key, nil, "")
	if err != nil {
		t.Fatalf("EncodeNConnection failed: %v", err)
	}
	gotKey, gotRelays, gotPlatform, err := DecodeNConnection(encoded)
	if err != nil {
		t.Fatalf("DecodeNConnection failed: %v", err)
	}
	if gotKey != key {
		t.Errorf("key mismatch: got %q, want %q", gotKey, key)
	}
	if len(gotRelays) != 0 {
		t.Errorf("expected 0 relays, got %d", len(gotRelays))
	}
	if gotPlatform != "" {
		t.Errorf("expected empty platform, got %q", gotPlatform)
	}
}

func TestEncodeNConnection_ArbitraryPlatformNames(t *testing.T) {
	// No predefined platform set — anything round-trips, including ones this
	// package has never heard of.
	key := ConnectionKey("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	for _, platform := range []WebIdentity{"discord", "telegram", "mastodon", "some-future-platform"} {
		encoded, err := EncodeNConnection(key, nil, platform)
		if err != nil {
			t.Fatalf("EncodeNConnection failed for %s: %v", platform, err)
		}
		_, _, gotPlatform, err := DecodeNConnection(encoded)
		if err != nil {
			t.Fatalf("DecodeNConnection failed for %s: %v", platform, err)
		}
		if gotPlatform != platform {
			t.Errorf("platform mismatch for %s: got %q", platform, gotPlatform)
		}
	}
}

func TestEncodeNConnection_InvalidKeyLength(t *testing.T) {
	if _, err := EncodeNConnection(ConnectionKey("abcd"), nil, ""); err == nil {
		t.Error("expected error for short key")
	}
}

func TestDecodeNConnection_WrongPrefix(t *testing.T) {
	key := ConnectionKey("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	encoded, _ := EncodeNConnection(key, nil, "")

	tampered := "npub1" + encoded[len(NConnectionPrefix)+1:]
	if _, _, _, err := DecodeNConnection(tampered); err == nil {
		t.Error("expected error for wrong prefix")
	}
}

func TestDecodeNConnection_InvalidBech32(t *testing.T) {
	if _, _, _, err := DecodeNConnection("not-bech32-at-all!!"); err == nil {
		t.Error("expected error for invalid bech32")
	}
}
