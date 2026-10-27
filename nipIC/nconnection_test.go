package nipIC

import (
	"encoding/hex"
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

// T05-15 (K-NCN-1), T05-16.
func TestT05_15_NConnection(t *testing.T) {
	const key = ConnectionKey("22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d")
	const want = "nconnection1qqsz9nk30lrm8fhhyckjm0sqksknq22gt92x3cp97sujkzjsy2urr8gpzamhxue69uhhyetvv9ujuetcv9khqmr99e3k7mgzqajxjumrdaexg6u9jzw"
	s, err := EncodeNConnection(key, []string{"wss://relay.example.com"}, "discord")
	if err != nil || s != want {
		t.Fatalf("K-NCN-1: %s %v", s, err)
	}
	k, relays, p, err := DecodeNConnection(want)
	if err != nil || k != key || len(relays) != 1 || p != "discord" {
		t.Fatalf("decode: %v", err)
	}
	keyBytes, _ := hex.DecodeString(string(key))
	tlv := func(typ byte, v []byte) []byte { return append([]byte{typ, byte(len(v))}, v...) }
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	if _, _, _, err := DecodeNConnection(encodeNpvString(t, NConnectionPrefix, cat(tlv(0, keyBytes), tlv(3, []byte("x")), tlv(255, nil)))); err != nil {
		t.Errorf("unknown types: %v", err)
	}
	for name, data := range map[string][]byte{
		"no type 0":      tlv(1, []byte("wss://r")),
		"two type 0":     cat(tlv(0, keyBytes), tlv(0, keyBytes)),
		"two type 2":     cat(tlv(0, keyBytes), tlv(2, []byte("x")), tlv(2, []byte("y"))),
		"31-byte type 0": tlv(0, keyBytes[:31]),
		"overrun":        cat(tlv(0, keyBytes), []byte{1, 9, 'a'}),
		"Discord":        cat(tlv(0, keyBytes), tlv(2, []byte("Discord"))),
		"git:hub":        cat(tlv(0, keyBytes), tlv(2, []byte("git:hub"))),
	} {
		if _, _, _, err := DecodeNConnection(encodeNpvString(t, NConnectionPrefix, data)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	for name, f := range map[string]func() error{
		"bad platform": func() error { _, err := EncodeNConnection(key, nil, "Discord"); return err },
		"non-ASCII":    func() error { _, err := EncodeNConnection(key, []string{"wss://ü"}, ""); return err },
		"uppercase":    func() error { _, err := EncodeNConnection(ConnectionKey("A"+string(key)[1:]), nil, ""); return err },
	} {
		if f() == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}
