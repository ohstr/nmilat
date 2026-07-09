package nip19

import (
	"reflect"
	"testing"
)

const testPubkeyHex = "3bf0d7c7e6fa8d5c8a0f5a6b0c9d2e1f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d"
const testEventIDHex = "5e0a1e6a9a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d"

func TestEncodeDecodeProfileRoundTrip(t *testing.T) {
	relays := []string{"wss://relay.one.example", "wss://relay.two.example"}

	nprofile, err := EncodeProfile(testPubkeyHex, relays)
	if err != nil {
		t.Fatalf("EncodeProfile() failed: %v", err)
	}
	if len(nprofile) < 8 || nprofile[:8] != "nprofile" {
		t.Errorf("EncodeProfile() returned string without nprofile prefix: %v", nprofile)
	}

	got, err := DecodeProfile(nprofile)
	if err != nil {
		t.Fatalf("DecodeProfile() failed: %v", err)
	}
	if got.PublicKey != testPubkeyHex {
		t.Errorf("DecodeProfile() PublicKey = %v, want %v", got.PublicKey, testPubkeyHex)
	}
	if !reflect.DeepEqual(got.Relays, relays) {
		t.Errorf("DecodeProfile() Relays = %v, want %v", got.Relays, relays)
	}

	// DecodeNprofile stays backwards compatible with the pubkey-only accessor.
	pk, err := DecodeNprofile(nprofile)
	if err != nil {
		t.Fatalf("DecodeNprofile() failed: %v", err)
	}
	if pk != testPubkeyHex {
		t.Errorf("DecodeNprofile() = %v, want %v", pk, testPubkeyHex)
	}
}

func TestEncodeProfileNoRelays(t *testing.T) {
	nprofile, err := EncodeProfile(testPubkeyHex, nil)
	if err != nil {
		t.Fatalf("EncodeProfile() failed: %v", err)
	}

	got, err := DecodeProfile(nprofile)
	if err != nil {
		t.Fatalf("DecodeProfile() failed: %v", err)
	}
	if got.PublicKey != testPubkeyHex {
		t.Errorf("DecodeProfile() PublicKey = %v, want %v", got.PublicKey, testPubkeyHex)
	}
	if len(got.Relays) != 0 {
		t.Errorf("DecodeProfile() Relays = %v, want none", got.Relays)
	}
}

func TestEncodeDecodeEventRoundTrip(t *testing.T) {
	p := EventPointer{
		ID:     testEventIDHex,
		Relays: []string{"wss://relay.one.example"},
		Author: testPubkeyHex,
		Kind:   1,
	}

	nevent, err := EncodeEvent(p)
	if err != nil {
		t.Fatalf("EncodeEvent() failed: %v", err)
	}
	if len(nevent) < 6 || nevent[:6] != "nevent" {
		t.Errorf("EncodeEvent() returned string without nevent prefix: %v", nevent)
	}

	got, err := DecodeEvent(nevent)
	if err != nil {
		t.Fatalf("DecodeEvent() failed: %v", err)
	}
	if !reflect.DeepEqual(*got, p) {
		t.Errorf("DecodeEvent() = %+v, want %+v", *got, p)
	}
}

func TestEncodeDecodeEventMinimal(t *testing.T) {
	p := EventPointer{ID: testEventIDHex}

	nevent, err := EncodeEvent(p)
	if err != nil {
		t.Fatalf("EncodeEvent() failed: %v", err)
	}

	got, err := DecodeEvent(nevent)
	if err != nil {
		t.Fatalf("DecodeEvent() failed: %v", err)
	}
	if got.ID != testEventIDHex {
		t.Errorf("DecodeEvent() ID = %v, want %v", got.ID, testEventIDHex)
	}
	if got.Author != "" || got.Kind != 0 || len(got.Relays) != 0 {
		t.Errorf("DecodeEvent() expected empty optional fields, got %+v", got)
	}
}

func TestEncodeDecodeAddrRoundTrip(t *testing.T) {
	p := EntityPointer{
		Identifier: "my-article",
		PublicKey:  testPubkeyHex,
		Kind:       30023,
		Relays:     []string{"wss://relay.one.example"},
	}

	naddr, err := EncodeAddr(p)
	if err != nil {
		t.Fatalf("EncodeAddr() failed: %v", err)
	}
	if len(naddr) < 5 || naddr[:5] != "naddr" {
		t.Errorf("EncodeAddr() returned string without naddr prefix: %v", naddr)
	}

	got, err := DecodeAddr(naddr)
	if err != nil {
		t.Fatalf("DecodeAddr() failed: %v", err)
	}
	if !reflect.DeepEqual(*got, p) {
		t.Errorf("DecodeAddr() = %+v, want %+v", *got, p)
	}
}

func TestEncodeDecodeAddrEmptyIdentifier(t *testing.T) {
	p := EntityPointer{
		Identifier: "",
		PublicKey:  testPubkeyHex,
		Kind:       0,
	}

	naddr, err := EncodeAddr(p)
	if err != nil {
		t.Fatalf("EncodeAddr() failed: %v", err)
	}

	got, err := DecodeAddr(naddr)
	if err != nil {
		t.Fatalf("DecodeAddr() failed: %v", err)
	}
	if got.Identifier != "" || got.PublicKey != testPubkeyHex || got.Kind != 0 {
		t.Errorf("DecodeAddr() = %+v, want %+v", *got, p)
	}
}

func TestDecodeWrongPrefixRejected(t *testing.T) {
	nprofile, err := EncodeProfile(testPubkeyHex, nil)
	if err != nil {
		t.Fatalf("EncodeProfile() failed: %v", err)
	}

	if _, err := DecodeEvent(nprofile); err == nil {
		t.Error("expected DecodeEvent to reject an nprofile string")
	}
	if _, err := DecodeAddr(nprofile); err == nil {
		t.Error("expected DecodeAddr to reject an nprofile string")
	}
}

func TestEncodeEventInvalidID(t *testing.T) {
	if _, err := EncodeEvent(EventPointer{ID: "not-hex"}); err == nil {
		t.Error("EncodeEvent() expected error for invalid hex id, got nil")
	}
}

func TestEncodeAddrInvalidPubkey(t *testing.T) {
	if _, err := EncodeAddr(EntityPointer{Identifier: "x", PublicKey: "not-hex"}); err == nil {
		t.Error("EncodeAddr() expected error for invalid hex pubkey, got nil")
	}
}

func TestNormalizeToHexEvent(t *testing.T) {
	nevent, err := EncodeEvent(EventPointer{ID: testEventIDHex})
	if err != nil {
		t.Fatalf("EncodeEvent() failed: %v", err)
	}
	if got := NormalizeToHex(nevent); got != testEventIDHex {
		t.Errorf("NormalizeToHex() = %v, want %v", got, testEventIDHex)
	}
}
