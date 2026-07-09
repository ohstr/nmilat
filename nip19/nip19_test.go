package nip19

import (
	"testing"
)

func TestCheckPublicKey(t *testing.T) {
	tests := []struct {
		name      string
		pubKeyHex string
		wantErr   bool
	}{
		{
			name:      "valid public key",
			pubKeyHex: "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d",
			wantErr:   false,
		},
		{
			name:      "invalid public key - odd length",
			pubKeyHex: "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551",
			wantErr:   true,
		},
		{
			name:      "invalid public key - non hex",
			pubKeyHex: "zzf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckPublicKey(tt.pubKeyHex); (err != nil) != tt.wantErr {
				t.Errorf("CheckPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	pubKeyHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	npub, err := EncodePublicKey(pubKeyHex)
	if err != nil {
		t.Fatalf("EncodePublicKey() failed: %v", err)
	}

	// Verify prefix
	if len(npub) < 4 || npub[:4] != "npub" {
		t.Errorf("EncodePublicKey() returned string without npub prefix: %v", npub)
	}

	prefix, value, err := Decode(npub)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}

	if prefix != "npub" {
		t.Errorf("Decode() prefix = %v, want npub", prefix)
	}

	if valStr, ok := value.(string); ok {
		if valStr != pubKeyHex {
			t.Errorf("Decode() value = %v, want %v", valStr, pubKeyHex)
		}
	} else {
		t.Errorf("Decode() value type mismatch, want string, got %T", value)
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	privKeyHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	nsec, err := EncodePrivateKey(privKeyHex)
	if err != nil {
		t.Fatalf("EncodePrivateKey() failed: %v", err)
	}

	// Verify prefix
	if len(nsec) < 4 || nsec[:4] != "nsec" {
		t.Errorf("EncodePrivateKey() returned string without nsec prefix: %v", nsec)
	}

	prefix, value, err := Decode(nsec)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}

	if prefix != "nsec" {
		t.Errorf("Decode() prefix = %v, want nsec", prefix)
	}

	if valStr, ok := value.(string); ok {
		if valStr != privKeyHex {
			t.Errorf("Decode() value = %v, want %v", valStr, privKeyHex)
		}
	} else {
		t.Errorf("Decode() value type mismatch, want string, got %T", value)
	}
}

func TestEncodeDecodeNote(t *testing.T) {
	eventIDHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	note, err := EncodeNote(eventIDHex)
	if err != nil {
		t.Fatalf("EncodeNote() failed: %v", err)
	}

	// Verify prefix
	if len(note) < 4 || note[:4] != "note" {
		t.Errorf("EncodeNote() returned string without note prefix: %v", note)
	}

	prefix, value, err := Decode(note)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}

	if prefix != "note" {
		t.Errorf("Decode() prefix = %v, want note", prefix)
	}

	if valStr, ok := value.(string); ok {
		if valStr != eventIDHex {
			t.Errorf("Decode() value = %v, want %v", valStr, eventIDHex)
		}
	} else {
		t.Errorf("Decode() value type mismatch, want string, got %T", value)
	}
}

func TestDecodePublicKey(t *testing.T) {
	pubKeyHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	npub, err := EncodePublicKey(pubKeyHex)
	if err != nil {
		t.Fatalf("EncodePublicKey() failed: %v", err)
	}

	got, err := DecodePublicKey(npub)
	if err != nil {
		t.Fatalf("DecodePublicKey() failed: %v", err)
	}
	if got != pubKeyHex {
		t.Errorf("DecodePublicKey() = %v, want %v", got, pubKeyHex)
	}

	nsec, err := EncodePrivateKey(pubKeyHex)
	if err != nil {
		t.Fatalf("EncodePrivateKey() failed: %v", err)
	}
	if _, err := DecodePublicKey(nsec); err == nil {
		t.Error("expected DecodePublicKey to reject an nsec string")
	}
}

func TestDecodePrivateKey(t *testing.T) {
	privKeyHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	nsec, err := EncodePrivateKey(privKeyHex)
	if err != nil {
		t.Fatalf("EncodePrivateKey() failed: %v", err)
	}

	got, err := DecodePrivateKey(nsec)
	if err != nil {
		t.Fatalf("DecodePrivateKey() failed: %v", err)
	}
	if got != privKeyHex {
		t.Errorf("DecodePrivateKey() = %v, want %v", got, privKeyHex)
	}

	npub, err := EncodePublicKey(privKeyHex)
	if err != nil {
		t.Fatalf("EncodePublicKey() failed: %v", err)
	}
	if _, err := DecodePrivateKey(npub); err == nil {
		t.Error("expected DecodePrivateKey to reject an npub string")
	}
}

func TestDecodeNote(t *testing.T) {
	eventIDHex := "3bf0c63fcb934770658986504981f1d5e012ca301b5d172776899778ab00551d"

	note, err := EncodeNote(eventIDHex)
	if err != nil {
		t.Fatalf("EncodeNote() failed: %v", err)
	}

	got, err := DecodeNote(note)
	if err != nil {
		t.Fatalf("DecodeNote() failed: %v", err)
	}
	if got != eventIDHex {
		t.Errorf("DecodeNote() = %v, want %v", got, eventIDHex)
	}

	npub, err := EncodePublicKey(eventIDHex)
	if err != nil {
		t.Fatalf("EncodePublicKey() failed: %v", err)
	}
	if _, err := DecodeNote(npub); err == nil {
		t.Error("expected DecodeNote to reject an npub string")
	}
}

func TestCheckPrivateKeyErrors(t *testing.T) {
	_, err := EncodePrivateKey("invalid-hex")
	if err == nil {
		t.Error("EncodePrivateKey() expected error for invalid hex, got nil")
	}
}

func TestCheckPublicKeyErrors(t *testing.T) {
	_, err := EncodePublicKey("invalid-hex")
	if err == nil {
		t.Error("EncodePublicKey() expected error for invalid hex, got nil")
	}
}

func TestCheckNoteErrors(t *testing.T) {
	_, err := EncodeNote("invalid-hex")
	if err == nil {
		t.Error("EncodeNote() expected error for invalid hex, got nil")
	}
}

func TestDecodeErrors(t *testing.T) {
	// Invalid bech32
	_, _, err := Decode("invalid-bech32")
	if err == nil {
		t.Error("Decode() expected error for invalid bech32, got nil")
	}

	// Valid bech32 but unknown prefix (well, Decode doesn't error on unknown prefix immediately unless logic dictates,
	// but the function returns error for unknown tags at the end)
	// Let's try to construct a valid bech32 string with unknown prefix "unknown"
	// We can't easily construct a valid checksummed bech32 without the library, so we will skip complex fabrication
	// and rely on what we can pass.
}
