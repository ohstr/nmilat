package nip19

import (
	"errors"
	"strings"
	"testing"
)

// Vectors from the NIP-19 spec.
const (
	specPubHex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
	specNpub   = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
	specNsec   = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
)

func TestParsePublicKey_Accepts(t *testing.T) {
	nprofile, err := EncodeProfile(specPubHex, []string{"wss://r.example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"hex":       specPubHex,
		"upper hex": strings.ToUpper(specPubHex),
		"npub":      specNpub,
		"nprofile":  nprofile,
		"padded":    "  " + specNpub + "\n",
	} {
		got, err := ParsePublicKey(in)
		if err != nil || got != specPubHex {
			t.Errorf("%s: ParsePublicKey(%q) = %q, %v; want %q", name, in, got, err, specPubHex)
		}
	}
}

func TestParsePublicKey_Rejects(t *testing.T) {
	if _, err := ParsePublicKey(specNsec); !errors.Is(err, ErrPrivateKey) {
		t.Errorf("nsec: err = %v, want ErrPrivateKey", err)
	}
	note, err := EncodeNote(specPubHex)
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"empty":        "",
		"short hex":    specPubHex[:62],
		"long hex":     specPubHex + "00",
		"not hex":      strings.Repeat("z", 64),
		"off curve":    strings.Repeat("f", 64),
		"note":         note,
		"bad checksum": specNpub[:len(specNpub)-1] + "q",
	} {
		if got, err := ParsePublicKey(in); err == nil {
			t.Errorf("%s: ParsePublicKey(%q) = %q, want an error", name, in, got)
		}
	}
}
