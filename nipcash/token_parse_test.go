package nipcash

import (
	"errors"
	"strings"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// signedTokenAndData is a signed satscash token on relays, and its decoded data bytes.
func signedTokenAndData(t *testing.T, relays ...string) (string, []byte) {
	t.Helper()
	amt := uint64(21000)
	tok := Token{HRP: "satscash", WalletPubkey: strings.Repeat("22", 32), Secret: strings.Repeat("33", 32),
		RelayURLs: relays, AttestedAmountMillis: &amt}
	sign, err := LocalMintSigner(strings.Repeat("01", 32), "satscash")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignToken(tok, SchemeMintV1, nil, "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", sign)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	_, words, err := bech32.DecodeNoLimit(s)
	if err != nil {
		t.Fatal(err)
	}
	data, err := bech32.ConvertBits(words, 5, 8, false)
	if err != nil {
		t.Fatal(err)
	}
	return s, data
}

func satscashFromWords(t *testing.T, words []byte) string {
	t.Helper()
	s, err := bech32.Encode("satscash", words)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func satscashFromData(t *testing.T, data []byte) string {
	t.Helper()
	w, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	return satscashFromWords(t, w)
}

// NIP-CASH §Wire Format: malformed, mis-padded, mixed-case, repeated or trailing input never decodes into a bill
// other than the one encoded; the uppercase form, an unknown TLV and a token past 1023 characters still decode.
func TestDecode_NoInputDecodesToAnotherBill(t *testing.T) {
	s, data := signedTokenAndData(t, "wss://relay.example.com")
	_, words, _ := bech32.DecodeNoLimit(s)

	refuse := map[string]string{}
	// Non-zero padding bits, and an extra all-zero group: BIP-173 refuses both.
	if bits := len(data) * 8; bits%5 != 0 {
		w := append([]byte(nil), words...)
		w[len(w)-1] |= 1
		refuse["non-zero padding"] = satscashFromWords(t, w)
	}
	refuse["excess padding group"] = satscashFromWords(t, append(append([]byte(nil), words...), 0))
	refuse["mixed case in the hrp only"] = "Satscash" + s[len("satscash"):]
	refuse["mixed case in the data only"] = s[:len(s)-1] + strings.ToUpper(s[len(s)-1:])
	refuse["one trailing byte"] = satscashFromData(t, append(append([]byte(nil), data...), 9))
	refuse["truncated value"] = satscashFromData(t, append(append([]byte(nil), data...), 9, 5, 1))
	refuse["second secret"] = satscashFromData(t, append(append([]byte(nil), data...), append([]byte{2, 32}, make([]byte, 32)...)...))
	refuse["second wallet pubkey"] = satscashFromData(t, append(append([]byte(nil), data...), append([]byte{0, 32}, make([]byte, 32)...)...))
	refuse["lookalike unicode"] = strings.Replace(s, "q", "ԛ", 1)
	refuse["bech32m checksum"] = func() string {
		out, err := bech32.EncodeM("satscash", words)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}()
	if _, ok := refuse["non-zero padding"]; !ok {
		t.Fatal("setup: the token has no padding bits to flip")
	}
	for name, in := range refuse {
		if tok, err := Decode(in); err == nil {
			t.Errorf("%s: decoded to %+v, want a refusal", name, tok.WalletPubkey)
		}
	}
	if _, err := Decode(refuse["mixed case in the hrp only"]); !errors.Is(err, ErrMixedCase) {
		t.Errorf("mixed-case hrp: err = %v, want ErrMixedCase", err)
	}

	// Accepted: the uppercase form, and an unknown trailing TLV; both still the same bill, provenance intact.
	for name, in := range map[string]string{"uppercase": strings.ToUpper(s), "unknown TLV 9": satscashFromData(t, append(append([]byte(nil), data...), 9, 1, 0))} {
		tok, err := Decode(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := VerifyProvenance(tok); !ok || tok.WalletPubkey != strings.Repeat("22", 32) || tok.HRP != "satscash" {
			t.Errorf("%s: not the same verifying bill", name)
		}
	}

	// No 90-character limit: a token far past 1023 characters decodes.
	var relays []string
	for i := 0; i < 12; i++ {
		relays = append(relays, "wss://relay-"+strings.Repeat("x", 60)+".example.com")
	}
	long, _ := signedTokenAndData(t, relays...)
	if len(long) < 1100 {
		t.Fatalf("setup: token only %d characters", len(long))
	}
	if tok, err := Decode(long); err != nil || len(tok.RelayURLs) != 12 {
		t.Errorf("long token (%d chars): err = %v", len(long), err)
	}
}
