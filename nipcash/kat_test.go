package nipcash

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/nipIC"
)

// Frozen known-answer vectors. Each value was computed outside the code under
// test, so a change to a prefix, separator, payload scheme or kind number turns
// these red instead of moving both sides of a round trip together.

// Private key 0x11 repeated 32 times; its compressed pubkey is the minter.
const (
	katMinter = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
	// MintPayload(hrp, 0x22 x 32, 21000) signed under each backend's prefix.
	katLokicashSig = "20c72cfbb8e8566000d6d90904c0c04fd047ce066dd599ede34c84dfb314f3126709ad9a50800f285c90a9683f8282b268a8bb85f8b7a9599f9b4482cbfd83b508"
	katSatscashSig = "1fcae9f6586ffbf8b1ee7e71eb3a531fc605573f2e04934899040d5237ef7280ad0a75647a2ebf91a982a93aaeaba324768e8b3a28e137bec9570d7f7e9d559b6c"
)

// NIP-CASH §Mint Provenance: pins the payload scheme, flnd's and lnd's prefixes,
// and the double-SHA256 digest.
func TestKAT_MintProvenance(t *testing.T) {
	wallet := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	amount := uint64(21000)
	if got, want := MintPayload("lokicash", wallet, amount), "lokicash-mint:v1:lokicash:"+wallet+":21000"; got != want {
		t.Fatalf("MintPayload = %q, want %q", got, want)
	}
	for hrp, sigHex := range map[string]string{"lokicash": katLokicashSig, "satscash": katSatscashSig} {
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := VerifyProvenance(Token{HRP: hrp, WalletPubkey: wallet, MintSignature: sig, AttestedAmountMillis: &amount, Scheme: SchemeMintV1})
		if !ok || got != katMinter {
			t.Errorf("%s vector: VerifyProvenance = (%s, %v), want (%s, true)", hrp, got, ok, katMinter)
		}
	}
}

// NIP-CASH §Terminology: a connection_key's identity_value is
// hex(SHA256(platform + ":" + externalID)). Value from `printf 'github:12345' | sha256sum`.
func TestKAT_ConnectionKey(t *testing.T) {
	const want = "2db75fb4d7a8e3005aca09c643b4e6f40142ddcfc18c675509988c1b111d0dcf"
	if got := string(nipIC.NewConnectionKey("github", "12345")); got != want {
		t.Fatalf("NewConnectionKey(github, 12345) = %s, want %s", got, want)
	}
}

// NIP-CASH §Methods: the claim proof is kind 23198, defined nowhere else.
func TestKAT_KindClaimProof(t *testing.T) {
	if KindClaimProof != 23198 {
		t.Fatalf("KindClaimProof = %d, want 23198", KindClaimProof)
	}
}

// NIP-CASH §The Cash Token: a decoder MUST ignore a TLV of an unrecognized type,
// including the reserved type 4, rather than reject the token.
func TestDecode_IgnoresUnknownTLVTypes(t *testing.T) {
	pub := bytes.Repeat([]byte{0x22}, 32)
	secret := bytes.Repeat([]byte{0x33}, 32)
	relay := []byte("wss://r.example")
	var buf bytes.Buffer
	for _, tlv := range []struct {
		typ   byte
		value []byte
	}{
		{tlvWalletPubkey, pub}, {4, []byte{1, 2, 3}}, {tlvRelay, relay}, {200, []byte("future")}, {tlvSecret, secret},
	} {
		buf.WriteByte(tlv.typ)
		buf.WriteByte(byte(len(tlv.value)))
		buf.Write(tlv.value)
	}
	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := bech32.Encode("lokicash", bits5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(s)
	if err != nil {
		t.Fatalf("Decode rejected a token carrying unknown TLVs: %v", err)
	}
	if got.WalletPubkey != hex.EncodeToString(pub) || got.Secret != hex.EncodeToString(secret) ||
		len(got.RelayURLs) != 1 || got.RelayURLs[0] != string(relay) {
		t.Fatalf("decoded %+v, want the known fields intact", got)
	}
}

// NIP-CASH §Terminology: implementations MUST reject `bearer` as an unknown
// identity type, so a roster row typed `bearer` is never matched as cash-mode.
func TestMatchClaimAuto_BearerIsNotCash(t *testing.T) {
	rows := []RecipientStatus{{IdentityType: "bearer", AmountMillis: 1000}}
	if r, ok := MatchClaimAuto(rows, NoLocalIdentity); ok {
		t.Fatalf("a bearer row matched: %+v", r)
	}
}
