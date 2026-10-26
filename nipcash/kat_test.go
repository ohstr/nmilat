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

// T04-05: a signature over the removed lokicash-mint:v1:<hrp>:<wallet>:<amount>
// payload carries no provenance: without TLV 8 the decoder marks the set
// malformed, and with TLV 8 = 1 it is a signature over another text.
func TestT04_05_RemovedPayloadHasNoProvenance(t *testing.T) {
	wallet := hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	amount := uint64(21000)
	sign, err := LocalMintSigner(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), "lokicash")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign("lokicash-mint:v1:lokicash:" + wallet + ":21000")
	if err != nil {
		t.Fatal(err)
	}
	tok := Token{HRP: "lokicash", WalletPubkey: wallet, Secret: hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
		RelayURLs: []string{"wss://r.example"}, MintSignature: sig, AttestedAmountMillis: &amount, Scheme: SchemeMintV1}
	minter := "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa" // key 0x11 x 32
	if m, _ := VerifyProvenance(tok); m == minter {
		t.Fatal("a signature over the removed payload recovered the minter under cash-mint:v1")
	}
	var buf bytes.Buffer
	pub, _ := hex.DecodeString(wallet)
	sec, _ := hex.DecodeString(tok.Secret)
	writeTLV(&buf, tlvWalletPubkey, pub)
	writeTLV(&buf, tlvRelay, []byte("wss://r.example"))
	writeTLV(&buf, tlvSecret, sec)
	writeTLV(&buf, tlvMintSignature, sig)
	amt := []byte{0, 0, 0, 0, 0, 0, 0x52, 0x08}
	writeTLV(&buf, tlvAttestedAmount, amt)
	bits5, _ := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	s, _ := bech32.Encode("lokicash", bits5)
	got, err := Decode(s)
	if err != nil || got.Scheme != SchemeMalformed || got.HasProvenance() {
		t.Fatalf("no TLV 8: scheme %d err %v", got.Scheme, err)
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
