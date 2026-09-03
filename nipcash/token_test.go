package nipcash

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/utils"
)

func randomKeyHex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

// generateTestKeypair returns a fresh (privKeyHex, pubKeyHex) pair — the
// same primitives BySigning/signingCredential use internally
// (btcec.NewPrivateKey, utils.GetPublicKey).
func generateTestKeypair(t *testing.T) (privKeyHex, pubKeyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privKeyHex = hex.EncodeToString(priv.Serialize())
	pubKeyHex, err = utils.GetPublicKey(privKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return privKeyHex, pubKeyHex
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	want := Token{
		HRP:          "lokicash",
		WalletPubkey: randomKeyHex(t),
		Secret:       randomKeyHex(t),
		RelayURLs:    []string{"wss://relay.one", "wss://relay.two"},
	}
	token, err := Encode(want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HRP != want.HRP || got.WalletPubkey != want.WalletPubkey || got.Secret != want.Secret {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
	}
	if len(got.RelayURLs) != 2 || got.RelayURLs[0] != want.RelayURLs[0] || got.RelayURLs[1] != want.RelayURLs[1] {
		t.Fatalf("relay urls mismatch: got %v", got.RelayURLs)
	}
	// Re-encoding a decoded token must reproduce the same bech32 string.
	again, err := Encode(got)
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if again != token {
		t.Fatalf("re-encode not byte-identical:\n got  %s\n want %s", again, token)
	}
}

func TestEncodeDecode_AnyHRP(t *testing.T) {
	for _, hrp := range []string{"lokicash", "satscash", "somethingelsecash"} {
		token, err := Encode(Token{HRP: hrp, WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t)})
		if err != nil {
			t.Fatalf("Encode(%q): %v", hrp, err)
		}
		got, err := Decode(token)
		if err != nil {
			t.Fatalf("Decode(%q token): %v", hrp, err)
		}
		if got.HRP != hrp {
			t.Fatalf("HRP mismatch: got %q, want %q", got.HRP, hrp)
		}
	}
}

func TestEncodeDecode_IdentityRequired(t *testing.T) {
	yes := true
	token, err := Encode(Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t), IdentityRequired: &yes})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.IdentityRequired == nil || !*got.IdentityRequired {
		t.Fatalf("IdentityRequired: got %v, want true", got.IdentityRequired)
	}
}

func TestEncodeDecode_MintProvenancePair(t *testing.T) {
	amount := uint64(21000)
	sig := make([]byte, mintSigLen)
	for i := range sig {
		sig[i] = byte(i)
	}
	token, err := Encode(Token{
		HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t),
		MintSignature: sig, AttestedAmountMillis: &amount,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.HasProvenance() {
		t.Fatal("expected provenance to survive round-trip")
	}
	if *got.AttestedAmountMillis != amount {
		t.Fatalf("amount mismatch: got %d, want %d", *got.AttestedAmountMillis, amount)
	}
}

func TestEncode_MintProvenanceHalfPairRejected(t *testing.T) {
	amount := uint64(1000)
	_, err := Encode(Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t), AttestedAmountMillis: &amount})
	if err == nil {
		t.Fatal("expected error for a lone attested amount with no signature")
	}
}

func TestDecode_MissingRequiredFields(t *testing.T) {
	// Encode a wallet pubkey only, no secret, by hand — Encode itself
	// refuses to build this, so construct the bech32 string directly to
	// exercise Decode's own missing-field check.
	pub, _ := hex.DecodeString(randomKeyHex(t))
	buf := []byte{tlvWalletPubkey, byte(len(pub))}
	buf = append(buf, pub...)
	bits5, err := bech32.ConvertBits(buf, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := bech32.Encode("lokicash", bits5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(token); err == nil {
		t.Fatal("expected error for a token missing its secret")
	}
}

func TestDecode_TruncatedTLV(t *testing.T) {
	if _, err := Decode("lokicash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"); err == nil {
		t.Fatal("expected error for garbage bech32 data")
	}
}
