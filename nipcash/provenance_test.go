package nipcash

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	btcec "github.com/flokiorg/go-flokicoin/crypto"
)

func signProvenance(t *testing.T, priv *btcec.PrivateKey, hrp, walletPubkeyHex string, amountMillis uint64) []byte {
	t.Helper()
	payload := MintPayload(hrp, walletPubkeyHex, amountMillis)
	digest := doubleSHA256([]byte(LNSignedMessagePrefix + payload))
	return ecdsa.SignCompact(priv, digest, true)
}

func TestVerifyProvenance_HappyPath(t *testing.T) {
	priv, pub := btcec.PrivKeyFromBytes([]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})
	walletPubkey := randomKeyHex(t)
	amount := uint64(40000)
	sig := signProvenance(t, priv, "lokicash", walletPubkey, amount)

	token := Token{HRP: "lokicash", WalletPubkey: walletPubkey, Secret: randomKeyHex(t), MintSignature: sig, AttestedAmountMillis: &amount}
	recovered, ok := VerifyProvenance(token)
	if !ok {
		t.Fatal("expected VerifyProvenance to succeed")
	}
	serialized := btcec.ToSerialized(pub)
	wantPubkeyHex := hex.EncodeToString(serialized[:])
	if recovered != wantPubkeyHex {
		t.Fatalf("recovered pubkey mismatch: got %s, want %s", recovered, wantPubkeyHex)
	}
}

func TestVerifyProvenance_NoProvenance(t *testing.T) {
	token := Token{HRP: "lokicash", WalletPubkey: randomKeyHex(t), Secret: randomKeyHex(t)}
	if _, ok := VerifyProvenance(token); ok {
		t.Fatal("expected no provenance to fail verification")
	}
}

// TestVerifyProvenance_ForgeryTable checks the real security invariant: a
// tampered token NEVER recovers the true signer's pubkey. RecoverCompact
// mathematically recovers *some* valid pubkey from any well-formed
// signature+digest pair — that's the whole point of a recoverable signature
// — so tampering the payload does NOT generally make ok false; it makes the
// recovered pubkey wrong. Only a structurally malformed signature (wrong
// length) fails outright.
func TestVerifyProvenance_ForgeryTable(t *testing.T) {
	priv, pub := btcec.PrivKeyFromBytes([]byte{
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
	})
	otherPriv, _ := btcec.PrivKeyFromBytes([]byte{
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
		81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
	})
	walletPubkey := randomKeyHex(t)
	otherWalletPubkey := randomKeyHex(t)
	amount := uint64(21000)
	sig := signProvenance(t, priv, "lokicash", walletPubkey, amount)

	serialized := btcec.ToSerialized(pub)
	trueSignerHex := hex.EncodeToString(serialized[:])

	cases := []struct {
		name           string
		token          Token
		wantVerifyFail bool // true only for structurally malformed signatures
	}{
		{"tampered amount", Token{HRP: "lokicash", WalletPubkey: walletPubkey, MintSignature: sig, AttestedAmountMillis: uint64Ptr(amount + 1)}, false},
		{"tampered wallet pubkey", Token{HRP: "lokicash", WalletPubkey: otherWalletPubkey, MintSignature: sig, AttestedAmountMillis: &amount}, false},
		{"tampered hrp", Token{HRP: "satscash", WalletPubkey: walletPubkey, MintSignature: sig, AttestedAmountMillis: &amount}, false},
		{"cross-token signature reuse", Token{HRP: "lokicash", WalletPubkey: otherWalletPubkey, MintSignature: sig, AttestedAmountMillis: &amount}, false},
		{"signature from a different signer entirely", Token{
			HRP: "lokicash", WalletPubkey: walletPubkey,
			MintSignature:        signProvenance(t, otherPriv, "lokicash", walletPubkey, amount),
			AttestedAmountMillis: &amount,
		}, false},
		{"malformed signature length", Token{HRP: "lokicash", WalletPubkey: walletPubkey, MintSignature: []byte{1, 2, 3}, AttestedAmountMillis: &amount}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recovered, ok := VerifyProvenance(tc.token)
			if tc.wantVerifyFail {
				if ok {
					t.Fatalf("expected verification to fail outright, recovered %s", recovered)
				}
				return
			}
			if ok && recovered == trueSignerHex {
				t.Fatalf("tampered token must never recover the true signer (%s)", trueSignerHex)
			}
		})
	}
}

func uint64Ptr(v uint64) *uint64 { return &v }

// signUnder signs a mint payload under an explicit signed-message prefix, the way
// a minter on that backend would.
func signUnder(t *testing.T, priv *btcec.PrivateKey, prefix, hrp, walletPubkeyHex string, amountMillis uint64) []byte {
	t.Helper()
	return ecdsa.SignCompact(priv, doubleSHA256([]byte(prefix+MintPayload(hrp, walletPubkeyHex, amountMillis))), true)
}

// NIP-CASH §Mint Provenance: the prefix comes from the token's own HRP, so a
// satscash1... token verifies under lnd's prefix and recovers its real minter.
func TestVerifyProvenance_SatscashUsesLndPrefix(t *testing.T) {
	priv, pub := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	serialized := btcec.ToSerialized(pub)
	want := hex.EncodeToString(serialized[:])
	wallet := randomKeyHex(t)
	amount := uint64(5000)
	tok := Token{HRP: "satscash", WalletPubkey: wallet, AttestedAmountMillis: &amount,
		MintSignature: signUnder(t, priv, "Lightning Signed Message:", "satscash", wallet, amount)}
	got, ok := VerifyProvenance(tok)
	if !ok || got != want {
		t.Fatalf("satscash token signed under lnd's prefix: got (%s, %v), want (%s, true)", got, ok, want)
	}
}

// NIP-CASH §Mint Provenance: an HRP with no known prefix carries no valid
// provenance, rather than a guess that names whatever key happens to recover.
func TestVerifyProvenance_UnknownHRPHasNoProvenance(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{9}, 32))
	wallet := randomKeyHex(t)
	amount := uint64(5000)
	for _, prefix := range []string{"Flokicoin Lightning Signed Message:", "Lightning Signed Message:"} {
		tok := Token{HRP: "xyzcash", WalletPubkey: wallet, AttestedAmountMillis: &amount,
			MintSignature: signUnder(t, priv, prefix, "xyzcash", wallet, amount)}
		if got, ok := VerifyProvenance(tok); ok {
			t.Fatalf("xyzcash token (signed under %q) verified with minter %s; want no provenance", prefix, got)
		}
	}
}
