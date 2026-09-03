package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	btcec "github.com/flokiorg/go-flokicoin/crypto"
)

// mintPayloadScheme is the fixed, versioned tag prefixing every mint-
// signature payload, regardless of coin/HRP. Bumping the version invalidates
// old signatures deliberately.
const mintPayloadScheme = "lokicash-mint:v1"

// LNSignedMessagePrefix is the context prefix a minting node's own
// SignMessage call prepends to a payload before double-SHA256-hashing and
// signing it. VerifyProvenance MUST reproduce this exact prefixing to
// recover the signer.
//
// This is a real, documented limitation, not a universal guarantee: NIP-CASH
// itself doesn't mandate a digest convention for how a minting node signs —
// only that the signature is recoverable ECDSA over MintPayload's canonical
// string. This constant matches the one real minter implementation this
// package was built against (lokihub, backed by flnd — an LND-style node
// whose SignMessage RPC prepends "Flokicoin Lightning Signed Message:"
// before hashing). A minter on a different Lightning backend with a
// different SignMessage convention would produce a signature
// VerifyProvenance can't recover, even though the token itself is otherwise
// perfectly valid and spendable — mint-signature verification is best-effort
// provenance, never a spending credential, exactly as NIP-CASH §Mint
// Provenance describes.
const LNSignedMessagePrefix = "Flokicoin Lightning Signed Message:"

// MintPayload returns the canonical ASCII string a mint signature commits to
// (NIP-CASH §Mint Provenance):
// "lokicash-mint:v1:<hrp>:<wallet_pubkey_hex>:<amount_millis>". A minter
// signs this at mint time; VerifyProvenance recomputes it from a token's own
// fields, so both sides MUST use this one function, never hand-build the
// string, to stay byte-identical.
func MintPayload(hrp, walletPubkeyHex string, amountMillis uint64) string {
	return mintPayloadScheme + ":" + hrp + ":" + walletPubkeyHex + ":" + strconv.FormatUint(amountMillis, 10)
}

// doubleSHA256 is the Bitcoin-family "hash a message twice" convention
// (equivalent to btcsuite/decred's chainhash.DoubleHashB) — implemented
// directly rather than pulling in a whole chainhash-style dependency for
// one two-line function.
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// VerifyProvenance recovers the minting node's Lightning pubkey (compressed,
// hex) from a token's mint-provenance pair, verifying it against the
// token's own payload. It returns the recovered pubkey and true only when
// the token carries a complete, well-formed pair whose signature recovers
// cleanly; otherwise "", false — for a token with no provenance at all, or
// one whose signature doesn't verify.
//
// VerifyProvenance does NOT decide trust: it answers "who signed this," not
// "should I trust them." The caller compares the returned pubkey against
// whichever minter it expects (e.g. a locally-configured trusted-minter
// list). The signature proves origin and denomination only — it is never a
// spending credential.
func VerifyProvenance(t Token) (minterPubkeyHex string, ok bool) {
	if !t.HasProvenance() {
		return "", false
	}
	if len(t.MintSignature) != mintSigLen {
		return "", false
	}
	payload := MintPayload(t.HRP, t.WalletPubkey, *t.AttestedAmountMillis)
	digest := doubleSHA256([]byte(LNSignedMessagePrefix + payload))
	pub, _, err := ecdsa.RecoverCompact(t.MintSignature, digest)
	if err != nil {
		return "", false
	}
	serialized := btcec.ToSerialized(pub)
	return hex.EncodeToString(serialized[:]), true
}
