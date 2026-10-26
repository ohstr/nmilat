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

// LNSignedMessagePrefix is flnd's signed-message prefix: what a Flokicoin
// minting node's SignMessage prepends to a payload before double-SHA256-hashing
// and signing it. It is the prefix for lokicash1... tokens.
const LNSignedMessagePrefix = "Flokicoin Lightning Signed Message:"

// LndSignedMessagePrefix is lnd's signed-message prefix, the unqualified
// Bitcoin original. It is the prefix for satscash1... tokens.
const LndSignedMessagePrefix = "Lightning Signed Message:"

// SignedMessagePrefix returns the signed-message prefix a minter for hrp signs
// under, and false for an HRP with no known prefix. It reads the same table as
// ChainSignedMessagePrefix.
func SignedMessagePrefix(hrp string) (string, bool) {
	for _, row := range prefixTable {
		if row.hrp == hrp {
			return row.prefix, true
		}
	}
	return "", false
}

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
	// An HRP with no known prefix carries no valid provenance: a guessed prefix
	// would still recover some pubkey and name it as the minter.
	prefix, known := SignedMessagePrefix(t.HRP)
	if !known {
		return "", false
	}
	payload := MintPayload(t.HRP, t.WalletPubkey, *t.AttestedAmountMillis)
	digest := doubleSHA256([]byte(prefix + payload))
	pub, _, err := ecdsa.RecoverCompact(t.MintSignature, digest)
	if err != nil {
		return "", false
	}
	serialized := btcec.ToSerialized(pub)
	return hex.EncodeToString(serialized[:]), true
}
