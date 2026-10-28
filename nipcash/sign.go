package nipcash

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// SignToken signs t under scheme and returns it with MintSignature,
// AttestedAmountMillis (which the caller sets beforehand) and Scheme in place.
//
// It refuses a scheme/context mismatch (scheme 2 needs z, scheme 1 takes none), a
// token whose RelayURLs Encode would refuse (a blank or non-ASCII hint), and a
// signature that does not recover to expectedMinterXOnly (ErrSignerMismatch: a
// node of another coin, or the wrong key, fails here). Every error means "fail
// before commit": a Hub never issues an unsigned token.
func SignToken(t Token, scheme SignatureScheme, z *ZapContext, expectedMinterXOnly string, sign MintSigner) (Token, error) {
	if scheme != SchemeMintV1 && scheme != SchemeZapV1 {
		return Token{}, fmt.Errorf("%w: %d", ErrSchemeUnsupported, scheme)
	}
	for _, u := range t.RelayURLs {
		if credcodec.IsBlankHint(u) {
			return Token{}, fmt.Errorf("%w: %q", ErrBlankRelayHint, u)
		}
		if !credcodec.IsASCII(u) {
			return Token{}, fmt.Errorf("%w: %q", ErrNonASCIIRelayHint, u)
		}
	}
	prefix, ok := SignedMessagePrefix(strings.ToLower(t.HRP))
	if !ok {
		return Token{}, fmt.Errorf("nipcash: no signed-message prefix is known for hrp %q", t.HRP)
	}
	t.Scheme = scheme
	payload, err := ProvenancePayload(t, z)
	if err != nil {
		return Token{}, err
	}
	raw, err := sign(payload)
	if err != nil {
		return Token{}, fmt.Errorf("nipcash: sign token: %w", err)
	}
	sig, ok := normalizeRecovery(raw)
	if !ok {
		return Token{}, fmt.Errorf("%w: the signer returned no compact recoverable signature", ErrSignerMismatch)
	}
	minter, ok := recoverCompressed(sig, prefix, payload)
	if !ok {
		return Token{}, fmt.Errorf("%w: the signature recovers no key", ErrSignerMismatch)
	}
	if x, _ := MinterXOnly(minter); x != strings.ToLower(expectedMinterXOnly) {
		return Token{}, fmt.Errorf("%w: signed by %s, expected %s", ErrSignerMismatch, minter, expectedMinterXOnly)
	}
	t.MintSignature = sig
	return t, nil
}

// LocalMintSigner signs payloads with a local key under hrp's prefix (RFC 6979
// nonces, low S, header 31 + recid). For tests, fakes and vector exporters; a Hub
// signs through its node.
func LocalMintSigner(privHex, hrp string) (MintSigner, error) {
	prefix, ok := SignedMessagePrefix(strings.ToLower(hrp))
	if !ok {
		return nil, fmt.Errorf("nipcash: no signed-message prefix is known for hrp %q", hrp)
	}
	return localSigner(privHex, prefix)
}

// recoverCompressed recovers the signer of payload under prefix as a compressed
// key, hex.
func recoverCompressed(sig []byte, prefix, payload string) (string, bool) {
	pub, _, err := ecdsa.RecoverCompact(sig, doubleSHA256([]byte(prefix+payload)))
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(pub.SerializeCompressed()), true
}

// recoverWithDigest recovers a compressed key from a signature over a raw digest.
func recoverWithDigest(sig, digest []byte) (string, bool, error) {
	pub, compressed, err := ecdsa.RecoverCompact(sig, digest)
	if err != nil {
		return "", false, err
	}
	return hex.EncodeToString(pub.SerializeCompressed()), compressed, nil
}
