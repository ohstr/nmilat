package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// The fixed labels of the connection signatures (NIP-CASH §Connection
// Signatures), chosen by the string's HRP.
const (
	ConnLabelCashHub   = "cash-hub:v1"
	ConnLabelCashOrder = "cash-order:v1"
	ConnLabelCircleHub = "circle-hub:v1"
)

var connLabels = map[string]string{
	CashHubConnectionHRP: ConnLabelCashHub,
	"cashorder":          ConnLabelCashOrder,
	"circlehub":          ConnLabelCircleHub,
}

var (
	// ErrConnUnsigned is a connection string whose TLV 4 (Hub identity) or TLV 5
	// (connection signature) is missing, repeated or of the wrong length.
	ErrConnUnsigned = credcodec.ErrConnUnsigned
	// ErrChainName is a TLV 6 that is missing, repeated or not a chain name.
	ErrChainName = credcodec.ErrChainName
	// ErrConnUnverified is a connection string whose signature does not show it
	// was issued by its TLV 4. It still decodes; a client tells its user the Hub
	// is not confirmed. It wraps ErrChainNoPrefix or ErrConnSignerMismatch.
	ErrConnUnverified = errors.New("nipcash: connection string is not verified")
	// ErrChainNoPrefix is a chain with no known signed-message prefix.
	ErrChainNoPrefix = errors.New("nipcash: no signed-message prefix is known for this chain")
	// ErrConnSignerMismatch is a connection signature that does not recover to TLV 4
	// over the rebuilt text.
	ErrConnSignerMismatch = errors.New("nipcash: connection signature does not recover to the hub identity")
	// ErrSignerMismatch is a signer that did not sign as the key expected of it, so
	// nothing is issued.
	ErrSignerMismatch = errors.New("nipcash: the signature does not recover to the expected key")
)

// MintSigner signs a payload through a node's signed-message convention: it
// applies its own prefix, hashes twice with SHA-256 and returns a 65-byte compact
// recoverable signature (LND's SignMessage does exactly this).
type MintSigner func(payload string) (compactSig []byte, err error)

// prefixRow is one row of the §Mint Provenance prefix table: a bill's HRP, the
// chain a connection string names, and the signed-message prefix both use.
type prefixRow struct{ hrp, chain, prefix string }

// prefixTable is the one table behind SignedMessagePrefix (by HRP, for bills) and
// ChainSignedMessagePrefix (by chain, for connection strings).
var prefixTable = []prefixRow{
	{hrp: "satscash", chain: "bitcoin", prefix: LndSignedMessagePrefix},
	{hrp: "lokicash", chain: "flokicoin", prefix: LNSignedMessagePrefix},
}

// ChainSignedMessagePrefix is the signed-message prefix of a chain, by its name
// as get_info reports it, and false for a chain with no known prefix.
func ChainSignedMessagePrefix(chain string) (string, bool) {
	for _, row := range prefixTable {
		if row.chain == chain {
			return row.prefix, true
		}
	}
	return "", false
}

// ChainForHRP is the chain a bill's HRP is minted on, by the §Mint
// Provenance prefix table (satscash → bitcoin), and false for an HRP with no
// row. The HRP is matched in lowercase.
func ChainForHRP(hrp string) (string, bool) {
	hrp = strings.ToLower(hrp)
	for _, row := range prefixTable {
		if row.hrp == hrp {
			return row.chain, true
		}
	}
	return "", false
}

// ValidChainName reports a chain name of 1 to 32 bytes of a-z, 0-9 and '-'.
func ValidChainName(s string) bool { return credcodec.ValidChainName(s) }

// QRForm is s in uppercase, which fits a QR code's alphanumeric mode (a client
// SHOULD render every bech32 credential this way in a QR code).
func QRForm(s string) string { return strings.ToUpper(s) }

// RelayHash is the lowercase hex sha256 of every relay hint in the order given,
// each as a 1-byte length then its bytes, then the 32-byte secret (NIP-CASH §Mint
// Provenance). Every entry counts exactly as given, an empty one included.
func RelayHash(relays []string, secretHex string) (string, error) {
	secret, err := decodeKeyHex(secretHex, "secret")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, r := range relays {
		if len(r) > credcodec.MaxTLVValueLen {
			return "", fmt.Errorf("nipcash: relay hint exceeds %d bytes", credcodec.MaxTLVValueLen)
		}
		h.Write([]byte{byte(len(r))})
		h.Write([]byte(r))
	}
	h.Write(secret)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ConnFields is what a connection signature covers: the string's HRP and TLV 0-4
// and 6. Relays are TLV 1 exactly as encoded.
type ConnFields struct {
	HRP, Chain, Pubkey, HubIdentity string
	Relays                          []string
	Secret, Label                   string
	HasLabel                        bool
}

// ConnSignedText is the text a connection signature signs:
// <label>:<chain>:<connection_pubkey>:<hub_identity>:<relay_hash>:<label_hash>,
// with <label_hash> the hex sha256 of TLV 3 when present (an empty one hashed as
// sha256("")) and empty without one.
func ConnSignedText(f ConnFields) (string, error) {
	label, ok := connLabels[f.HRP]
	if !ok {
		return "", fmt.Errorf("nipcash: no connection signature is defined for hrp %q", f.HRP)
	}
	if !ValidChainName(f.Chain) {
		return "", fmt.Errorf("%w: %q", ErrChainName, f.Chain)
	}
	pubkey, err := lowerKeyHex(f.Pubkey, "pubkey")
	if err != nil {
		return "", err
	}
	identity, err := lowerKeyHex(f.HubIdentity, "hub identity")
	if err != nil {
		return "", err
	}
	relayHash, err := RelayHash(f.Relays, f.Secret)
	if err != nil {
		return "", err
	}
	labelHash := ""
	if f.HasLabel {
		sum := sha256.Sum256([]byte(f.Label))
		labelHash = hex.EncodeToString(sum[:])
	}
	return strings.Join([]string{label, f.Chain, pubkey, identity, relayHash, labelHash}, ":"), nil
}

// SignConnection signs f through sign and returns the 65-byte TLV 5, header
// 31 + recid. The signature is recovered before it is returned: it must name
// f.HubIdentity and expectedXOnly, or ErrSignerMismatch and nothing is issued.
func SignConnection(f ConnFields, sign MintSigner, expectedXOnly string) ([]byte, error) {
	if f.HasLabel && f.Label == "" {
		return nil, errors.New("nipcash: an empty label is never emitted, so it is never signed")
	}
	if !f.HasLabel && f.Label != "" {
		return nil, errors.New("nipcash: a label is set without HasLabel, so TLV 3 would be encoded but not signed")
	}
	text, err := ConnSignedText(f)
	if err != nil {
		return nil, err
	}
	prefix, ok := ChainSignedMessagePrefix(f.Chain)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrChainNoPrefix, f.Chain)
	}
	raw, err := sign(text)
	if err != nil {
		return nil, fmt.Errorf("nipcash: sign connection: %w", err)
	}
	sig, ok := normalizeRecovery(raw)
	if !ok {
		return nil, fmt.Errorf("%w: the signer returned no compact recoverable signature", ErrSignerMismatch)
	}
	got, ok := recoverXOnly(sig, prefix, text)
	if !ok || got != strings.ToLower(f.HubIdentity) || got != strings.ToLower(expectedXOnly) {
		return nil, fmt.Errorf("%w: recovered %q, hub identity %q, expected %q", ErrSignerMismatch, got, f.HubIdentity, expectedXOnly)
	}
	return sig, nil
}

// VerifyConnection reports nil when sig, over f's rebuilt text, recovers to f's
// Hub identity. Otherwise it returns ErrConnUnverified wrapping ErrChainNoPrefix
// (a chain with no known prefix) or ErrConnSignerMismatch.
func VerifyConnection(f ConnFields, sig []byte) error {
	prefix, ok := ChainSignedMessagePrefix(f.Chain)
	if !ok {
		return fmt.Errorf("%w: %w: %q", ErrConnUnverified, ErrChainNoPrefix, f.Chain)
	}
	text, err := ConnSignedText(f)
	if err != nil {
		return fmt.Errorf("%w: %w: %v", ErrConnUnverified, ErrConnSignerMismatch, err)
	}
	norm, ok := normalizeRecovery(sig)
	if !ok {
		return fmt.Errorf("%w: %w: no compact recoverable signature", ErrConnUnverified, ErrConnSignerMismatch)
	}
	got, ok := recoverXOnly(norm, prefix, text)
	if !ok || got != strings.ToLower(f.HubIdentity) {
		return fmt.Errorf("%w: %w", ErrConnUnverified, ErrConnSignerMismatch)
	}
	return nil
}

// LocalChainSigner signs with a local key under chain's prefix (RFC 6979 nonces,
// low S, header 31 + recid). For tests, fakes and vector exporters; a Hub signs
// through its node.
func LocalChainSigner(privHex, chain string) (MintSigner, error) {
	prefix, ok := ChainSignedMessagePrefix(chain)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrChainNoPrefix, chain)
	}
	return localSigner(privHex, prefix)
}

func localSigner(privHex, prefix string) (MintSigner, error) {
	b, err := hex.DecodeString(privHex)
	if err != nil || len(b) != 32 {
		return nil, errors.New("nipcash: a signing key is 32 bytes of hex")
	}
	key := secp256k1.PrivKeyFromBytes(b)
	return func(payload string) ([]byte, error) {
		return ecdsa.SignCompact(key, doubleSHA256([]byte(prefix+payload)), true), nil
	}, nil
}

// normalizeRecovery reads a compact signature's header as NIP-CASH §Mint
// Provenance allows (27 to 34, or a raw recid 0 to 3) and rewrites it as
// 31 + recid. Anything else is no signature.
func normalizeRecovery(sig []byte) ([]byte, bool) {
	if len(sig) != mintSigLen {
		return nil, false
	}
	var recid byte
	switch h := sig[0]; {
	case h >= 27 && h <= 34:
		recid = (h - 27) % 4
	case h <= 3:
		recid = h
	default:
		return nil, false
	}
	out := append([]byte(nil), sig...)
	out[0] = 31 + recid
	return out, true
}

// recoverXOnly recovers the signer of text under prefix and returns its x-only key
// as 64 lowercase hex. sig carries a compressed-key header.
func recoverXOnly(sig []byte, prefix, text string) (string, bool) {
	compressed, ok := recoverCompressed(sig, prefix, text)
	if !ok {
		return "", false
	}
	return compressed[2:], true
}

func lowerKeyHex(s, field string) (string, error) {
	b, err := decodeKeyHex(s, field)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
