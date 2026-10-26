package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The fixed labels of the mint-signature payloads (NIP-CASH §Mint Provenance).
// They are the same for every HRP; the token's own HRP appears only as <hrp>.
const (
	PayloadMintV1 = "cash-mint:v1"
	PayloadZapV1  = "cash-zap:v1"
)

// LNSignedMessagePrefix is the signed-message prefix of the Flokicoin Lightning
// implementation, for lokicash1... tokens and the flokicoin chain.
const LNSignedMessagePrefix = "Flokicoin Lightning Signed Message:"

// LndSignedMessagePrefix is lnd's signed-message prefix, for satscash1... tokens
// and the bitcoin chain.
const LndSignedMessagePrefix = "Lightning Signed Message:"

var (
	// ErrSchemeUnsupported is a scheme SignToken cannot sign under.
	ErrSchemeUnsupported = errors.New("nipcash: unsupported signature scheme")
	// ErrZapContextRequired is scheme 2 without its zap context.
	ErrZapContextRequired = errors.New("nipcash: a cash-zap:v1 signature needs its zap context")
	// ErrZapContextUnexpected is a zap context given for scheme 1.
	ErrZapContextUnexpected = errors.New("nipcash: a cash-mint:v1 signature takes no zap context")
	// ErrPayloadField is a payload field that is empty or not in its canonical form.
	ErrPayloadField = errors.New("nipcash: payload field is malformed")
)

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

// MintPayloadV1 is the scheme-1 payload:
// cash-mint:v1:<hrp>:<wallet_pubkey_hex>:<amount_millis>:<relay_hash>, with the
// HRP and the wallet pubkey lowercased.
func MintPayloadV1(hrp, walletHex string, amount uint64, relayHash string) string {
	return strings.Join([]string{PayloadMintV1, strings.ToLower(hrp), strings.ToLower(walletHex),
		strconv.FormatUint(amount, 10), relayHash}, ":")
}

// ZapContext is what a scheme-2 payload adds, rebuilt from the Cash Zap that
// carries the token (NIP-CZ). Recipient and Sender are 64 lowercase hex pubkeys;
// ZapTarget is hashed exactly as given; ExpiresAt is 0 for a bill that never
// expires.
type ZapContext struct {
	Recipient, Sender, ZapTarget string
	IssuedAt, ExpiresAt          uint64
}

// ZapPayloadV1 is the scheme-2 payload:
// cash-zap:v1:<hrp>:<wallet>:<amount>:<relay_hash>:pubkey/<recipient>:pubkey/<sender>:<target_hash>:<issued_at>:<expires_at>.
func ZapPayloadV1(hrp, walletHex string, amount uint64, relayHash string, z ZapContext) (string, error) {
	if !isLowerHex64(z.Recipient) || !isLowerHex64(z.Sender) {
		return "", fmt.Errorf("%w: recipient and sender are 64 lowercase hex characters", ErrPayloadField)
	}
	if z.ZapTarget == "" {
		return "", fmt.Errorf("%w: zap_target is empty", ErrPayloadField)
	}
	sum := sha256.Sum256([]byte(z.ZapTarget))
	return strings.Join([]string{PayloadZapV1, strings.ToLower(hrp), strings.ToLower(walletHex),
		strconv.FormatUint(amount, 10), relayHash, "pubkey/" + z.Recipient, "pubkey/" + z.Sender,
		hex.EncodeToString(sum[:]), strconv.FormatUint(z.IssuedAt, 10), strconv.FormatUint(z.ExpiresAt, 10)}, ":"), nil
}

// ProvenancePayload is the payload t's mint signature signs, by t.Scheme. A zap
// context is required for scheme 2 and refused for scheme 1.
func ProvenancePayload(t Token, z *ZapContext) (string, error) {
	if t.AttestedAmountMillis == nil {
		return "", fmt.Errorf("%w: no attested amount", ErrPayloadField)
	}
	relayHash, err := RelayHash(t.RelayURLs, t.Secret)
	if err != nil {
		return "", err
	}
	switch t.Scheme {
	case SchemeMintV1:
		if z != nil {
			return "", ErrZapContextUnexpected
		}
		return MintPayloadV1(t.HRP, t.WalletPubkey, *t.AttestedAmountMillis, relayHash), nil
	case SchemeZapV1:
		if z == nil {
			return "", ErrZapContextRequired
		}
		return ZapPayloadV1(t.HRP, t.WalletPubkey, *t.AttestedAmountMillis, relayHash, *z)
	default:
		return "", fmt.Errorf("%w: %d", ErrSchemeUnsupported, t.Scheme)
	}
}

// doubleSHA256 is the signed-message convention's "hash twice".
func doubleSHA256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// VerifyProvenance recovers the minter (a compressed key, hex) of a scheme-1
// token. It answers "who signed this", never "should I trust them": the caller
// compares the key with the minter it expects. A scheme-2 token, a token with no
// or malformed provenance, an HRP with no known prefix, or a signature that does
// not recover over the token's own payload all return "", false; the token still
// decodes.
func VerifyProvenance(t Token) (minterCompressedHex string, ok bool) {
	if t.Scheme != SchemeMintV1 {
		return "", false
	}
	return verifyPayload(t, nil)
}

// VerifyZapProvenance recovers the minter of a scheme-2 token, given the context
// rebuilt from its Cash Zap.
func VerifyZapProvenance(t Token, z ZapContext) (minterCompressedHex string, ok bool) {
	if t.Scheme != SchemeZapV1 {
		return "", false
	}
	return verifyPayload(t, &z)
}

func verifyPayload(t Token, z *ZapContext) (string, bool) {
	if !t.HasProvenance() {
		return "", false
	}
	prefix, known := SignedMessagePrefix(strings.ToLower(t.HRP))
	if !known {
		return "", false
	}
	payload, err := ProvenancePayload(t, z)
	if err != nil {
		return "", false
	}
	sig, ok := normalizeRecovery(t.MintSignature)
	if !ok {
		return "", false
	}
	return recoverCompressed(sig, prefix, payload)
}

// MinterXOnly is a recovered compressed minter key's x-only part, the 32 bytes
// after its prefix byte, as 64 lowercase hex: the form a Nostr pubkey compares
// with.
func MinterXOnly(compressedHex string) (string, error) {
	b, err := hex.DecodeString(compressedHex)
	if err != nil || len(b) != 33 || (b[0] != 2 && b[0] != 3) {
		return "", fmt.Errorf("nipcash: %q is not a 33-byte compressed key", compressedHex)
	}
	return hex.EncodeToString(b[1:]), nil
}

// reservedSignPrefixes are the labels a node's sign-message path must refuse, so
// it cannot be used as an oracle for a provenance or connection signature.
var reservedSignPrefixes = []string{"cash-mint:", "cash-zap:", "cash-hub:", "cash-order:", "circle-hub:"}

// IsReservedSignText reports a text that begins, in any case, with one of the
// labels this protocol signs: cash-mint:, cash-zap:, cash-hub:, cash-order: or
// circle-hub:. A Hub's generic sign-message method refuses such a text.
func IsReservedSignText(msg string) bool {
	lower := strings.ToLower(msg)
	for _, p := range reservedSignPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
