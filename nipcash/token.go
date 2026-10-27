package nipcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ohstr/nmilat/internal/credcodec"
)

// TLV type numbers within a cash-token-family bech32 string (NIP-CASH §The
// Cash Token → Wire Format). 0 and 1 follow the same convention NIP-19 uses
// for nprofile/nevent/naddr (0 is the token's primary identifier, 1 is a
// relay hint); 2-3 and 5-6 are specific to this token family. Type 4 is
// reserved and MUST NOT be assigned a new meaning (NIP-CASH's own decoders
// ignore it as an unrecognized type, same as any type this decoder doesn't
// know about — see the "unknown TLV type: ignore" rule in Decode).
const (
	tlvWalletPubkey     uint8 = 0
	tlvRelay            uint8 = 1
	tlvSecret           uint8 = 2
	tlvIdentityRequired uint8 = 3
	tlvMintSignature    uint8 = 5
	tlvAttestedAmount   uint8 = 6
	tlvHubGroup         uint8 = 7
	tlvSignatureScheme  uint8 = 8
)

// SignatureScheme is a token's TLV 8: which payload its mint signature signs
// (NIP-CASH §Mint Provenance).
type SignatureScheme uint8

const (
	// SchemeNone is a token with no provenance at all.
	SchemeNone SignatureScheme = 0
	// SchemeMintV1 signs "cash-mint:v1:...".
	SchemeMintV1 SignatureScheme = 1
	// SchemeZapV1 signs "cash-zap:v1:..." (a bill created by a zap transfer).
	SchemeZapV1 SignatureScheme = 2
	// SchemeMalformed is a decoded token whose provenance fields are present but
	// unusable: TLV 8 absent beside 5/6, wrong-length, repeated or unknown, or
	// 5/6 themselves wrong-length, repeated or unpaired. The token decodes with no
	// valid provenance; an encoder never writes it.
	SchemeMalformed SignatureScheme = 0xFF
)

var (
	// ErrTokenUnsigned is a token Encode was asked to write without a complete
	// provenance: a 65-byte mint signature, an attested amount and a scheme of
	// SchemeMintV1 or SchemeZapV1. A Hub never issues an unsigned token.
	ErrTokenUnsigned = errors.New("nipcash: a token must carry its mint signature, attested amount and signature scheme")
	// ErrBlankRelayHint is an empty or whitespace-only relay hint Encode was asked
	// to write; it is refused, never skipped, so relay_hash covers what is written.
	ErrBlankRelayHint = credcodec.ErrBlankRelayHint
	// ErrNonASCIIRelayHint is a relay hint with a non-ASCII byte.
	ErrNonASCIIRelayHint = credcodec.ErrNonASCIIRelayHint
	// ErrHRPCase is an HRP Encode was asked to write that is not lowercase.
	ErrHRPCase = errors.New("nipcash: a token's hrp must be lowercase")
	// ErrMixedCase is a bech32 credential that mixes upper and lower case, which
	// every decoder here refuses, as BIP-173 requires (NIP-CASH §Wire Format).
	ErrMixedCase = credcodec.ErrMixedCase
	// ErrBech32m is a credential carrying a bech32m checksum: every decoder here
	// requires NIP-19 bech32 (BIP-173).
	ErrBech32m = credcodec.ErrBech32m
)

// HubGroupLen is the byte length of the hub-group fingerprint (TLV type 7): a
// truncated hash of the issuing Cash Hub's own pubkey.
//
// Four bytes, and the reason it can be this short is what it is FOR. It answers
// exactly one question — do two bills share an issuing Hub, and may therefore be
// consolidated together — and it is never an authorization input. A wrong value
// makes a client group wrongly and the Hub refuses with its own same-Hub error, so
// the worst outcome is a failed consolidate, never misplaced value.
//
// Collisions only matter among the Hubs of ONE Lightning node, since bills must
// already share a minter before grouping is considered at all. That is a handful of
// Hubs against a 4-byte space, so the margin is enormous — and the cost of being
// wrong is a retry with explicit sources.
//
// It is a HASH rather than the Hub's pubkey itself, and truncated rather than full,
// because every bill a Hub mints would otherwise carry a stable, linkable
// identifier for that Hub in the clear. A 4-byte digest of a pubkey nobody can
// enumerate groups bills for their holder without publishing which Hub issued them.
const HubGroupLen = 4

// keyLen is the byte length of both a wallet pubkey and a pairing secret —
// raw 32-byte values, same as every other Nostr key.
const keyLen = 32

// mintSigLen is the byte length of a recoverable ECDSA compact signature (1
// recovery byte + 32-byte R + 32-byte S) — see VerifyProvenance.
const mintSigLen = 65

// attestedAmountLen is the fixed width of the attested-amount TLV value: an
// 8-byte big-endian millis amount.
const attestedAmountLen = 8

// maxTLVValueLen is the largest value a single TLV entry's one-byte length
// field can hold. A relay URL longer than this would silently truncate the
// length prefix instead of erroring, corrupting every entry that follows it
// in the stream — Encode rejects it outright instead.
const maxTLVValueLen = 255

// Token is the decoded content of a cash-token-family bech32 string
// (`lokicash1...`, `satscash1...`, ...): the NIP-47 pairing data a Cash
// Wallet connection needs, plus the optional identity-required hint and
// mint-provenance pair (NIP-CASH §The Cash Token).
//
// IdentityRequired is a pointer specifically so a caller can tell "this
// token doesn't carry this hint" (nil) apart from a real, meaningful zero
// value. Treat it as a best-effort hint only, snapshotted at whatever
// moment the token was minted or last re-derived — NOT a live guarantee.
// Every cash_redeem/cash_transfer call is still authoritatively checked
// server-side regardless of what a token implies; a client MUST NOT treat
// this field as a substitute for that check, only as a hint for deciding
// how to attempt one.
type Token struct {
	HRP          string   // e.g. "lokicash", "satscash" — Decode accepts any prefix
	WalletPubkey string   // hex, 32 bytes
	Secret       string   // hex, 32 bytes — the NWC connection secret
	RelayURLs    []string // in encoded order

	IdentityRequired *bool

	// MintSignature and AttestedAmountMillis are the mint-provenance pair
	// (NIP-CASH §Mint Provenance): a 65-byte compact recoverable signature by
	// the minting node's identity key over the payload Scheme names
	// (ProvenancePayload), and the amount it commits to. An encoder requires
	// both; a decoder drops a faulty pair and marks Scheme SchemeMalformed.
	// VerifyProvenance or VerifyZapProvenance recovers the signer; the
	// signature proves origin and denomination and is NEVER a spending
	// credential.
	MintSignature        []byte
	AttestedAmountMillis *uint64

	// HubGroup is the issuing Cash Hub's fingerprint (TLV type 7, HubGroupLen
	// bytes), nil when the minting Hub did not include one.
	//
	// Its ONLY use is grouping: two bills may be consolidated together just when
	// they share an issuing Hub, and nothing else in a token says which Hub that
	// was. Mint provenance identifies the minting NODE, and one node routinely runs
	// several Hubs — so grouping by minter merges bills the Hub will then refuse,
	// which is what this exists to fix.
	//
	// NOT an authorization input, and MUST NOT be treated as one. It is
	// unauthenticated and truncated; a wrong value causes a client to group wrongly
	// and the Hub to refuse, which costs a retry and never moves value. Compare with
	// HasProvenance, which IS verifiable and does identify the minter.
	HubGroup []byte

	// Scheme is TLV 8, which payload MintSignature signs. Decode sets
	// SchemeMalformed, and drops the signature and amount, when the provenance
	// fields are present but unusable.
	Scheme SignatureScheme
}

// UsableRelays are the relay hints a client dials: in encoded order, those that
// are non-empty once ASCII whitespace is trimmed and parse as ws:// or wss:// URLs.
// RelayURLs keeps every entry as encoded, since relay_hash covers them all.
func (t Token) UsableRelays() []string {
	var out []string
	for _, r := range t.RelayURLs {
		if credcodec.IsBlankHint(r) {
			continue
		}
		u, err := url.Parse(strings.Trim(r, " \t\n\r\f\v"))
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// SameHubGroup reports whether two tokens carry the same hub fingerprint, i.e.
// whether they may be consolidated together.
//
// False when either is missing one: an absent fingerprint is "unknown Hub", never a
// wildcard. Grouping two bills on the strength of neither naming a Hub is how the
// minter-based grouping this replaces went wrong.
func SameHubGroup(a, b Token) bool {
	if len(a.HubGroup) != HubGroupLen || len(b.HubGroup) != HubGroupLen {
		return false
	}
	return bytes.Equal(a.HubGroup, b.HubGroup)
}

// HubGroupFor derives the fingerprint a Hub stamps on every bill it mints:
// the first HubGroupLen bytes of sha256 of its own pubkey.
//
// Hashed rather than used raw so a bill does not carry a stable, linkable
// identifier for its issuing Hub in the clear; truncated because it only has to
// distinguish the Hubs of one node (see HubGroupLen).
func HubGroupFor(hubPubkeyHex string) []byte {
	sum := sha256.Sum256([]byte(hubPubkeyHex))
	return sum[:HubGroupLen]
}

// HasProvenance reports whether t carries a complete mint-provenance set: the
// signature, the attested amount and a known scheme.
func (t Token) HasProvenance() bool {
	return t.MintSignature != nil && t.AttestedAmountMillis != nil &&
		(t.Scheme == SchemeMintV1 || t.Scheme == SchemeZapV1)
}

// Encode packages t into a cash-token-family bech32 token under t.HRP, in
// lowercase, entries in ascending type order: 0, 1..., 2, 3, 5, 6, 7, 8.
//
// It refuses an unsigned token (ErrTokenUnsigned: a 65-byte MintSignature, an
// AttestedAmountMillis and a Scheme of SchemeMintV1 or SchemeZapV1 are required),
// a hint that is empty or whitespace-only (ErrBlankRelayHint), non-ASCII
// (ErrNonASCIIRelayHint) or over 255 bytes, a token with no hint, a non-lowercase
// HRP (ErrHRPCase) and a wrong-length hub group. Every hint is written as given,
// never skipped, so the relay_hash a signer computed over RelayURLs matches.
func Encode(t Token) (string, error) {
	if t.HRP == "" || strings.ToLower(t.HRP) != t.HRP {
		return "", fmt.Errorf("%w: %q", ErrHRPCase, t.HRP)
	}
	pubkey, err := decodeKeyHex(t.WalletPubkey, "wallet pubkey")
	if err != nil {
		return "", err
	}
	secret, err := decodeKeyHex(t.Secret, "secret")
	if err != nil {
		return "", err
	}
	// A cash token is reached only through its own relay hints: a bill's wallet
	// pubkey is published nowhere, so at least one hint is REQUIRED (NIP-CASH
	// §Relay Hints Are Mandatory).
	if len(t.RelayURLs) == 0 {
		return "", fmt.Errorf("nipcash: a cash token needs at least one relay url, or nobody can reach the wallet")
	}
	for _, u := range t.RelayURLs {
		switch {
		case credcodec.IsBlankHint(u):
			return "", fmt.Errorf("%w: %q", ErrBlankRelayHint, u)
		case !credcodec.IsASCII(u):
			return "", fmt.Errorf("%w: %q", ErrNonASCIIRelayHint, u)
		case len(u) > maxTLVValueLen:
			return "", fmt.Errorf("nipcash: relay url exceeds %d bytes: %q", maxTLVValueLen, u)
		}
	}
	if len(t.MintSignature) != mintSigLen || t.AttestedAmountMillis == nil ||
		(t.Scheme != SchemeMintV1 && t.Scheme != SchemeZapV1) {
		return "", ErrTokenUnsigned
	}
	if t.HubGroup != nil && len(t.HubGroup) != HubGroupLen {
		return "", fmt.Errorf("nipcash: hub group must be %d bytes, got %d", HubGroupLen, len(t.HubGroup))
	}

	buf := &bytes.Buffer{}
	writeTLV(buf, tlvWalletPubkey, pubkey)
	for _, u := range t.RelayURLs {
		writeTLV(buf, tlvRelay, []byte(u))
	}
	writeTLV(buf, tlvSecret, secret)
	if t.IdentityRequired != nil {
		var b byte
		if *t.IdentityRequired {
			b = 1
		}
		writeTLV(buf, tlvIdentityRequired, []byte{b})
	}
	var amountBytes [attestedAmountLen]byte
	binary.BigEndian.PutUint64(amountBytes[:], *t.AttestedAmountMillis)
	writeTLV(buf, tlvMintSignature, t.MintSignature)
	writeTLV(buf, tlvAttestedAmount, amountBytes[:])
	if t.HubGroup != nil {
		writeTLV(buf, tlvHubGroup, t.HubGroup)
	}
	writeTLV(buf, tlvSignatureScheme, []byte{byte(t.Scheme)})
	return credcodec.EncodeBech32(t.HRP, buf.Bytes())
}

// decodeBech32Case is Decode's one bech32 entry: it refuses a mixed-case string
// (ErrMixedCase) and decodes the lowercase form.
func decodeBech32Case(s string) (hrp string, data []byte, err error) {
	return credcodec.DecodeBech32(s)
}

// Decode parses a cash-token-family bech32 token (any HRP) back into its
// pairing data, the string all in lowercase or all in uppercase (a mixed-case
// one is ErrMixedCase); HRP comes back lowercase. It rejects a token missing
// TLV 0 or 2, a wrong-length fixed field other than 5-8, a repeated single field
// other than those, truncated TLV data and a token with no usable relay hint.
// Faulty provenance (5, 6, 8) leaves the token decodable with no valid
// provenance and Scheme SchemeMalformed; a faulty hub group (7) is dropped.
// RelayURLs keeps every TLV 1 entry exactly as encoded, empty ones included.
func Decode(token string) (Token, error) {
	hrp, data, err := decodeBech32Case(token)
	if err != nil {
		return Token{}, fmt.Errorf("nipcash: %w", err)
	}

	result := Token{HRP: hrp}
	haveWalletPubkey := false
	haveSecret := false
	haveIdentityRequired := false
	// Mint provenance (types 5/6) is optional and both-or-neither. Anything
	// anomalous about it — a lone half, a duplicate, a wrong-length value —
	// MUST leave the token with no provenance rather than fail the whole
	// decode (NIP-CASH §Mint Provenance). Collect the pair tentatively and
	// poison it on any anomaly, then attach it only if a clean pair survived.
	var mintSig []byte
	var attestedAmount *uint64
	provenancePoisoned := false
	// Same tentative-then-attach treatment for the hub-group fingerprint, and for a
	// softer reason: it is a grouping hint, so anything anomalous about it MUST
	// leave the token simply ungrouped rather than fail the decode.
	var hubGroup []byte
	hubGroupPoisoned := false
	// TLV 8 rides with the provenance pair: anything wrong with it poisons the
	// provenance, never the decode.
	var scheme SignatureScheme
	haveScheme, sawSigOrAmount := false, false
	curr := 0
	for curr < len(data) {
		typ, value, ok := readTLV(data[curr:])
		if !ok {
			return Token{}, fmt.Errorf("nipcash: truncated TLV entry at offset %d", curr)
		}
		switch typ {
		case tlvWalletPubkey:
			if len(value) != keyLen {
				return Token{}, fmt.Errorf("nipcash: wallet pubkey must be %d bytes, got %d", keyLen, len(value))
			}
			if haveWalletPubkey {
				return Token{}, fmt.Errorf("nipcash: duplicate wallet pubkey entry")
			}
			result.WalletPubkey = hex.EncodeToString(value)
			haveWalletPubkey = true
		case tlvRelay:
			result.RelayURLs = append(result.RelayURLs, string(value))
		case tlvSecret:
			if len(value) != keyLen {
				return Token{}, fmt.Errorf("nipcash: secret must be %d bytes, got %d", keyLen, len(value))
			}
			if haveSecret {
				return Token{}, fmt.Errorf("nipcash: duplicate secret entry")
			}
			result.Secret = hex.EncodeToString(value)
			haveSecret = true
		case tlvIdentityRequired:
			if len(value) != 1 {
				return Token{}, fmt.Errorf("nipcash: identity_required must be 1 byte, got %d", len(value))
			}
			if value[0] > 1 {
				return Token{}, fmt.Errorf("nipcash: identity_required must be 0 or 1, got %d", value[0])
			}
			if haveIdentityRequired {
				return Token{}, fmt.Errorf("nipcash: duplicate identity_required entry")
			}
			identityRequired := value[0] == 1
			result.IdentityRequired = &identityRequired
			haveIdentityRequired = true
		case tlvSignatureScheme:
			if haveScheme || len(value) != 1 || (value[0] != byte(SchemeMintV1) && value[0] != byte(SchemeZapV1)) {
				provenancePoisoned = true
			} else {
				scheme = SignatureScheme(value[0])
			}
			haveScheme = true
		case tlvMintSignature:
			sawSigOrAmount = true
			if mintSig != nil || len(value) != mintSigLen {
				provenancePoisoned = true
				break
			}
			mintSig = append([]byte(nil), value...)
		case tlvHubGroup:
			// A malformed or repeated fingerprint is DROPPED, not a decode failure.
			// It is a grouping hint: a bill carrying a bad one is still perfectly
			// spendable, one bill at a time, and refusing the whole token would make
			// a cosmetic field able to strand real value.
			if hubGroup != nil || len(value) != HubGroupLen {
				hubGroupPoisoned = true
				break
			}
			hubGroup = append([]byte(nil), value...)
		case tlvAttestedAmount:
			sawSigOrAmount = true
			if attestedAmount != nil || len(value) != attestedAmountLen {
				provenancePoisoned = true
				break
			}
			amt := binary.BigEndian.Uint64(value)
			attestedAmount = &amt
		default:
			// Unknown TLV type: ignore, same as NIP-19's own decoders, so a
			// future field can be added without breaking older decoders.
		}
		curr += 2 + len(value)
	}

	if !haveWalletPubkey {
		return Token{}, fmt.Errorf("nipcash: missing wallet pubkey")
	}
	if !haveSecret {
		return Token{}, fmt.Errorf("nipcash: missing secret")
	}
	if countUsableRelays(result.RelayURLs) == 0 {
		// Refused here rather than left to the caller's dialer. A relay-less token
		// is structurally valid and its checksum verifies, so every layer above
		// accepts it and the failure surfaces as an obscure connection error
		// against a bill that looks perfect.
		return Token{}, fmt.Errorf("nipcash: token carries no usable relay url, so the wallet is unreachable")
	}
	switch {
	case !sawSigOrAmount:
		// No signature and no amount: no provenance. A lone TLV 8 is ignored.
		result.Scheme = SchemeNone
	case !provenancePoisoned && mintSig != nil && attestedAmount != nil && scheme != SchemeNone:
		result.MintSignature = mintSig
		result.AttestedAmountMillis = attestedAmount
		result.Scheme = scheme
	default:
		// 5/6 present but unusable, or without a valid TLV 8: no valid provenance,
		// the rest decodes (there is no legacy scheme).
		result.Scheme = SchemeMalformed
	}
	if !hubGroupPoisoned {
		result.HubGroup = hubGroup
	}
	return result, nil
}

func decodeKeyHex(s, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nipcash: invalid %s hex: %w", field, err)
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("nipcash: %s must be %d bytes, got %d", field, keyLen, len(b))
	}
	return b, nil
}

func writeTLV(buf *bytes.Buffer, typ uint8, value []byte) {
	buf.WriteByte(typ)
	buf.WriteByte(uint8(len(value))) //nolint:gosec // every Encode call site pre-validates len(value) <= maxTLVValueLen before calling writeTLV
	buf.Write(value)
}

func readTLV(data []byte) (typ uint8, value []byte, ok bool) {
	if len(data) < 2 {
		return 0, nil, false
	}
	typ = data[0]
	length := int(data[1])
	if len(data) < 2+length {
		return 0, nil, false
	}
	return typ, data[2 : 2+length], true
}

// countUsableRelays counts the hints that are not blank. An unset relay
// configuration typically yields one empty URL rather than none, and such a
// credential is exactly as unreachable as one with no hint at all.
func countUsableRelays(urls []string) int { return credcodec.CountUsableHints(urls) }
