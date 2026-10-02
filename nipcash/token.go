package nipcash

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
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

	// MintSignature and AttestedAmountMillis are the optional mint-
	// provenance pair (NIP-CASH §Mint Provenance): a recoverable ECDSA
	// signature (raw mintSigLen bytes) by the minting node's Lightning
	// identity key over MintPayload(HRP, WalletPubkey,
	// *AttestedAmountMillis), and the amount that payload commits to. Both
	// nil = no provenance; both set = provenance present. Decode enforces
	// both-or-neither by dropping a lone one (never a decode failure — both
	// are optional). Verify with VerifyProvenance, which recovers the
	// signer pubkey; a bare signature proves origin and denomination but is
	// NEVER a spending credential.
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

// HasProvenance reports whether t carries a complete mint-provenance pair.
func (t Token) HasProvenance() bool {
	return t.MintSignature != nil && t.AttestedAmountMillis != nil
}

// Encode packages t into a cash-token-family bech32 token under t.HRP.
// WalletPubkey and Secret MUST each be a 32-byte hex string.
func Encode(t Token) (string, error) {
	pubkey, err := decodeKeyHex(t.WalletPubkey, "wallet pubkey")
	if err != nil {
		return "", err
	}
	secret, err := decodeKeyHex(t.Secret, "secret")
	if err != nil {
		return "", err
	}
	// A cash token is reached only through its own relay hints — there is no
	// discovery path for a bill's wallet pubkey, which is published nowhere, and
	// no client-side fallback. So at least one usable hint is REQUIRED, exactly as
	// for a hub connection (NIP-CASH §The Cash Token).
	if countUsableRelays(t.RelayURLs) == 0 {
		return "", fmt.Errorf("nipcash: a cash token needs at least one non-empty relay url, or nobody can reach the wallet")
	}
	for _, url := range t.RelayURLs {
		if len(url) > maxTLVValueLen {
			return "", fmt.Errorf("nipcash: relay url exceeds %d bytes: %q", maxTLVValueLen, url)
		}
	}
	if (t.MintSignature == nil) != (t.AttestedAmountMillis == nil) {
		return "", fmt.Errorf("nipcash: mint signature and attested amount must be set together")
	}
	if t.MintSignature != nil && len(t.MintSignature) != mintSigLen {
		return "", fmt.Errorf("nipcash: mint signature must be %d bytes, got %d", mintSigLen, len(t.MintSignature))
	}
	if t.HubGroup != nil && len(t.HubGroup) != HubGroupLen {
		return "", fmt.Errorf("nipcash: hub group must be %d bytes, got %d", HubGroupLen, len(t.HubGroup))
	}

	buf := &bytes.Buffer{}
	writeTLV(buf, tlvWalletPubkey, pubkey)
	for _, url := range t.RelayURLs {
		writeTLV(buf, tlvRelay, []byte(url))
	}
	writeTLV(buf, tlvSecret, secret)
	if t.IdentityRequired != nil {
		var b byte
		if *t.IdentityRequired {
			b = 1
		}
		writeTLV(buf, tlvIdentityRequired, []byte{b})
	}
	if t.MintSignature != nil {
		var amountBytes [attestedAmountLen]byte
		binary.BigEndian.PutUint64(amountBytes[:], *t.AttestedAmountMillis)
		writeTLV(buf, tlvMintSignature, t.MintSignature)
		writeTLV(buf, tlvAttestedAmount, amountBytes[:])
	}
	if t.HubGroup != nil {
		writeTLV(buf, tlvHubGroup, t.HubGroup)
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipcash: failed to convert bits: %w", err)
	}
	return bech32.Encode(t.HRP, bits5)
}

// Decode parses a cash-token-family bech32 token (any HRP — `lokicash1...`,
// `satscash1...`, ...) back into its pairing data. It rejects anything
// missing either required field (wallet pubkey or secret), carrying a
// malformed length for either, or repeating either one.
func Decode(token string) (Token, error) {
	hrp, bits5, err := bech32.DecodeNoLimit(token)
	if err != nil {
		return Token{}, fmt.Errorf("nipcash: invalid bech32: %w", err)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return Token{}, fmt.Errorf("nipcash: failed to convert bits: %w", err)
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
		case tlvMintSignature:
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
	if !provenancePoisoned && mintSig != nil && attestedAmount != nil {
		result.MintSignature = mintSig
		result.AttestedAmountMillis = attestedAmount
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

// countUsableRelays returns how many of urls are non-empty once trimmed.
//
// Empty entries are counted as absent rather than as relays. That distinction is
// the whole point: a producer whose relay config was unset can easily emit one
// relay whose URL is "", and such a credential is exactly as unreachable as one
// carrying no relay TLV at all — while passing any check that only counts
// entries. Trimming catches the " " variant of the same mistake.
func countUsableRelays(urls []string) int {
	n := 0
	for _, u := range urls {
		if strings.TrimSpace(u) != "" {
			n++
		}
	}
	return n
}
