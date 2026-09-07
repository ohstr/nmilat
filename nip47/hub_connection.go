package nip47

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// TLV type numbers within a hub-connection bech32 string (NIP-CASH §The Cash
// Hub Connection, NIP-CW §The Circle Wallet Hub Connection). 0-2 carry the
// same meaning the cash-token-family format (nipcash.Token) gives them; this
// format's own type space is otherwise independently scoped — a Hub
// connection has no slice, expiry, or provenance to carry, so it never
// defines that format's types 3/5/6.
const (
	hubTLVWalletPubkey uint8 = 0
	hubTLVRelay        uint8 = 1
	hubTLVSecret       uint8 = 2
	hubTLVLabel        uint8 = 3
)

// hubKeyLen is the byte length of both a wallet pubkey and a pairing secret —
// raw 32-byte values, same as every other Nostr key.
const hubKeyLen = 32

// maxHubTLVValueLen is the largest value a single TLV entry's one-byte length
// field can hold. A relay URL or label longer than this would silently
// truncate the length prefix instead of erroring, corrupting every entry
// that follows it in the stream — EncodeHubConnection rejects it outright
// instead.
const maxHubTLVValueLen = 255

// HubConnection is the decoded content of a Cash Hub's or Circle Wallet
// Hub's own bech32 connection string (`cashhub1...`/`circlehub1...`) — the
// same pairing data PairingInfo carries, plus an optional human-readable
// label. Unlike a cash token (nipcash.Token), this format never carries an
// identity-required hint or mint provenance — those describe concepts
// specific to a slice of cash, not a Hub connection.
type HubConnection struct {
	HRP          string   // e.g. "cashhub", "circlehub" — DecodeHubConnection accepts any prefix
	WalletPubkey string   // hex, 32 bytes — the Hub's own pubkey
	Secret       string   // hex, 32 bytes — the NWC connection secret
	RelayURLs    []string // in encoded order
	Label        string   // optional, "" if not set
}

// EncodeHubConnection packages h into a hub-connection bech32 string under
// h.HRP. WalletPubkey and Secret MUST each be a 32-byte hex string.
func EncodeHubConnection(h HubConnection) (string, error) {
	pubkey, err := decodeHubKeyHex(h.WalletPubkey, "wallet pubkey")
	if err != nil {
		return "", err
	}
	secret, err := decodeHubKeyHex(h.Secret, "secret")
	if err != nil {
		return "", err
	}
	for _, url := range h.RelayURLs {
		if len(url) > maxHubTLVValueLen {
			return "", fmt.Errorf("nip47: relay url exceeds %d bytes: %q", maxHubTLVValueLen, url)
		}
	}
	if len(h.Label) > maxHubTLVValueLen {
		return "", fmt.Errorf("nip47: label exceeds %d bytes", maxHubTLVValueLen)
	}

	buf := &bytes.Buffer{}
	writeHubTLV(buf, hubTLVWalletPubkey, pubkey)
	for _, url := range h.RelayURLs {
		writeHubTLV(buf, hubTLVRelay, []byte(url))
	}
	writeHubTLV(buf, hubTLVSecret, secret)
	if h.Label != "" {
		writeHubTLV(buf, hubTLVLabel, []byte(h.Label))
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nip47: failed to convert bits: %w", err)
	}
	return bech32.Encode(h.HRP, bits5)
}

// DecodeHubConnection parses a hub-connection bech32 string (any HRP —
// `cashhub1...`, `circlehub1...`, ...) back into its pairing data. It
// rejects anything missing either required field (wallet pubkey or secret),
// carrying a malformed length for either, or repeating either one. An
// unrecognized TLV type is ignored rather than rejected, so a future field
// can be added without breaking older decoders.
func DecodeHubConnection(s string) (HubConnection, error) {
	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		return HubConnection{}, fmt.Errorf("nip47: invalid bech32: %w", err)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return HubConnection{}, fmt.Errorf("nip47: failed to convert bits: %w", err)
	}

	result := HubConnection{HRP: hrp}
	haveWalletPubkey := false
	haveSecret := false
	haveLabel := false
	curr := 0
	for curr < len(data) {
		typ, value, ok := readHubTLV(data[curr:])
		if !ok {
			return HubConnection{}, fmt.Errorf("nip47: truncated TLV entry at offset %d", curr)
		}
		switch typ {
		case hubTLVWalletPubkey:
			if len(value) != hubKeyLen {
				return HubConnection{}, fmt.Errorf("nip47: wallet pubkey must be %d bytes, got %d", hubKeyLen, len(value))
			}
			if haveWalletPubkey {
				return HubConnection{}, fmt.Errorf("nip47: duplicate wallet pubkey entry")
			}
			result.WalletPubkey = hex.EncodeToString(value)
			haveWalletPubkey = true
		case hubTLVRelay:
			result.RelayURLs = append(result.RelayURLs, string(value))
		case hubTLVSecret:
			if len(value) != hubKeyLen {
				return HubConnection{}, fmt.Errorf("nip47: secret must be %d bytes, got %d", hubKeyLen, len(value))
			}
			if haveSecret {
				return HubConnection{}, fmt.Errorf("nip47: duplicate secret entry")
			}
			result.Secret = hex.EncodeToString(value)
			haveSecret = true
		case hubTLVLabel:
			if haveLabel {
				return HubConnection{}, fmt.Errorf("nip47: duplicate label entry")
			}
			result.Label = string(value)
			haveLabel = true
		default:
			// Unknown TLV type: ignore, same as the cash-token-family format's
			// own decoder, so a future field can be added without breaking
			// older decoders.
		}
		curr += 2 + len(value)
	}

	if !haveWalletPubkey {
		return HubConnection{}, fmt.Errorf("nip47: missing wallet pubkey")
	}
	if !haveSecret {
		return HubConnection{}, fmt.Errorf("nip47: missing secret")
	}
	return result, nil
}

func decodeHubKeyHex(s, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nip47: invalid %s hex: %w", field, err)
	}
	if len(b) != hubKeyLen {
		return nil, fmt.Errorf("nip47: %s must be %d bytes, got %d", field, hubKeyLen, len(b))
	}
	return b, nil
}

func writeHubTLV(buf *bytes.Buffer, typ uint8, value []byte) {
	buf.WriteByte(typ)
	buf.WriteByte(uint8(len(value))) //nolint:gosec // every EncodeHubConnection call site pre-validates len(value) <= maxHubTLVValueLen before calling writeHubTLV
	buf.Write(value)
}

func readHubTLV(data []byte) (typ uint8, value []byte, ok bool) {
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
