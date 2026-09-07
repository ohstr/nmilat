package nipcw

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// CircleHubConnectionHRP is the fixed bech32 prefix for a Circle Wallet
// Hub's own connection string (NIP-CW §The Circle Wallet Hub Connection) —
// the one members send create_circle_wallet to.
const CircleHubConnectionHRP = "circlehub"

// TLV type numbers within a circlehub1... string. 0-2 follow the same
// convention NIP-19/the cash-token-family format use for pairing data
// (wallet pubkey, relay, secret); 3 is specific to this format (an optional
// human-readable label) and is scoped to this decoder only — see NIP-CW's
// own note that a Hub-connection format's type numbers don't need to line
// up with any other format's.
const (
	circleHubTLVWalletPubkey uint8 = 0
	circleHubTLVRelay        uint8 = 1
	circleHubTLVSecret       uint8 = 2
	circleHubTLVLabel        uint8 = 3
)

// circleHubKeyLen is the byte length of both a wallet pubkey and a pairing
// secret — raw 32-byte values, same as every other Nostr key.
const circleHubKeyLen = 32

// maxCircleHubTLVValueLen is the largest value a single TLV entry's
// one-byte length field can hold. A relay URL or label longer than this
// would silently truncate the length prefix instead of erroring, corrupting
// every entry that follows it in the stream — EncodeCircleHubConnection
// rejects it outright instead.
const maxCircleHubTLVValueLen = 255

// CircleHubConnection is the decoded content of a Circle Wallet Hub's own
// circlehub1... connection string: the pairing data a member needs to send
// create_circle_wallet, plus an optional human-readable label.
type CircleHubConnection struct {
	WalletPubkey string   // hex, 32 bytes — the Hub's own pubkey
	Secret       string   // hex, 32 bytes — the NWC connection secret
	RelayURLs    []string // in encoded order
	Label        string   // optional, "" if not set
}

// EncodeCircleHubConnection packages c into a circlehub1... string.
// WalletPubkey and Secret MUST each be a 32-byte hex string.
func EncodeCircleHubConnection(c CircleHubConnection) (string, error) {
	pubkey, err := decodeCircleHubKeyHex(c.WalletPubkey, "wallet pubkey")
	if err != nil {
		return "", err
	}
	secret, err := decodeCircleHubKeyHex(c.Secret, "secret")
	if err != nil {
		return "", err
	}
	for _, url := range c.RelayURLs {
		if len(url) > maxCircleHubTLVValueLen {
			return "", fmt.Errorf("nipcw: relay url exceeds %d bytes: %q", maxCircleHubTLVValueLen, url)
		}
	}
	if len(c.Label) > maxCircleHubTLVValueLen {
		return "", fmt.Errorf("nipcw: label exceeds %d bytes", maxCircleHubTLVValueLen)
	}

	buf := &bytes.Buffer{}
	writeCircleHubTLV(buf, circleHubTLVWalletPubkey, pubkey)
	for _, url := range c.RelayURLs {
		writeCircleHubTLV(buf, circleHubTLVRelay, []byte(url))
	}
	writeCircleHubTLV(buf, circleHubTLVSecret, secret)
	if c.Label != "" {
		writeCircleHubTLV(buf, circleHubTLVLabel, []byte(c.Label))
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipcw: failed to convert bits: %w", err)
	}
	return bech32.Encode(CircleHubConnectionHRP, bits5)
}

// DecodeCircleHubConnection parses a circlehub1... string back into its
// pairing data. It rejects anything missing either required field (wallet
// pubkey or secret), carrying a malformed length for either, or repeating
// either one. An unrecognized TLV type is ignored rather than rejected, so
// a future field can be added without breaking older decoders.
func DecodeCircleHubConnection(s string) (CircleHubConnection, error) {
	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		return CircleHubConnection{}, fmt.Errorf("nipcw: invalid bech32: %w", err)
	}
	if hrp != CircleHubConnectionHRP {
		return CircleHubConnection{}, fmt.Errorf("nipcw: unexpected hrp %q, want %q", hrp, CircleHubConnectionHRP)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return CircleHubConnection{}, fmt.Errorf("nipcw: failed to convert bits: %w", err)
	}

	var result CircleHubConnection
	haveWalletPubkey := false
	haveSecret := false
	haveLabel := false
	curr := 0
	for curr < len(data) {
		typ, value, ok := readCircleHubTLV(data[curr:])
		if !ok {
			return CircleHubConnection{}, fmt.Errorf("nipcw: truncated TLV entry at offset %d", curr)
		}
		switch typ {
		case circleHubTLVWalletPubkey:
			if len(value) != circleHubKeyLen {
				return CircleHubConnection{}, fmt.Errorf("nipcw: wallet pubkey must be %d bytes, got %d", circleHubKeyLen, len(value))
			}
			if haveWalletPubkey {
				return CircleHubConnection{}, fmt.Errorf("nipcw: duplicate wallet pubkey entry")
			}
			result.WalletPubkey = hex.EncodeToString(value)
			haveWalletPubkey = true
		case circleHubTLVRelay:
			result.RelayURLs = append(result.RelayURLs, string(value))
		case circleHubTLVSecret:
			if len(value) != circleHubKeyLen {
				return CircleHubConnection{}, fmt.Errorf("nipcw: secret must be %d bytes, got %d", circleHubKeyLen, len(value))
			}
			if haveSecret {
				return CircleHubConnection{}, fmt.Errorf("nipcw: duplicate secret entry")
			}
			result.Secret = hex.EncodeToString(value)
			haveSecret = true
		case circleHubTLVLabel:
			if haveLabel {
				return CircleHubConnection{}, fmt.Errorf("nipcw: duplicate label entry")
			}
			result.Label = string(value)
			haveLabel = true
		default:
			// Unknown TLV type: ignore, same forward-compatibility rule the
			// cash-token-family format's own Decode establishes.
		}
		curr += 2 + len(value)
	}

	if !haveWalletPubkey {
		return CircleHubConnection{}, fmt.Errorf("nipcw: missing wallet pubkey")
	}
	if !haveSecret {
		return CircleHubConnection{}, fmt.Errorf("nipcw: missing secret")
	}
	return result, nil
}

func decodeCircleHubKeyHex(s, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nipcw: invalid %s hex: %w", field, err)
	}
	if len(b) != circleHubKeyLen {
		return nil, fmt.Errorf("nipcw: %s must be %d bytes, got %d", field, circleHubKeyLen, len(b))
	}
	return b, nil
}

func writeCircleHubTLV(buf *bytes.Buffer, typ uint8, value []byte) {
	buf.WriteByte(typ)
	buf.WriteByte(uint8(len(value))) //nolint:gosec // every EncodeCircleHubConnection call site pre-validates len(value) <= maxCircleHubTLVValueLen before calling writeCircleHubTLV
	buf.Write(value)
}

func readCircleHubTLV(data []byte) (typ uint8, value []byte, ok bool) {
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
