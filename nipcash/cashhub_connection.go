package nipcash

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// CashHubConnectionHRP is the fixed bech32 prefix for a Cash Hub's own
// connection string (NIP-CASH §The Cash Hub Connection) — the one its owner
// calls mint_cash over, as distinct from a Cash Wallet's own lokicash1...
// token (§The Cash Token).
const CashHubConnectionHRP = "cashhub"

// cashHubTLVLabel is the one TLV type this format adds beyond the pairing
// data types 0-2 already share with the cash-token-family format (see the
// const block in token.go) — an optional human-readable label. It reuses
// the numeric value token.go's tlvIdentityRequired also uses, under a
// different name: the two are decoded by entirely different functions
// (DecodeCashHubConnection vs Decode) over entirely different HRPs, so
// there's no actual collision, exactly as NIP-CASH's own spec text notes
// ("this format's type numbers are scoped to its own HRP").
const cashHubTLVLabel uint8 = 3

// CashHubConnection is the decoded content of a Cash Hub's own
// cashhub1... connection string: the same pairing data PairingInfo-shaped
// types carry, plus an optional human-readable label. Unlike a cash token
// (Token), it never carries an identity-required hint or mint provenance —
// those describe a slice of cash, not a Hub connection.
type CashHubConnection struct {
	WalletPubkey string   // hex, 32 bytes — the Hub's own pubkey
	Secret       string   // hex, 32 bytes — the NWC connection secret
	RelayURLs    []string // in encoded order
	Label        string   // optional, "" if not set
}

// EncodeCashHubConnection packages c into a cashhub1... string.
// WalletPubkey and Secret MUST each be a 32-byte hex string.
func EncodeCashHubConnection(c CashHubConnection) (string, error) {
	pubkey, err := decodeKeyHex(c.WalletPubkey, "wallet pubkey")
	if err != nil {
		return "", err
	}
	secret, err := decodeKeyHex(c.Secret, "secret")
	if err != nil {
		return "", err
	}
	for _, url := range c.RelayURLs {
		if len(url) > maxTLVValueLen {
			return "", fmt.Errorf("nipcash: relay url exceeds %d bytes: %q", maxTLVValueLen, url)
		}
	}
	if len(c.Label) > maxTLVValueLen {
		return "", fmt.Errorf("nipcash: label exceeds %d bytes", maxTLVValueLen)
	}

	buf := &bytes.Buffer{}
	writeTLV(buf, tlvWalletPubkey, pubkey)
	for _, url := range c.RelayURLs {
		writeTLV(buf, tlvRelay, []byte(url))
	}
	writeTLV(buf, tlvSecret, secret)
	if c.Label != "" {
		writeTLV(buf, cashHubTLVLabel, []byte(c.Label))
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipcash: failed to convert bits: %w", err)
	}
	return bech32.Encode(CashHubConnectionHRP, bits5)
}

// DecodeCashHubConnection parses a cashhub1... string back into its pairing
// data. It rejects anything missing either required field (wallet pubkey or
// secret), carrying a malformed length for either, or repeating either one.
// An unrecognized TLV type is ignored rather than rejected, so a future
// field can be added without breaking older decoders.
func DecodeCashHubConnection(s string) (CashHubConnection, error) {
	hrp, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		return CashHubConnection{}, fmt.Errorf("nipcash: invalid bech32: %w", err)
	}
	if hrp != CashHubConnectionHRP {
		return CashHubConnection{}, fmt.Errorf("nipcash: unexpected hrp %q, want %q", hrp, CashHubConnectionHRP)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return CashHubConnection{}, fmt.Errorf("nipcash: failed to convert bits: %w", err)
	}

	var result CashHubConnection
	haveWalletPubkey := false
	haveSecret := false
	haveLabel := false
	curr := 0
	for curr < len(data) {
		typ, value, ok := readTLV(data[curr:])
		if !ok {
			return CashHubConnection{}, fmt.Errorf("nipcash: truncated TLV entry at offset %d", curr)
		}
		switch typ {
		case tlvWalletPubkey:
			if len(value) != keyLen {
				return CashHubConnection{}, fmt.Errorf("nipcash: wallet pubkey must be %d bytes, got %d", keyLen, len(value))
			}
			if haveWalletPubkey {
				return CashHubConnection{}, fmt.Errorf("nipcash: duplicate wallet pubkey entry")
			}
			result.WalletPubkey = hex.EncodeToString(value)
			haveWalletPubkey = true
		case tlvRelay:
			result.RelayURLs = append(result.RelayURLs, string(value))
		case tlvSecret:
			if len(value) != keyLen {
				return CashHubConnection{}, fmt.Errorf("nipcash: secret must be %d bytes, got %d", keyLen, len(value))
			}
			if haveSecret {
				return CashHubConnection{}, fmt.Errorf("nipcash: duplicate secret entry")
			}
			result.Secret = hex.EncodeToString(value)
			haveSecret = true
		case cashHubTLVLabel:
			if haveLabel {
				return CashHubConnection{}, fmt.Errorf("nipcash: duplicate label entry")
			}
			result.Label = string(value)
			haveLabel = true
		default:
			// Unknown TLV type: ignore, same forward-compatibility rule as
			// the cash-token-family format's own Decode.
		}
		curr += 2 + len(value)
	}

	if !haveWalletPubkey {
		return CashHubConnection{}, fmt.Errorf("nipcash: missing wallet pubkey")
	}
	if !haveSecret {
		return CashHubConnection{}, fmt.Errorf("nipcash: missing secret")
	}
	return result, nil
}
