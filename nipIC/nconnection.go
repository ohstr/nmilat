package nipIC

import (
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// NConnectionPrefix is the bech32 human-readable prefix for nconnection strings.
const NConnectionPrefix = "nconnection"

// TLV types within an nconnection payload (NIP-IC §The nconnection Bech32
// Encoding).
const (
	nconnTypeConnectionKey = 0 // 32 bytes, exactly one
	nconnTypeRelay         = 1 // relay URL, ASCII, repeatable
	nconnTypePlatform      = 2 // platform name, at most one
)

// EncodeNConnection bundles a ConnectionKey with relay hints and optionally a
// platform. It refuses a key that is not 64 lowercase hex, a platform outside
// ValidPlatformName, and a relay that is not ASCII or exceeds 255 bytes.
func EncodeNConnection(key ConnectionKey, relays []string, platform WebIdentity) (string, error) {
	if !isLowerHex64(string(key)) {
		return "", ErrConnectionKey
	}
	keyBytes, _ := hex.DecodeString(string(key))
	tlv := append([]byte{nconnTypeConnectionKey, 32}, keyBytes...)
	for _, relay := range relays {
		if len(relay) > 255 || !isASCII(relay) {
			return "", fmt.Errorf("nipIC: relay %q is not an ASCII URL of at most 255 bytes", relay)
		}
		tlv = append(tlv, nconnTypeRelay, byte(len(relay)))
		tlv = append(tlv, relay...)
	}
	if platform != "" {
		if !ValidPlatformName(platform) || len(platform) > 255 {
			return "", ErrPlatformName
		}
		tlv = append(tlv, nconnTypePlatform, byte(len(platform)))
		tlv = append(tlv, platform...)
	}
	bits5, err := bech32.ConvertBits(tlv, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipIC: bech32 convert: %w", err)
	}
	return bech32.Encode(NConnectionPrefix, bits5)
}

// DecodeNConnection parses an nconnection string. It rejects no type 0, more
// than one type 0 or type 2, a type 0 that is not 32 bytes, a TLV running past
// the end, and a type 2 that is not a valid platform name (no key is taken from
// it); unknown types are ignored.
func DecodeNConnection(s string) (key ConnectionKey, relays []string, platform WebIdentity, err error) {
	prefix, bits5, err := bech32.DecodeNoLimit(s)
	if err != nil {
		return "", nil, "", fmt.Errorf("nipIC: bech32 decode: %w", err)
	}
	if prefix != NConnectionPrefix {
		return "", nil, "", fmt.Errorf("nipIC: expected prefix %q, got %q", NConnectionPrefix, prefix)
	}
	data, err := bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return "", nil, "", fmt.Errorf("nipIC: bech32 convert: %w", err)
	}
	var keyHex string
	havePlatform := false
	for pos := 0; pos < len(data); {
		if pos+2 > len(data) {
			return "", nil, "", fmt.Errorf("nipIC: truncated TLV at offset %d", pos)
		}
		t, l := data[pos], int(data[pos+1])
		pos += 2
		if pos+l > len(data) {
			return "", nil, "", fmt.Errorf("nipIC: TLV at offset %d runs past the end", pos-2)
		}
		v := data[pos : pos+l]
		pos += l
		switch t {
		case nconnTypeConnectionKey:
			if keyHex != "" {
				return "", nil, "", fmt.Errorf("nipIC: more than one ConnectionKey")
			}
			if l != 32 {
				return "", nil, "", fmt.Errorf("nipIC: ConnectionKey must be 32 bytes, got %d", l)
			}
			keyHex = hex.EncodeToString(v)
		case nconnTypeRelay:
			relays = append(relays, string(v))
		case nconnTypePlatform:
			if havePlatform {
				return "", nil, "", fmt.Errorf("nipIC: more than one platform")
			}
			havePlatform = true
			platform = WebIdentity(v)
			if !ValidPlatformName(platform) {
				return "", nil, "", ErrPlatformName
			}
		}
	}
	if keyHex == "" {
		return "", nil, "", fmt.Errorf("nipIC: nconnection missing ConnectionKey")
	}
	return ConnectionKey(keyHex), relays, platform, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}
