package nipIC

import (
	"encoding/hex"
	"fmt"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// NConnectionPrefix is the bech32 human-readable prefix for nconnection strings.
const NConnectionPrefix = "nconnection"

// TLV types within an nconnection payload — same convention NIP-19 uses for
// nprofile.
const (
	nconnTypeConnectionKey = 0 // 32-byte ConnectionKey, required, at most once
	nconnTypeRelay         = 1 // relay URL, UTF-8, repeatable
	nconnTypePlatform      = 2 // platform name, UTF-8, optional, at most once
)

// EncodeNConnection bundles a ConnectionKey with relay hints (and optionally
// a platform name) into a portable, shareable "nconnection1..." string — the
// same pattern NIP-19 uses for nprofile/nevent, handed e.g. from a Discord
// bot to a mobile wallet.
func EncodeNConnection(key ConnectionKey, relays []string, platform WebIdentity) (string, error) {
	keyBytes, err := hex.DecodeString(string(key))
	if err != nil {
		return "", fmt.Errorf("nipIC: invalid ConnectionKey hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("nipIC: ConnectionKey must be 32 bytes, got %d", len(keyBytes))
	}

	var tlv []byte
	tlv = append(tlv, nconnTypeConnectionKey, byte(len(keyBytes)))
	tlv = append(tlv, keyBytes...)

	for _, relay := range relays {
		relayBytes := []byte(relay)
		tlv = append(tlv, nconnTypeRelay, byte(len(relayBytes)))
		tlv = append(tlv, relayBytes...)
	}

	if platform != "" {
		platformBytes := []byte(platform)
		tlv = append(tlv, nconnTypePlatform, byte(len(platformBytes)))
		tlv = append(tlv, platformBytes...)
	}

	bits5, err := bech32.ConvertBits(tlv, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("nipIC: bech32 convert: %w", err)
	}
	encoded, err := bech32.Encode(NConnectionPrefix, bits5)
	if err != nil {
		return "", fmt.Errorf("nipIC: bech32 encode: %w", err)
	}
	return encoded, nil
}

// DecodeNConnection reverses EncodeNConnection.
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

	pos := 0
	var keyHex string
	for pos+2 <= len(data) {
		t := data[pos]
		l := int(data[pos+1])
		pos += 2
		if pos+l > len(data) {
			break
		}
		v := data[pos : pos+l]
		pos += l

		switch t {
		case nconnTypeConnectionKey:
			if l != 32 {
				return "", nil, "", fmt.Errorf("nipIC: ConnectionKey must be 32 bytes, got %d", l)
			}
			keyHex = hex.EncodeToString(v)
		case nconnTypeRelay:
			relays = append(relays, string(v))
		case nconnTypePlatform:
			platform = WebIdentity(v)
		}
	}

	if keyHex == "" {
		return "", nil, "", fmt.Errorf("nipIC: nconnection missing ConnectionKey")
	}
	return ConnectionKey(keyHex), relays, platform, nil
}
