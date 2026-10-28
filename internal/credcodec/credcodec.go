// Package credcodec is the one bech32 and TLV codec behind every credential
// string the cash NIPs define: cash tokens, cashhub1, cashorder1 and circlehub1.
//
// It exists so the case rule and the connection-string layout are written once.
// A decoder accepts a string all in lowercase or all in uppercase and refuses one
// that mixes the two, as BIP-173 requires (NIP-CASH §Wire Format); DecodeBech32 is
// the only place a credential decoder calls bech32.DecodeNoLimit.
package credcodec

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// ErrMixedCase is a bech32 string with both upper- and lowercase letters.
var ErrMixedCase = errors.New("bech32 string mixes upper and lower case")

// ErrBech32m is a string carrying a bech32m checksum: credentials are NIP-19
// bech32 (BIP-173), and only on-chain addresses use bech32m (BIP-350).
var ErrBech32m = errors.New("bech32m checksum where a bech32 checksum is required")

// MaxTLVValueLen is the largest value one TLV entry's length byte can carry.
const MaxTLVValueLen = 255

// DecodeBech32 refuses a mixed-case string or a bech32m checksum, lowercases it
// and decodes it with no length limit, returning the lowercase HRP and the
// 8-bit data.
func DecodeBech32(s string) (hrp string, data []byte, err error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, ErrMixedCase
	}
	hrp, bits5, version, err := bech32.DecodeNoLimitWithVersion(strings.ToLower(s))
	if err != nil {
		return "", nil, fmt.Errorf("invalid bech32: %w", err)
	}
	if version != bech32.Version0 {
		return "", nil, ErrBech32m
	}
	data, err = bech32.ConvertBits(bits5, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("failed to convert bits: %w", err)
	}
	return hrp, data, nil
}

// EncodeBech32 encodes data under hrp, in lowercase.
func EncodeBech32(hrp string, data []byte) (string, error) {
	bits5, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	return bech32.Encode(hrp, bits5)
}

// WriteTLV appends one entry. The caller has checked len(value) <= MaxTLVValueLen.
func WriteTLV(buf *bytes.Buffer, typ uint8, value []byte) {
	buf.WriteByte(typ)
	buf.WriteByte(uint8(len(value))) //nolint:gosec // callers bound len(value) by MaxTLVValueLen
	buf.Write(value)
}

// ReadTLV reads the entry at the start of data; ok is false when it is truncated.
func ReadTLV(data []byte) (typ uint8, value []byte, ok bool) {
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

// IsBlankHint reports a relay hint that is empty once ASCII whitespace is trimmed.
func IsBlankHint(s string) bool { return strings.Trim(s, " \t\n\r\f\v") == "" }

// IsASCII reports whether every byte of s is ASCII.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

// CountUsableHints counts the hints that are not blank.
func CountUsableHints(hints []string) int {
	n := 0
	for _, h := range hints {
		if !IsBlankHint(h) {
			n++
		}
	}
	return n
}
