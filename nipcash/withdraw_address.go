package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/base58"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// ScriptType is a witness output type: the exact pair of witness version and
// program length (NIP-CASH §Quoting a Withdrawal). On the wire it is the pair
// [version, length].
type ScriptType struct{ Version, ProgramLen uint8 }

// MarshalJSON writes [version, length].
func (s ScriptType) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]uint8{s.Version, s.ProgramLen})
}

// UnmarshalJSON reads [version, length].
func (s *ScriptType) UnmarshalJSON(b []byte) error {
	var pair [2]uint8
	if err := json.Unmarshal(b, &pair); err != nil {
		return fmt.Errorf("nipcash: a script type is [witness_version, program_length]: %w", err)
	}
	s.Version, s.ProgramLen = pair[0], pair[1]
	return nil
}

// Valid reports a witness type an address can have: version 0 with a 20- or
// 32-byte program, versions 1 to 16 with 2 to 40 bytes.
func (s ScriptType) Valid() bool {
	switch {
	case s.Version > 16, s.ProgramLen < 2, s.ProgramLen > 40:
		return false
	case s.Version == 0:
		return s.ProgramLen == 20 || s.ProgramLen == 32
	}
	return true
}

var (
	// ErrAddressMalformed is an address that is not a lowercase witness address
	// under BIP-173/BIP-350: a Hub refuses it BAD_REQUEST.
	ErrAddressMalformed = errors.New("nipcash: malformed withdrawal address")
	// ErrAddressNetwork is a valid witness address of another network (another
	// HRP): RESTRICTED with detail network.
	ErrAddressNetwork = errors.New("nipcash: the address is for another network")
	// ErrAddressNoWitness is a valid base58check address, which has no witness
	// program: RESTRICTED with detail script_type.
	ErrAddressNoWitness = errors.New("nipcash: the address has no witness program")
	// ErrScriptTypeNotPaid is an address whose script type the Hub does not pay.
	ErrScriptTypeNotPaid = errors.New("nipcash: the Hub does not pay this address's script type")
)

// maxAddressLen is BIP-173's limit on a segwit address.
const maxAddressLen = 90

// DecodeWitnessAddress decodes a witness address under hrp, following the
// BIP-173/BIP-350 reference decoder: at most 90 characters, lowercase only
// (an uppercase string is malformed here; see NormalizeAddress), a bech32
// checksum for version 0 and bech32m for versions 1 to 16, the 5-to-8-bit
// conversion without padding, a program of 2 to 40 bytes and of 20 or 32 for
// version 0. A valid address under another HRP is ErrAddressNetwork; a valid
// base58check string is ErrAddressNoWitness; anything else ErrAddressMalformed.
// hrp "" accepts the address's own HRP.
func DecodeWitnessAddress(addr, hrp string) (version uint8, program []byte, err error) {
	version, program, got, err := decodeWitness(addr)
	if err != nil {
		return 0, nil, err
	}
	if hrp != "" && got != hrp {
		return 0, nil, fmt.Errorf("%w: %q", ErrAddressNetwork, got)
	}
	return version, program, nil
}

// decodeWitness decodes a witness address under its own HRP.
func decodeWitness(addr string) (version uint8, program []byte, hrp string, err error) {
	if len(addr) > maxAddressLen {
		return 0, nil, "", fmt.Errorf("%w: longer than %d characters", ErrAddressMalformed, maxAddressLen)
	}
	hrp, data, checksum, err := bech32.DecodeGeneric(addr)
	if err != nil {
		if _, _, b58err := base58.CheckDecode(addr); b58err == nil {
			return 0, nil, "", ErrAddressNoWitness
		}
		return 0, nil, "", fmt.Errorf("%w: not bech32", ErrAddressMalformed)
	}
	if strings.ToLower(addr) != addr {
		return 0, nil, "", fmt.Errorf("%w: not lowercase", ErrAddressMalformed)
	}
	if len(data) < 1 {
		return 0, nil, "", fmt.Errorf("%w: no witness version", ErrAddressMalformed)
	}
	if data[0] > 16 {
		return 0, nil, "", fmt.Errorf("%w: witness version %d", ErrAddressMalformed, data[0])
	}
	version = data[0]
	program, err = bech32.ConvertBits(data[1:], 5, 8, false)
	switch {
	case err != nil:
		return 0, nil, "", fmt.Errorf("%w: program padding", ErrAddressMalformed)
	case !(ScriptType{Version: version, ProgramLen: uint8(min(len(program), 255))}).Valid():
		return 0, nil, "", fmt.Errorf("%w: a version %d program of %d bytes", ErrAddressMalformed, version, len(program))
	case version == 0 && checksum != bech32.Version0:
		return 0, nil, "", fmt.Errorf("%w: a version 0 address takes a bech32 checksum", ErrAddressMalformed)
	case version > 0 && checksum != bech32.VersionM:
		return 0, nil, "", fmt.Errorf("%w: a version %d address takes a bech32m checksum", ErrAddressMalformed, version)
	}
	return version, program, hrp, nil
}

// ClassifyAddress is the script type of a witness address under hrp, with
// DecodeWitnessAddress's errors. It never looks at whose address it is: a Hub
// checks its own wallet last, at the call (NIP-CASH §Processing Algorithm).
func ClassifyAddress(addr, hrp string) (ScriptType, error) {
	v, prog, err := DecodeWitnessAddress(addr, hrp)
	if err != nil {
		return ScriptType{}, err
	}
	return ScriptType{Version: v, ProgramLen: uint8(len(prog))}, nil
}

// ClassifyAddressAmong is ClassifyAddress under whichever of hrps the address
// carries, returning that HRP; a valid witness address of none of them is
// ErrAddressNetwork.
func ClassifyAddressAmong(addr string, hrps []string) (ScriptType, string, error) {
	v, prog, hrp, err := decodeWitness(addr)
	if err != nil {
		return ScriptType{}, "", err
	}
	for _, h := range hrps {
		if h == hrp {
			return ScriptType{Version: v, ProgramLen: uint8(len(prog))}, hrp, nil
		}
	}
	return ScriptType{}, "", fmt.Errorf("%w: %q", ErrAddressNetwork, hrp)
}

// NormalizeAddress is the client's form of an address typed by a person:
// trimmed, and lowercased when it is all uppercase. A valid base58check address
// (which is case-sensitive and has no witness program) is ErrAddressNoWitness;
// any other string mixing cases is ErrAddressMalformed. It checks nothing else;
// ClassifyAddress does.
func NormalizeAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if _, _, err := base58.CheckDecode(s); err == nil {
		return "", ErrAddressNoWitness
	}
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	switch s {
	case lower:
		return s, nil
	case upper:
		return lower, nil
	}
	return "", fmt.Errorf("%w: mixed case", ErrAddressMalformed)
}

// PaysScriptType reports whether st is among pays.
func PaysScriptType(pays []ScriptType, st ScriptType) bool {
	for _, p := range pays {
		if p == st {
			return true
		}
	}
	return false
}

// WitnessScript is the output script paying a witness program: OP_0 or OP_1 to
// OP_16, then a push of the program.
func WitnessScript(version uint8, program []byte) []byte {
	op := byte(0x00)
	if version > 0 {
		op = 0x50 + version
	}
	return append([]byte{op, byte(len(program))}, program...)
}

// withdrawHRPs is the client-local table of witness HRPs by chain: every
// network of the coin, main first.
var withdrawHRPs = map[string][]string{
	"bitcoin":   {"bc", "tb", "bcrt"},
	"flokicoin": {"fc", "tf", "fcrt", "sf"},
}

// WithdrawHRPs is every witness HRP of chain's networks (main, test, regtest,
// and signet or simnet where they differ), main first; false for a chain this
// table does not know, which then gets no local network check.
func WithdrawHRPs(chain string) ([]string, bool) {
	h, ok := withdrawHRPs[chain]
	return append([]string(nil), h...), ok
}

// ScriptTypeList is the terms' script_types as ScriptType values, skipping
// a pair outside 0 to 255 (Validate refuses those).
func (w WithdrawTerms) ScriptTypeList() []ScriptType {
	out := make([]ScriptType, 0, len(w.ScriptTypes))
	for _, p := range w.ScriptTypes {
		if p[0] < 0 || p[0] > 255 || p[1] < 0 || p[1] > 255 {
			continue
		}
		out = append(out, ScriptType{Version: uint8(p[0]), ProgramLen: uint8(p[1])})
	}
	return out
}
