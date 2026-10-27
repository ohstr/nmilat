package client

import (
	"fmt"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
)

// segwitHRPs are the segwit address HRPs by chain and network, as get_info
// reports them.
var segwitHRPs = map[string]map[string]string{
	"bitcoin":   {"mainnet": "bc", "testnet": "tb", "testnet4": "tb", "signet": "tb", "regtest": "bcrt"},
	"flokicoin": {"mainnet": "fc", "testnet": "tf", "regtest": "fcrt"},
}

// checkOrderAddress checks an order's on-chain address: all lowercase or all
// uppercase (returned lowercased), a valid segwit address (version 0 bech32 with
// a 20- or 32-byte program, versions 1 to 16 bech32m with 2 to 40 bytes) under
// the HRP of the Hub's chain and network. A chain and network with no known HRP
// still need a valid segwit address.
func checkOrderAddress(addr, chain, network string) (string, error) {
	if strings.ToLower(addr) != addr && strings.ToUpper(addr) != addr {
		return "", fmt.Errorf("%w: the address mixes upper and lower case", ErrOrderReplyInvalid)
	}
	addr = strings.ToLower(addr)
	hrp, data, version, err := bech32.DecodeGeneric(addr)
	if err != nil || len(data) < 1 {
		return "", fmt.Errorf("%w: the address is not a segwit address", ErrOrderReplyInvalid)
	}
	if want, ok := segwitHRPs[chain][network]; ok && hrp != want {
		return "", fmt.Errorf("%w: the address is for %q, not the Hub's %s %s", ErrOrderReplyInvalid, hrp, chain, network)
	}
	witnessVersion := data[0]
	prog, err := bech32.ConvertBits(data[1:], 5, 8, false)
	switch {
	case err != nil, witnessVersion > 16, len(prog) < 2, len(prog) > 40:
		return "", fmt.Errorf("%w: malformed witness program", ErrOrderReplyInvalid)
	case witnessVersion == 0 && (version != bech32.Version0 || (len(prog) != 20 && len(prog) != 32)):
		return "", fmt.Errorf("%w: malformed version 0 address", ErrOrderReplyInvalid)
	case witnessVersion > 0 && version != bech32.VersionM:
		return "", fmt.Errorf("%w: a version %d address is bech32m", ErrOrderReplyInvalid, witnessVersion)
	}
	return addr, nil
}
