package client

import (
	"fmt"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

// segwitHRPs are the segwit address HRPs by chain and network, as get_info
// reports them.
var segwitHRPs = map[string]map[string]string{
	"bitcoin":   {"mainnet": "bc", "testnet": "tb", "testnet4": "tb", "signet": "tb", "regtest": "bcrt"},
	"flokicoin": {"mainnet": "fc", "testnet": "tf", "regtest": "fcrt"},
}

// orderAddress checks an order's on-chain address with nipcash's witness
// address rules: all lowercase or all uppercase (returned lowercased), a valid
// witness address under the HRP of the Hub's chain and network; under any of
// the chain's HRPs when the network has no known one; under its own HRP when
// the chain is unknown too.
func orderAddress(addr, chain, network string) (string, error) {
	norm, err := nipcash.NormalizeAddress(addr)
	if err != nil || len(norm) != len(addr) {
		return "", fmt.Errorf("%w: the address is not single-case", ErrOrderReplyInvalid)
	}
	if hrp, ok := segwitHRPs[chain][network]; ok {
		_, err = nipcash.ClassifyAddress(norm, hrp)
	} else if hrps, ok := nipcash.WithdrawHRPs(chain); ok {
		_, _, err = nipcash.ClassifyAddressAmong(norm, hrps)
	} else {
		_, _, err = nipcash.DecodeWitnessAddress(norm, "")
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOrderReplyInvalid, err)
	}
	return norm, nil
}

// checkOrderInvoice is nipCO.CheckOrderInvoice as ErrOrderReplyInvalid.
func checkOrderInvoice(o *nipCO.Order) error {
	if err := nipCO.CheckOrderInvoice(o); err != nil {
		return fmt.Errorf("%w: %v", ErrOrderReplyInvalid, err)
	}
	return nil
}
