package nipCO

import (
	"fmt"
	"math/bits"
)

// The two payment kinds (NIP-CO §Request, payment).
const (
	PaymentLightning = "lightning"
	PaymentOnchain   = "onchain"
)

// OrderFee is an order's fee and the amount the buyer pays (NIP-CO §Response):
// fee = fee_base + ⌊fee_ppm × amount / 1,000,000⌋, computed without overflow; on
// chain the fee is rounded up so that pay = amount + fee is a whole number of
// base units (a multiple of 1000), and amountMillis must itself be one. An
// unknown kind, an on-chain amount that is not a multiple of 1000 or a result
// above 2^64 − 1 is an error.
func OrderFee(kind string, k KindTerms, amountMillis uint64) (fee, pay uint64, err error) {
	if kind != PaymentLightning && kind != PaymentOnchain {
		return 0, 0, fmt.Errorf("%w: payment %q", ErrOrderRequest, kind)
	}
	if kind == PaymentOnchain && amountMillis%1000 != 0 {
		return 0, 0, fmt.Errorf("%w: an on-chain amount is a multiple of 1000 millis", ErrOrderRequest)
	}
	hi, lo := bits.Mul64(k.FeePpm, amountMillis)
	if hi >= 1_000_000 {
		return 0, 0, ErrOrderAmount
	}
	prop, _ := bits.Div64(hi, lo, 1_000_000)
	fee, carry := bits.Add64(k.FeeBase, prop, 0)
	if carry != 0 {
		return 0, 0, ErrOrderAmount
	}
	pay, carry = bits.Add64(amountMillis, fee, 0)
	if carry != 0 {
		return 0, 0, ErrOrderAmount
	}
	if kind == PaymentOnchain {
		if r := pay % 1000; r != 0 {
			up := 1000 - r
			if pay, carry = bits.Add64(pay, up, 0); carry != 0 {
				return 0, 0, ErrOrderAmount
			}
			fee += up
		}
	}
	return fee, pay, nil
}

// ConfirmationsFor is the n of the tier a payment of valueMillis falls in: the
// first tier whose up_to_millis is at least the value, else the open last tier
// (NIP-CO §Terms). Tiers with no open last tier, and no tier at all, are an error.
func ConfirmationsFor(tiers []Tier, valueMillis uint64) (uint32, error) {
	for _, t := range tiers {
		if t.UpToMillis == nil || *t.UpToMillis >= valueMillis {
			return t.N, nil
		}
	}
	return 0, fmt.Errorf("%w: no confirmation tier covers %d millis", ErrOrderTerms, valueMillis)
}

// MintSplit is the bills one payment mints (NIP-CO §Minting): nil when what it
// brought in is at most the fee, else received − fee as bills of maxMillis and
// then the rest. maxMillis 0 is read as no bound (one bill).
func MintSplit(receivedMillis, feeMillis, maxMillis uint64) []uint64 {
	if receivedMillis <= feeMillis {
		return nil
	}
	rest := receivedMillis - feeMillis
	if maxMillis == 0 {
		return []uint64{rest}
	}
	var out []uint64
	for rest > maxMillis {
		out = append(out, maxMillis)
		rest -= maxMillis
	}
	return append(out, rest)
}
