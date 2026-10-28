package nipcw

import (
	"math"
	"math/bits"

	"github.com/ohstr/nmilat/nip47"
)

// mulDivFloor is floor(a × b / 1,000,000), saturating at MaxUint64.
func mulDivFloor(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi >= 1_000_000 {
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, 1_000_000)
	return q
}

func addSat(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return s
}

// FeeSkim is the fees_ppm fee on a Lightning payment (kind 4) of amount:
// ppm × amount / 1,000,000, rounded down (NIP-CW §Fees). No other kind of
// payment carries it.
func FeeSkim(amount, ppm uint64) uint64 { return mulDivFloor(amount, ppm) }

// RoutingFeeReserve is the routing fee reserved for a Lightning payment of
// amount: the larger of min_millis and amount × ppm / 1,000,000, rounded down
// (NIP-CW §Own Funds and Caps). A negative field counts as 0.
func RoutingFeeReserve(amount uint64, r nip47.FeeReserve) uint64 {
	return max(nonNegative(r.MinMillis), mulDivFloor(amount, nonNegative(r.Ppm)))
}

// MaxCost is the most a Lightning payment of amount may cost: the amount, its
// fees_ppm fee and its routing-fee reserve. It is what a Hub holds back and
// counts against the send cap while the payment is in flight.
func MaxCost(amount, feesPpm uint64, r nip47.FeeReserve) uint64 {
	return addSat(addSat(amount, FeeSkim(amount, feesPpm)), RoutingFeeReserve(amount, r))
}

func nonNegative(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}
