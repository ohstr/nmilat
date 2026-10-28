package nipcash

import (
	"errors"
	"fmt"
	"math/bits"
)

// ErrFeeOverflow is a withdraw fee whose sum does not fit in 64 bits.
var ErrFeeOverflow = errors.New("nipcash: the withdraw fee overflows")

// WithdrawFee is an on-chain withdrawal's fee and payout (NIP-CASH §The
// Withdraw Fee): hub = base + floor(ppm × amount / 1,000,000); fee =
// max(network + hub, redeemFee), capped at the amount, then raised so the
// payout is a whole number of base units (a multiple of 1000 millis); payout
// = amount − fee. redeemFeeMillis is RedeemFee of the slice's own terms;
// withdrawFeeBase and withdrawFeePpm are the Hub's current terms. A payout of 0
// is returned, never refused here (a Hub refuses it below_min). A ppm above
// 1,000,000 is ErrFeeRate; an overflow ErrFeeOverflow.
func WithdrawFee(amountMillis, networkFeeMillis, withdrawFeeBase, withdrawFeePpm, redeemFeeMillis uint64) (hubFee, fee, payout uint64, err error) {
	if withdrawFeePpm > 1_000_000 {
		return 0, 0, 0, fmt.Errorf("%w: withdraw_fee_ppm %d", ErrFeeRate, withdrawFeePpm)
	}
	hi, lo := bits.Mul64(withdrawFeePpm, amountMillis)
	prop, _ := bits.Div64(hi, lo, 1_000_000) // hi < 1e6 as ppm ≤ 1e6, so no panic
	hubFee, carry := bits.Add64(withdrawFeeBase, prop, 0)
	if carry != 0 {
		return 0, 0, 0, ErrFeeOverflow
	}
	fee, carry = bits.Add64(networkFeeMillis, hubFee, 0)
	if carry != 0 {
		return 0, 0, 0, ErrFeeOverflow
	}
	fee = max(fee, redeemFeeMillis)
	fee = min(fee, amountMillis)
	payout = amountMillis - fee
	fee += payout % 1000
	payout -= payout % 1000
	return hubFee, fee, payout, nil
}
