package nipcash

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrFeeRate is a redeem_fee_ppm above 1,000,000.
var ErrFeeRate = errors.New("nipcash: a ppm rate is at most 1000000")

// RedeemFee is a slice's redeem fee and net payout (NIP-CASH §The Redeem Fee):
// base + floor(ppm × amount / 1,000,000), in integer arithmetic, capped at the
// amount.
func RedeemFee(amount, base, ppm uint64) (fee, net uint64, err error) {
	if ppm > 1_000_000 {
		return 0, 0, fmt.Errorf("%w: %d", ErrFeeRate, ppm)
	}
	prop := new(big.Int).Mul(new(big.Int).SetUint64(ppm), new(big.Int).SetUint64(amount))
	prop.Quo(prop, big.NewInt(1_000_000))
	total := new(big.Int).Add(prop, new(big.Int).SetUint64(base))
	if total.Cmp(new(big.Int).SetUint64(amount)) > 0 {
		return amount, 0, nil
	}
	fee = total.Uint64()
	return fee, amount - fee, nil
}

// InvoiceCheck is the outcome of RequiredInvoiceAmount: Code is "" when the
// invoice amount is right, else BAD_REQUEST or RESTRICTED.
type InvoiceCheck struct{ Code string }

// RequiredInvoiceAmount applies §Redeeming a Slice step 3 in its order: the
// required amount is the committed amount (same-node) or committed − fee; an
// amount param on an invoice that carries one is BAD_REQUEST; an amountless
// invoice without one resolves to 0; a required amount of 0 is RESTRICTED
// before any comparison; a resolved amount other than the required one is
// BAD_REQUEST.
func RequiredInvoiceAmount(committed, fee uint64, sameNode bool, invoiceMsat *uint64, amountParam *uint64) (uint64, InvoiceCheck) {
	required := committed
	if !sameNode {
		required = committed - min(fee, committed)
	}
	if invoiceMsat != nil && amountParam != nil {
		return required, InvoiceCheck{Code: ErrCodeBadRequest}
	}
	var resolved uint64
	switch {
	case invoiceMsat != nil:
		resolved = *invoiceMsat
	case amountParam != nil:
		resolved = *amountParam
	}
	if required == 0 {
		return required, InvoiceCheck{Code: ErrCodeRestricted}
	}
	if resolved != required {
		return required, InvoiceCheck{Code: ErrCodeBadRequest}
	}
	return required, InvoiceCheck{}
}

// RedeemInvoiceMillis is the amount a redeem invoice should carry for a row:
// its full amount when the payee is the bill's own minter (a same-node payment,
// fee-free), else its net redeemable amount. A payee given as a 66-hex
// compressed key is compared by its x-only part. The Hub decides with its own
// payment path; a wrong guess is a definitive BAD_REQUEST.
func RedeemInvoiceMillis(row RecipientStatus, payeeXOnly, minterXOnly string) (millis uint64, sameNode bool) {
	if minterXOnly != "" && HubIdentityEqual(minterXOnly, payeeXOnly) {
		return row.AmountMillis, true
	}
	return row.NetRedeemableMillis, false
}

// RedeemProgress is what a cash_status read says about a redeem whose own
// answer was lost (INTERNAL, an omission, an incomplete reply or a timeout).
type RedeemProgress int

const (
	// RedeemReleased: the own row is unclaimed; nothing was paid.
	RedeemReleased RedeemProgress = iota
	// RedeemInFlight: the own row is claimed; the payment may still settle, or
	// has settled on a wallet with other recipients.
	RedeemInFlight
	// RedeemDone: the bill is gone (a tombstone).
	RedeemDone
)

// RedeemProgressOf reads a cash_status answer: a tombstone is done, a claimed
// own row in flight, an unclaimed one released.
func RedeemProgressOf(row *RecipientStatus, tomb *Tombstone) RedeemProgress {
	switch {
	case tomb != nil:
		return RedeemDone
	case row != nil && row.Claimed:
		return RedeemInFlight
	default:
		return RedeemReleased
	}
}
