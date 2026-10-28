package cashtest

import (
	"sync"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// slicePaying is a slice whose redeem payment FaultHoldPayments holds: claimed,
// not terminal.
const slicePaying = "paying"

// heldRedeem is one redeem payment held in flight.
type heldRedeem struct {
	bill    *ledgerBill
	slice   *ledgerSlice
	invoice *fakeInvoice
}

// heldRedeems are the ledgers' held payments, by ledger, kept outside the
// ledger's own fields; heldMu guards the map and is taken under l.mu.
var (
	heldMu      sync.Mutex
	heldRedeems = map[*WithdrawLedger][]heldRedeem{}
)

// takeHeld removes and returns l's held payments.
func takeHeld(l *WithdrawLedger) []heldRedeem {
	heldMu.Lock()
	defer heldMu.Unlock()
	held := heldRedeems[l]
	delete(heldRedeems, l)
	return held
}

// holdRedeemLocked claims s for a redeem whose payment is held: the claim
// proof is consumed, nothing is paid, and the redeem is answered INTERNAL, the
// answer of a Hub whose payment may still settle (NIP-CASH §Redeeming a Slice,
// step 4).
func (l *WithdrawLedger) holdRedeemLocked(b *ledgerBill, s *ledgerSlice, fi *fakeInvoice, verdict nipcash.ClaimVerdict, identityEvent string) *transport.Result {
	s.state, s.claimedAt = slicePaying, l.nowLocked()
	l.consumeLocked(verdict, identityEvent)
	heldMu.Lock()
	heldRedeems[l] = append(heldRedeems[l], heldRedeem{bill: b, slice: s, invoice: fi})
	heldMu.Unlock()
	return errResult(nipcash.ErrCodeInternal, "the payment is in flight", "")
}

// SettleHeldRedeems settles every held redeem payment: its invoice is paid and
// its slice redeemed (the bill destroyed once drained). It returns how many.
func (l *WithdrawLedger) SettleHeldRedeems() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	held := takeHeld(l)
	for _, h := range held {
		h.invoice.paid = true
		h.slice.state = nipcash.ReasonRedeemed
		l.destroyIfDrainedLocked(h.bill, h.slice)
	}
	return len(held)
}

// FailHeldRedeems fails every held redeem payment: nothing was paid and each
// slice is claimable again. It returns how many.
func (l *WithdrawLedger) FailHeldRedeems() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	held := takeHeld(l)
	for _, h := range held {
		h.slice.state, h.slice.claimedAt = "", 0
	}
	return len(held)
}
