package cashtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// cash_redeem and cash_transfer on the ledger's bills (NIP-CASH §Redeeming a
// Slice, §Transferring and Splitting a Slice), and the owner's delete and
// removal (§Lifecycle and Deletion, §Removing a Recipient).
//
// A redemption pays through a fake Lightning payee: Invoice issues an invoice
// the ledger can pay, and paying it reveals its preimage. Any other invoice
// fails before it can have settled (PAYMENT_FAILED, the slice claimable), as
// does every payment under FaultRouteOverBound. The payee is never the Hub's
// own node, so the required invoice amount is the slice's net redeemable one.

// fakeInvoice is one invoice of the fake payee.
type fakeInvoice struct {
	preimage string
	paid     bool
}

// callRecord is a committed transfer's record, for cash_lookup.
type callRecord struct {
	wallet         string
	authorizer     string // the claim-proof signer; "" for a cash commitment
	cashCommitment string
	result         json.RawMessage
}

// FakeInvoiceHRP is the human-readable part of the fake payee's invoices.
const FakeInvoiceHRP = "lnbcrt"

// Invoice is a fresh invoice of the fake Lightning payee for millis (0: an
// amountless invoice) that the ledger pays once.
func (l *WithdrawLedger) Invoice(millis uint64) string {
	preimage := randHex(32)
	raw, _ := hex.DecodeString(preimage)
	hash := sha256.Sum256(raw)
	inv := FakeBolt11(hash[:], millis)
	l.mu.Lock()
	l.invoices[hex.EncodeToString(hash[:])] = &fakeInvoice{preimage: preimage}
	l.mu.Unlock()
	return inv
}

// FakeBolt11 is an unsigned BOLT11 string (zero timestamp and signature) under
// FakeInvoiceHRP carrying paymentHash and millis (0: amountless): enough for
// nip57.DecodeBolt11, never payable on a real network.
func FakeBolt11(paymentHash []byte, millis uint64) string {
	hrp := FakeInvoiceHRP
	if millis > 0 {
		hrp += strconv.FormatUint(millis*10, 10) + "p"
	}
	words := make([]byte, 7)
	data, err := bech32.ConvertBits(paymentHash, 8, 5, true)
	if err != nil {
		panic("cashtest: invoice: " + err.Error())
	}
	words = append(words, 1, byte(len(data)/32), byte(len(data)%32))
	words = append(words, data...)
	words = append(words, make([]byte, 104)...)
	s, err := bech32.Encode(hrp, words)
	if err != nil {
		panic("cashtest: invoice: " + err.Error())
	}
	return s
}

// locateLocked is step 1 of cash_redeem and cash_transfer: a cash_secret's
// cash-mode slice, else the slice registered to the identity, an unclaimed one
// first. A terminal or expired slice is RESTRICTED.
func (l *WithdrawLedger) locateLocked(b *ledgerBill, cashSecret, idType, idValue string) (*ledgerSlice, *transport.Result) {
	var s *ledgerSlice
	if b.cashMode && cashSecret != "" {
		s = b.slices[0]
	} else if idType == "pubkey" || idType == "connection_key" {
		for _, c := range b.slices {
			if c.idType == idType && c.idValue == idValue && (s == nil || c.live()) {
				s = c
			}
		}
	}
	switch {
	case s == nil:
		return nil, errResult(nipcash.ErrCodeNotFound, "no slice", "")
	case !s.live() || !nipcash.SliceLive(l.nowLocked(), b.expiresAt):
		return nil, errResult(nipcash.ErrCodeRestricted, "slice claimed, terminal or expired", "")
	}
	return s, nil
}

// authorizeLocked is the authorization step: the cash secret, or the claim
// proof bound as bind and signed by the item proof's signer.
func (l *WithdrawLedger) authorizeLocked(it *ledgerItem, s *ledgerSlice, cashSecret, identityEvent, attestation string,
	bind nipcash.ClaimBinding) (nipcash.ClaimVerdict, *transport.Result) {
	if s.idType == "cash" {
		if !secretMatches(cashSecret, s.idValue) {
			return nipcash.ClaimVerdict{}, errResult(nipcash.ErrCodeUnauthorized, "cash_secret", "")
		}
		return nipcash.ClaimVerdict{}, nil
	}
	verdict, err := nipcash.VerifyClaimProof(identityEvent, nipcash.ClaimExpectation{
		Binding: bind, SliceType: s.idType, SliceValue: s.idValue, SliceIA: s.ia, Attestation: attestation,
		IATrusted: l.iaTrusted, Consumed: func(id string) bool { _, ok := l.consumed[id]; return ok },
	}, it.c.Now)
	if err != nil {
		return verdict, errCode(err)
	}
	if !nipcash.ItemSignerMatchesClaim(it.signer, verdict) {
		return verdict, errResult(nipcash.ErrCodeUnauthorized, "the item proof is not the claim proof's signer", "")
	}
	if s.idType == "connection_key" {
		l.ckHolder[sliceKey(s)] = verdict.Signer
	}
	return verdict, nil
}

// consumeLocked consumes a committed call's claim proof.
func (l *WithdrawLedger) consumeLocked(v nipcash.ClaimVerdict, identityEvent string) {
	if v.RecomputedID == "" {
		return
	}
	var ev nip01.Event
	_ = json.Unmarshal([]byte(identityEvent), &ev)
	l.consumed[v.RecomputedID] = nipcash.ClaimRetainUntil(int64(ev.CreatedAt))
}

// commitPastDeadline is the deadline rechecked as the call commits.
func (l *WithdrawLedger) commitPastDeadline(it *ledgerItem) *transport.Result {
	if !nipcash.CommitAllowed(it.c.Envelope.NotAfter, l.h.Clock.Now().Unix()) {
		return errResult(nipcash.ErrCodeBadRequest, "the call reached its commit past its deadline", "")
	}
	return nil
}

// redeemLocked is cash_redeem.
func (l *WithdrawLedger) redeemLocked(it *ledgerItem) *transport.Result {
	var req nipcash.CashRedeemRequest
	if json.Unmarshal(it.c.Item.Params, &req) != nil {
		return errResult(nipcash.ErrCodeBadRequest, "params", "")
	}
	inv, err := nip57.DecodeBolt11(req.Invoice)
	if err != nil || inv.AmountMloki < 0 {
		return errResult(nipcash.ErrCodeBadRequest, "invoice", "")
	}
	b := it.b
	s, res := l.locateLocked(b, req.CashSecret, req.IdentityType, req.IdentityValue)
	if res != nil {
		return res
	}
	verdict, res := l.authorizeLocked(it, s, req.CashSecret, req.IdentityEvent, req.AttestationEvent,
		nipcash.ClaimBinding{Method: nipcash.MethodCashRedeem, Wallet: b.wallet, Bolt11Hash: inv.PaymentHash})
	if res != nil {
		return res
	}
	fee, _, err := nipcash.RedeemFee(s.amount, s.redeemBase, s.redeemPpm)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "fee terms", "")
	}
	var invoiceMillis *uint64
	if inv.AmountMloki > 0 {
		v := uint64(inv.AmountMloki)
		invoiceMillis = &v
	}
	if _, check := nipcash.RequiredInvoiceAmount(s.amount, fee, false, invoiceMillis, req.Amount); check.Code != "" {
		return errResult(check.Code, "invoice amount", "")
	}
	if res := l.commitPastDeadline(it); res != nil {
		return res
	}
	fi := l.invoices[inv.PaymentHash]
	if fi == nil || fi.paid || it.c.Fault.Is(FaultRouteOverBound) {
		return errResult(nipcash.ErrCodePaymentFailed, "the payment failed", "")
	}
	if it.c.Fault.Is(FaultHoldPayments) {
		return l.holdRedeemLocked(b, s, fi, verdict, req.IdentityEvent)
	}
	fi.paid = true
	s.state, s.claimedAt = nipcash.ReasonRedeemed, l.nowLocked()
	l.consumeLocked(verdict, req.IdentityEvent)
	l.destroyIfDrainedLocked(b, s)
	return okResult(map[string]any{"preimage": fi.preimage, "fees_paid": fee})
}

func isHex64(s string) bool { return nipcash.ValidCommitment(s) }

func liveSlices(b *ledgerBill) int {
	n := 0
	for _, s := range b.slices {
		if s.live() {
			n++
		}
	}
	return n
}

// transferLocked is cash_transfer: in place, or a spin-off into one or two new
// wallets. A zap transfer is always a spin-off, its new_identity's wallet signed
// under the zap scheme (ledger_merge.go).
func (l *WithdrawLedger) transferLocked(it *ledgerItem) *transport.Result {
	var req nipcash.CashTransferRequest
	if json.Unmarshal(it.c.Item.Params, &req) != nil {
		return errResult(nipcash.ErrCodeBadRequest, "params", "")
	}
	zap := req.ZapTarget != nil
	if zap && *req.ZapTarget == "" {
		return errResult(nipcash.ErrCodeBadRequest, "empty zap_target", "")
	}
	b := it.b
	// Step 1.
	s, res := l.locateLocked(b, req.CashSecret, req.IdentityType, req.IdentityValue)
	if res != nil {
		return res
	}
	ni := req.NewIdentity
	amount := s.amount
	if req.AmountMillis != nil {
		amount = *req.AmountMillis
	}
	verdict, res := l.authorizeLocked(it, s, req.CashSecret, req.IdentityEvent, req.AttestationEvent,
		nipcash.ClaimBinding{Method: nipcash.MethodCashTransfer, Wallet: b.wallet,
			NewIdentityHash: nipcash.NewIdentityHashOf(ni.IdentityType, ni.IdentityValue, ni.IAPubkey), AmountMillis: &amount})
	if res != nil {
		return res
	}
	l.used[req.RequestID] = true
	if zap && s.idType != "pubkey" {
		return errResult(nipcash.ErrCodeRestricted, "a zap transfer's source is pubkey-bound", "")
	}
	// Step 2.
	if zap && ni.IdentityType != "pubkey" {
		return errResult(nipcash.ErrCodeBadRequest, "a zap transfer's new_identity is a pubkey", "")
	}
	switch {
	case ni.IdentityType == "pubkey" && isHex64(ni.IdentityValue) && ni.IAPubkey == "":
	case ni.IdentityType == "cash" && nipcash.ValidCommitment(ni.IdentityValue) && ni.IAPubkey == "":
	case ni.IdentityType == "connection_key" && isHex64(ni.IdentityValue) && isHex64(ni.IAPubkey):
		if !l.iaTrusted(ni.IAPubkey) {
			return errResult(nipcash.ErrCodeRestricted, "IA not trusted", "")
		}
	default:
		return errResult(nipcash.ErrCodeBadRequest, "new_identity", "")
	}
	// Steps 3 and 4.
	if amount == 0 || amount > s.amount {
		return errResult(nipcash.ErrCodeBadRequest, "amount_millis", "")
	}
	partial := amount < s.amount
	if partial {
		if rest := s.amount - amount; amount < s.minTransfer || rest < s.minTransfer {
			return errResult(nipcash.ErrCodeRestricted, "below min_transfer_millis", "")
		}
	}
	if partial && s.idType == "cash" {
		if !nipcash.ValidCommitment(req.RemainderCommitment) || nipcash.CommitmentsEqual(req.RemainderCommitment, s.idValue) {
			return errResult(nipcash.ErrCodeBadRequest, "remainder_commitment", "")
		}
	} else if req.RemainderCommitment != "" {
		return errResult(nipcash.ErrCodeBadRequest, "remainder_commitment", "")
	}
	spin := partial || zap
	if !spin {
		switch ni.IdentityType {
		case "cash":
			spin = len(b.slices) != 1
		default:
			for _, c := range b.slices {
				spin = spin || c != s && c.live() && c.idType == ni.IdentityType && c.idValue == ni.IdentityValue && c.ia == ni.IAPubkey
			}
		}
	}
	if spin {
		fresh, drained := 1, 0
		if partial {
			fresh = 2
		}
		if live := liveSlices(b); live == 1 {
			drained = 1
		}
		if res := l.gateLocked(b, fresh, drained, true); res != nil {
			return res
		}
	}
	// The commit.
	if res := l.commitPastDeadline(it); res != nil {
		return res
	}
	out := map[string]any{"amount_millis": amount, "identity_type": ni.IdentityType}
	if ni.IdentityValue != "" {
		out["identity_value"] = ni.IdentityValue
	}
	if !spin {
		if s.idType == "connection_key" {
			delete(l.ckHolder, sliceKey(s))
		}
		s.idType, s.idValue, s.ia = ni.IdentityType, ni.IdentityValue, ni.IAPubkey
		b.cashMode = s.idType == "cash"
	} else {
		deliver := func(nb *ledgerBill) (string, error) {
			if s.idType == "cash" {
				return nb.token, nil // a cash-mode caller's delivery is in the clear
			}
			return deliverTo(nb.walletPriv, verdict.Signer, nb.token)
		}
		carved, err := l.spinOffLocked(b, s, nipcash.RecipientParam{IdentityType: ni.IdentityType, IdentityValue: ni.IdentityValue,
			IAPubkey: ni.IAPubkey, AmountMillis: amount})
		if err != nil {
			return errResult(nipcash.ErrCodeInternal, "signer", "")
		}
		spun := []*ledgerBill{carved}
		if zap {
			z := nipcash.ZapContext{Recipient: ni.IdentityValue, Sender: s.idValue, ZapTarget: *req.ZapTarget,
				IssuedAt: uint64(l.nowLocked())}
			if carved.expiresAt != nil {
				z.ExpiresAt = uint64(*carved.expiresAt)
			}
			if err := l.zapSignLocked(carved, z); err != nil {
				delete(l.bills, carved.wallet)
				return errResult(nipcash.ErrCodeInternal, "signer", "")
			}
			out["issued_at"], out["expires_at"] = z.IssuedAt, z.ExpiresAt
		}
		tok, err := deliver(carved)
		if err != nil {
			return errResult(nipcash.ErrCodeInternal, "delivery", "")
		}
		out["new_wallet_pubkey"], out["new_wallet_token"] = carved.wallet, tok
		if partial {
			r := nipcash.RecipientParam{IdentityType: s.idType, IdentityValue: s.idValue, IAPubkey: s.ia, AmountMillis: s.amount - amount}
			if s.idType == "cash" {
				r.IdentityValue = req.RemainderCommitment
			}
			rb, err := l.spinOffLocked(b, s, r)
			if err != nil {
				return errResult(nipcash.ErrCodeInternal, "signer", "")
			}
			spun = append(spun, rb)
			if tok, err = deliver(rb); err != nil {
				return errResult(nipcash.ErrCodeInternal, "delivery", "")
			}
			out["remaining_amount_millis"] = s.amount - amount
			out["remainder_wallet_pubkey"], out["remainder_wallet_token"] = rb.wallet, tok
		}
		s.state, s.claimedAt = nipcash.ReasonTransferred, l.nowLocked()
		l.recordSpinLocked(b, spun...)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "encode", "")
	}
	rec := &callRecord{wallet: b.wallet, authorizer: verdict.Signer, result: raw}
	if verdict.Signer == "" {
		rec.cashCommitment, _ = nipcash.CashCommitment(req.CashSecret)
	}
	l.calls[req.RequestID] = rec
	l.consumeLocked(verdict, req.IdentityEvent)
	if spin {
		l.destroyIfDrainedLocked(b, s)
	}
	return &transport.Result{Result: raw}
}

// spinOffLocked is a new dedicated wallet for r, carrying src's fee terms and
// ordered mark and its bill's expiry.
func (l *WithdrawLedger) spinOffLocked(b *ledgerBill, src *ledgerSlice, r nipcash.RecipientParam) (*ledgerBill, error) {
	nb, err := l.newBillLocked([]nipcash.RecipientParam{r}, b.expiresAt, nil)
	if err != nil {
		return nil, err
	}
	ns := nb.slices[0]
	ns.redeemBase, ns.redeemPpm, ns.minTransfer, ns.ordered = src.redeemBase, src.redeemPpm, src.minTransfer, src.ordered
	return nb, nil
}

// ErrOwnerRefused is the owner's delete of a wallet holding, or removal of, an
// unclaimed re-minted or ordered slice (NIP-CASH §Lifecycle and Deletion,
// §Removing a Recipient).
var ErrOwnerRefused = errors.New("cashtest: the owner cannot delete a wallet holding, nor remove, an unclaimed re-minted or ordered slice")

// ErrNoSuchBill is a delete or removal naming no live bill or slice of the
// ledger.
var ErrNoSuchBill = errors.New("cashtest: no such live bill or slice")

func (s *ledgerSlice) ownerLocked() bool { return s.live() && (s.reminted || s.ordered) }

// DeleteBill is the wallet owner's delete of a bill: refused while it holds an
// unclaimed re-minted or ordered slice; otherwise every unclaimed slice is
// reclaimed and the bill destroyed.
func (l *WithdrawLedger) DeleteBill(wallet string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bills[wallet]
	if b == nil || b.destroyed {
		return ErrNoSuchBill
	}
	for _, s := range b.slices {
		if s.ownerLocked() {
			return ErrOwnerRefused
		}
	}
	var last *ledgerSlice
	for _, s := range b.slices {
		if s.live() {
			s.state, s.claimedAt, last = nipcash.ReasonReclaimed, l.nowLocked(), s
		}
	}
	if last == nil {
		last = &ledgerSlice{state: nipcash.ReasonReclaimed}
	}
	l.destroyIfDrainedLocked(b, last)
	return nil
}

// RemoveSlice is the wallet owner's removal of the unclaimed slice registered
// to identityType/identityValue: refused for a re-minted or ordered one;
// otherwise the slice is gone (a later call finds no slice) and a bill left
// with none is destroyed.
func (l *WithdrawLedger) RemoveSlice(wallet, identityType, identityValue string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bills[wallet]
	if b == nil || b.destroyed {
		return ErrNoSuchBill
	}
	for i, s := range b.slices {
		if !s.live() || s.idType != identityType || s.idValue != identityValue {
			continue
		}
		if s.ownerLocked() {
			return ErrOwnerRefused
		}
		b.slices = append(b.slices[:i:i], b.slices[i+1:]...)
		if len(b.slices) == 0 {
			b.slices = []*ledgerSlice{{idType: s.idType, idValue: s.idValue, ia: s.ia, state: nipcash.ReasonReclaimed}}
		}
		l.destroyIfDrainedLocked(b, &ledgerSlice{state: nipcash.ReasonReclaimed})
		return nil
	}
	return ErrNoSuchBill
}

// Balance is the Hub's node wallet as far as the ledger keeps it: the value of
// its coins no payout has set aside, in millis.
func (l *WithdrawLedger) Balance() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var n uint64
	for _, c := range l.coins {
		if _, taken := l.setAside[c]; !taken {
			n += ledgerCoinSats * 1000
		}
	}
	return n
}
