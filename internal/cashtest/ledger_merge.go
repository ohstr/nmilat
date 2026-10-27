package cashtest

import (
	"encoding/json"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// cash_consolidate, zap transfers' zap bills, the operator's caps on new
// wallets, and archive drops on the ledger (NIP-CASH §Consolidating Tokens,
// §Transferring and Splitting a Slice, §Mint Provenance, §Security
// Considerations for Cash-Mode Slices, §Looking Up a Call).

// ledgerExt is the ledger state beyond bills and payouts.
type ledgerExt struct {
	// liveCap bounds the Cash Hub's live wallets (0: none): a call that would
	// pass it is QUOTA_EXCEEDED.
	liveCap int
	// spinRate spin-offs per spinPer per lineage (0: none): more is
	// RATE_LIMITED.
	spinRate int
	spinPer  time.Duration
	spins    map[string][]int64
	root     map[string]string // wallet -> the minted bill its lineage starts at
	circle   *circleDesk
}

// SetLiveWalletCap bounds the Cash Hub's live wallets at n (0 lifts it): a
// mint, spin-off or consolidation that would take them past it is refused
// QUOTA_EXCEEDED, nothing committed.
func (l *WithdrawLedger) SetLiveWalletCap(n int) { l.mu.Lock(); l.ext.liveCap = n; l.mu.Unlock() }

// SetSpinOffRate allows n spin-offs per period per lineage (a minted bill and
// every wallet spun off from it); n 0 lifts it. One over is refused
// RATE_LIMITED, nothing committed. Only committed spin-offs count, so refusals
// never lock a bill's other holders out.
func (l *WithdrawLedger) SetSpinOffRate(n int, per time.Duration) {
	l.mu.Lock()
	l.ext.spinRate, l.ext.spinPer = n, per
	l.mu.Unlock()
}

// DropArchive drops a destroyed bill's archive: its call records and its
// tombstone. Its pairing key stays derivable, so a lookup naming it is still
// answered, by its deadline.
func (l *WithdrawLedger) DropArchive(wallet string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bills[wallet]
	if b == nil || !b.destroyed {
		return ErrNoSuchBill
	}
	for rid, c := range l.calls {
		if c.wallet == wallet {
			delete(l.calls, rid)
		}
	}
	b.retainedUntil = min(b.retainedUntil, l.nowLocked()-1)
	return nil
}

func (l *WithdrawLedger) liveBillsLocked() int {
	n := 0
	for _, b := range l.bills {
		if !b.destroyed {
			n++
		}
	}
	return n
}

func (l *WithdrawLedger) rootLocked(wallet string) string {
	if r, ok := l.ext.root[wallet]; ok {
		return r
	}
	return wallet
}

// gateLocked is the operator's caps on a call adding fresh wallets and
// draining drained live ones; spin counts it against src's lineage rate.
func (l *WithdrawLedger) gateLocked(src *ledgerBill, fresh, drained int, spin bool) *transport.Result {
	if l.ext.liveCap > 0 && l.liveBillsLocked()-drained+fresh > l.ext.liveCap {
		return errResult(nipcash.ErrCodeQuotaExceeded, "over the Cash Hub's live-wallet cap", "")
	}
	if spin && l.ext.spinRate > 0 {
		since := l.nowLocked() - int64(l.ext.spinPer/time.Second)
		n := 0
		for _, at := range l.ext.spins[l.rootLocked(src.wallet)] {
			if at > since {
				n++
			}
		}
		if n >= l.ext.spinRate {
			return errResult(nipcash.ErrCodeRateLimited, "too many spin-offs from this bill's lineage", "")
		}
	}
	return nil
}

// recordSpinLocked counts a committed spin-off of src and puts its children in
// src's lineage.
func (l *WithdrawLedger) recordSpinLocked(src *ledgerBill, children ...*ledgerBill) {
	if l.ext.spins == nil {
		l.ext.spins, l.ext.root = map[string][]int64{}, map[string]string{}
	}
	root := l.rootLocked(src.wallet)
	l.ext.spins[root] = append(l.ext.spins[root], l.nowLocked())
	for _, c := range children {
		l.ext.root[c.wallet] = root
	}
}

// zapSignLocked re-signs nb's token under the zap scheme (scheme 2).
func (l *WithdrawLedger) zapSignLocked(nb *ledgerBill, z nipcash.ZapContext) error {
	tok, err := nipcash.Decode(nb.token)
	if err != nil {
		return err
	}
	sign, err := nipcash.LocalMintSigner(l.h.NodePriv, "satscash")
	if err != nil {
		return err
	}
	if tok, err = nipcash.SignToken(tok, nipcash.SchemeZapV1, &z, l.h.nodeXOnly, sign); err != nil {
		return err
	}
	nb.token, err = nipcash.Encode(tok)
	return err
}

// consolidateLocked is cash_consolidate, steps 1 to 8.
func (l *WithdrawLedger) consolidateLocked(it *ledgerItem) *transport.Result {
	var req nipcash.CashConsolidateRequest
	if json.Unmarshal(it.c.Item.Params, &req) != nil {
		return errResult(nipcash.ErrCodeBadRequest, "params", "")
	}
	// Step 1.
	if len(req.Sources) == 0 || req.Sources[0].WalletPubkey != it.b.wallet {
		return errResult(nipcash.ErrCodeBadRequest, "the item's target is not sources[0]", "")
	}
	if len(req.Sources) < 2 {
		return errResult(nipcash.ErrCodeBadRequest, "fewer than two sources", "")
	}
	seen := map[string]bool{}
	wallets := make([]string, len(req.Sources))
	for i, src := range req.Sources {
		key := src.WalletPubkey + ":" + src.IdentityType + ":" + src.IdentityValue
		switch {
		case seen[key]:
			return errResult(nipcash.ErrCodeBadRequest, "a repeated source", "")
		case src.CashSecret != "" || src.IdentityType == "cash":
			return errResult(nipcash.ErrCodeBadRequest, "a cash source", "")
		}
		seen[key] = true
		wallets[i] = src.WalletPubkey
	}
	if cap := l.h.Limits.MaxConsolidateSources; cap > 0 && len(req.Sources) > cap {
		return errResult(nipcash.ErrCodeQuotaExceeded, "more sources than max_consolidate_sources", "")
	}
	// Step 2: every source is held, has the slice and its proof verifies, or
	// the whole call is UNAUTHORIZED with one message.
	ni := req.NewIdentity
	sHash, err := nipcash.SourcesHash(wallets)
	if err != nil {
		return errResult(nipcash.ErrCodeBadRequest, "a source wallet is not 64 lowercase hex", "")
	}
	type held struct {
		b       *ledgerBill
		s       *ledgerSlice
		verdict nipcash.ClaimVerdict
		event   string
	}
	srcs := make([]held, len(req.Sources))
	unauthorized := errResult(nipcash.ErrCodeUnauthorized, "a source does not verify", "")
	for i, src := range req.Sources {
		b := l.bills[src.WalletPubkey]
		if b == nil {
			return unauthorized
		}
		var s *ledgerSlice
		for _, c := range b.slices {
			if c.idType == src.IdentityType && c.idValue == src.IdentityValue && (s == nil || c.live()) {
				s = c
			}
		}
		if s == nil {
			return unauthorized
		}
		amount := s.amount
		v, err := nipcash.VerifyClaimProof(src.IdentityEvent, nipcash.ClaimExpectation{
			Binding: nipcash.ClaimBinding{Method: nipcash.MethodCashConsolidate, Wallet: b.wallet,
				NewIdentityHash: nipcash.NewIdentityHashOf(ni.IdentityType, ni.IdentityValue, ni.IAPubkey), AmountMillis: &amount, SourcesHash: sHash},
			SliceType: s.idType, SliceValue: s.idValue, SliceIA: s.ia, Attestation: src.AttestationEvent,
			IATrusted: func(string) bool { return true }, // step 3 decides trust
			Consumed:  func(id string) bool { _, ok := l.consumed[id]; return ok },
		}, it.c.Now)
		if err != nil {
			return unauthorized
		}
		srcs[i] = held{b: b, s: s, verdict: v, event: src.IdentityEvent}
	}
	if !nipcash.ItemSignerMatchesClaim(it.signer, srcs[0].verdict) {
		return unauthorized
	}
	l.used[req.RequestID] = true
	// Step 3.
	ordered := srcs[0].s.ordered
	for _, h := range srcs {
		switch {
		case !h.s.live() || !nipcash.SliceLive(l.nowLocked(), h.b.expiresAt):
			return errResult(nipcash.ErrCodeRestricted, "a source is claimed, terminal or expired", "")
		case h.s.idType == "connection_key" && !l.iaTrusted(h.s.ia):
			return errResult(nipcash.ErrCodeRestricted, "a source's IA is no longer trusted", "")
		case h.s.ordered != ordered:
			return errResult(nipcash.ErrCodeRestricted, "ordered and unordered sources", "")
		}
	}
	// Step 4.
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
	// Steps 5 and 6.
	var sum uint64
	var earliest *int64
	first := srcs[0].s
	for _, h := range srcs {
		if sum+h.s.amount < sum {
			return errResult(nipcash.ErrCodeQuotaExceeded, "the sum overflows", "")
		}
		sum += h.s.amount
		if h.s.minTransfer != first.minTransfer || h.s.redeemBase != first.redeemBase || h.s.redeemPpm != first.redeemPpm {
			return errResult(nipcash.ErrCodeRestricted, "the sources' terms differ", "")
		}
		if e := h.b.expiresAt; e != nil && (earliest == nil || *e < *earliest) {
			v := *e
			earliest = &v
		}
	}
	if sum > ledgerWalletCeiling {
		return errResult(nipcash.ErrCodeQuotaExceeded, "over the per-wallet ceiling", "")
	}
	taken := map[*ledgerBill]int{}
	for _, h := range srcs {
		taken[h.b]++
	}
	drained := 0
	for b, n := range taken {
		live := 0
		for _, c := range b.slices {
			if c.live() {
				live++
			}
		}
		if live == n {
			drained++
		}
	}
	if res := l.gateLocked(srcs[0].b, 1, drained, false); res != nil {
		return res
	}
	// Step 7.
	if res := l.commitPastDeadline(it); res != nil {
		return res
	}
	nb, err := l.newBillLocked([]nipcash.RecipientParam{{IdentityType: ni.IdentityType, IdentityValue: ni.IdentityValue,
		IAPubkey: ni.IAPubkey, AmountMillis: sum}}, earliest, nil)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "signer", "")
	}
	ns := nb.slices[0]
	ns.redeemBase, ns.redeemPpm, ns.minTransfer, ns.ordered = first.redeemBase, first.redeemPpm, first.minTransfer, ordered
	tok := nb.token
	if ni.IdentityType == "pubkey" { // step 8
		if tok, err = deliverTo(nb.walletPriv, srcs[0].verdict.Signer, nb.token); err != nil {
			delete(l.bills, nb.wallet)
			return errResult(nipcash.ErrCodeInternal, "delivery", "")
		}
	}
	for _, h := range srcs {
		h.s.state, h.s.claimedAt = nipcash.ReasonConsolidated, l.nowLocked()
		l.consumeLocked(h.verdict, h.event)
	}
	for _, h := range srcs {
		if !h.b.destroyed {
			l.destroyIfDrainedLocked(h.b, h.s)
		}
	}
	out := map[string]any{"amount_millis": sum, "new_wallet_pubkey": nb.wallet, "new_wallet_token": tok}
	if earliest != nil {
		out["expires_at"] = *earliest
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "encode", "")
	}
	l.calls[req.RequestID] = &callRecord{wallet: it.b.wallet, authorizer: srcs[0].verdict.Signer, result: raw}
	return &transport.Result{Result: raw}
}
