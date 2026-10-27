package cashtest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	mrand "math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/flokiorg/go-flokicoin/wire"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// On-chain withdrawals (NIP-CASH §Redeeming On-chain) on the fake Hub: a bill
// ledger, quotes, calls, cancel requests, lookups, and a payout engine paying on
// a fake chain.

// The fake's withdrawal constants: the network fee it estimates for every
// script type, its bump and invalidation fees, its coins, and the version
// unconfirmed this many blocks before it bumps it.
const (
	WithdrawNetworkFeeMillis = 1_200_000
	WithdrawSentByAfter      = 3600 // sent_by = quote time + this
	WithdrawEarliestSend     = 600  // too_slow below quote time + this (XQ-30)
	WithdrawHoldBlocks       = 2    // holds_until = tip + this
	WithdrawBumpAfterBlocks  = 6
	ledgerCoinSats           = 100_000_000
	ledgerCoins              = 32
	versionFeeSats           = 1000
)

// DefaultWithdrawTerms are the terms ServeWithdrawals offers when given none:
// NIP-CASH's fee example (base 500000, 2000 ppm), [[0,20],[0,32],[1,32]],
// final_depth 6, a minimum of 1000000 millis and a maximum of 10^10.
func DefaultWithdrawTerms() nipcash.WithdrawTerms {
	minM, maxM := uint64(1_000_000), uint64(10_000_000_000)
	return nipcash.WithdrawTerms{FeeBase: 500000, FeePpm: 2000, MinMillis: &minM, MaxMillis: &maxM,
		ScriptTypes: [][2]int{{0, 20}, {0, 32}, {1, 32}}, FinalDepth: 6}
}

// dustMillis is the dust limit the fake applies per script type.
func dustMillis(st nipcash.ScriptType) uint64 {
	if st.Version == 0 && st.ProgramLen == 20 {
		return 294_000
	}
	return 330_000
}

// WithdrawLedger is the fake Hub's bill ledger and on-chain withdrawal desk.
//
// It keeps two clocks. Envelope freshness, proofs and call deadlines are read
// on the Hub's Clock, which the SDK's wall-clock deadlines share; everything
// the ledger decides — slice expiry, quotes, sent_by, cancellation, notices,
// retention — runs on that clock plus what Advance added, so a test can move a
// payout days ahead while its client keeps talking to the Hub.
//
// The payout engine runs on every Tick: after each block, reorganisation and
// eviction, each Advance, and each fault change; never inside a call, so a
// reply is always queued and nothing is signed until the test moves the clock
// or the chain. It writes the about-to-sign record, signs one version (the
// payout and a change output, from one coin set aside at the commit), stores
// it, broadcasts it, bumps it with a conflicting version after
// WithdrawBumpAfterBlocks unconfirmed blocks (through a child once it has
// confirmed), rebroadcasts the identical transaction after an eviction or a
// reorganisation, and cancels per NIP-CASH §Cancelling a Payout, invalidating
// with a self-spend of the coin mined to final_depth.
type WithdrawLedger struct {
	h     *FakeHub
	chain *Chain

	mu       sync.Mutex
	terms    nipcash.WithdrawTerms
	offered  bool
	skew     time.Duration
	bills    map[string]*ledgerBill
	payouts  map[string]*payout
	used     map[string]bool
	consumed map[string]int64
	ckHolder map[string]string

	hubScript   []byte
	ownAddress  string
	coins       []wire.OutPoint
	setAside    map[wire.OutPoint]string
	bound       uint64
	starve      bool
	rateLimited bool
	holdSign    bool
	holdCast    bool
	crash       bool
	rng         io.Reader

	// invoices are the fake Lightning payee's open invoices, by payment hash.
	invoices map[string]*fakeInvoice
	// calls are the records of the transfers the ledger committed.
	calls map[string]*callRecord
	// ext is the rest: caps and lineages (ledger_merge.go).
	ext ledgerExt
}

// payout is one withdrawal's record.
type payout struct {
	rid, wallet    string
	bill           *ledgerBill
	slice          *ledgerSlice
	authorizer     string // the claim-proof signer; "" for a cash commitment
	cashCommitment string
	remintCommit   string
	quote          *nipcash.WithdrawQuote
	quoteRaw       string
	receipt        string
	deadline       int64
	finalDepth     uint32
	notify         string
	relay          *Relay

	coin         wire.OutPoint
	aboutToSign  []string
	versions     []*payoutVersion
	crashed      bool
	invalidation *wire.MsgTx
	child        *wire.MsgTx
	finalReached bool
	cancelled    bool
	cancelAt     int64
	endedAt      int64
	remint       *ledgerBill
	newToken     string
	notices      []int64
	archive      []ArchiveFact
}

type payoutVersion struct {
	tx            *wire.MsgTx
	broadcast     bool
	castAt        int64 // tip height when last broadcast
	confirmedOnce bool
}

// ArchiveFact is what the fake records at each change of a payout's state
// (NIP-CASH §Archival on Deletion): the state and, once broadcast, the
// transaction id, the payout's output and the miner fee.
type ArchiveFact struct {
	State       nipcash.PayoutState
	Txid        string
	Vout        uint32
	MinerFeeSat int64
}

// ServeWithdrawals gives the Hub a bill ledger offering on-chain withdrawals
// under terms (nil: DefaultWithdrawTerms) and returns it. mint_cash is then
// served on the Cash Hub connection, both withdrawal methods are listed in its
// private_methods, and items naming a ledger bill are served by the ledger;
// anything else still goes to the decision hook set before.
func (h *FakeHub) ServeWithdrawals(t testing.TB, terms *nipcash.WithdrawTerms) *WithdrawLedger {
	t.Helper()
	l := &WithdrawLedger{h: h, chain: NewChain(), offered: true, bills: map[string]*ledgerBill{},
		payouts: map[string]*payout{}, used: map[string]bool{}, consumed: map[string]int64{}, ckHolder: map[string]string{},
		setAside: map[wire.OutPoint]string{}, bound: ^uint64(0), rng: mrand.NewChaCha8([32]byte{0x11}),
		invoices: map[string]*fakeInvoice{}, calls: map[string]*callRecord{}}
	l.terms = DefaultWithdrawTerms()
	if terms != nil {
		l.terms = *terms
	}
	if err := l.terms.Validate(); err != nil {
		t.Fatalf("cashtest: withdraw terms: %v", err)
	}
	prog, _ := hex.DecodeString(randHex(20))
	l.hubScript = nipcash.WitnessScript(0, prog)
	l.ownAddress = segwitAddress(0, prog)
	for range ledgerCoins {
		l.coins = append(l.coins, l.chain.Fund(l.hubScript, ledgerCoinSats))
	}
	l.chain.Mine(l.terms.FinalDepth)
	l.chain.OnChange(l.Tick)

	h.mu.Lock()
	h.ledger, h.Withdrawals = l, true
	prev := h.Decide
	h.Decide = func(c ItemCtx) *transport.Result {
		l.mu.Lock()
		_, mine := l.bills[c.Item.Target]
		l.mu.Unlock()
		if mine {
			return l.decide(c)
		}
		if prev == nil {
			return nil
		}
		return prev(c)
	}
	h.mu.Unlock()
	return l
}

func segwitAddress(version uint8, program []byte) string {
	conv, err := bech32.ConvertBits(program, 8, 5, true)
	if err != nil {
		panic(err)
	}
	data := append([]byte{version}, conv...)
	var s string
	if version == 0 {
		s, err = bech32.Encode(FakeAddressHRP, data)
	} else {
		s, err = bech32.EncodeM(FakeAddressHRP, data)
	}
	if err != nil {
		panic(err)
	}
	return s
}

// Chain is the ledger's chain.
func (l *WithdrawLedger) Chain() *Chain { return l.chain }

// Terms are the withdrawal terms the ledger offers.
func (l *WithdrawLedger) Terms() nipcash.WithdrawTerms {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.terms
}

// SetOffered turns withdrawals on or off. Off, both methods are refused
// NOT_IMPLEMENTED (after a destroyed bill's tombstone), neither is listed and
// cash_status carries no withdraw object; lookups and cancel requests of
// payouts committed before are still served, and those payouts still paid.
func (l *WithdrawLedger) SetOffered(on bool) {
	l.mu.Lock()
	l.offered = on
	l.mu.Unlock()
	l.h.mu.Lock()
	l.h.Withdrawals = on
	l.h.mu.Unlock()
}

// Now is the ledger's clock: the Hub's plus what Advance added.
func (l *WithdrawLedger) Now() time.Time { l.mu.Lock(); defer l.mu.Unlock(); return l.nowTimeLocked() }

func (l *WithdrawLedger) nowTimeLocked() time.Time { return l.h.Clock.Now().Add(l.skew) }
func (l *WithdrawLedger) nowLocked() int64         { return l.nowTimeLocked().Unix() }

// Advance moves the ledger's clock forward by d, then ticks.
func (l *WithdrawLedger) Advance(d time.Duration) {
	l.mu.Lock()
	l.skew += d
	l.mu.Unlock()
	l.Tick()
}

// HubOwnAddress is an address the Hub's node wallet controls.
func (l *WithdrawLedger) HubOwnAddress() string { return l.ownAddress }

// ExternalAddress is a fresh address of script type st under FakeAddressHRP.
func ExternalAddress(st nipcash.ScriptType) string {
	prog, _ := hex.DecodeString(randHex(int(st.ProgramLen)))
	return segwitAddress(st.Version, prog)
}

// SetUnconfirmedBound bounds the value of the Hub's unconfirmed payouts: a
// withdrawal that would take them over it is refused RATE_LIMITED.
// ^uint64(0) lifts the bound.
func (l *WithdrawLedger) SetUnconfirmedBound(millis uint64) {
	l.mu.Lock()
	l.bound = millis
	l.mu.Unlock()
}

// StarveCoins makes the Hub unable to set coins aside: INSUFFICIENT_BALANCE.
func (l *WithdrawLedger) StarveCoins(on bool) { l.mu.Lock(); l.starve = on; l.mu.Unlock() }

// MarkUsed marks rid used on the node, as if a call carrying it had passed
// its authorization here before: a later call with it is REQUEST_REUSED.
func (l *WithdrawLedger) MarkUsed(rid string) { l.mu.Lock(); l.used[rid] = true; l.mu.Unlock() }

// SetQuoteRateLimited refuses every quote RATE_LIMITED while on.
func (l *WithdrawLedger) SetQuoteRateLimited(on bool) { l.mu.Lock(); l.rateLimited = on; l.mu.Unlock() }

// InjectFault sets the payout engine's fault: FaultHoldSign writes no
// about-to-sign record, FaultCrashAfterSign stores the signed version and never
// broadcasts it (the Hub restarted without it), FaultHoldBroadcast holds every
// broadcast; FaultNone clears them, and the engine resumes. Any other fault is
// ignored here.
func (l *WithdrawLedger) InjectFault(f Fault) {
	l.mu.Lock()
	switch f.kind {
	case faultNone:
		l.holdSign, l.holdCast, l.crash = false, false, false
		for _, p := range l.payouts {
			p.crashed = false
		}
	case faultHoldSign:
		l.holdSign = true
	case faultCrashAfterSign:
		l.crash = true
	case faultHoldBroadcast:
		l.holdCast = true
	}
	l.mu.Unlock()
	l.Tick()
}

// Payout is the payout of the withdrawal placed under rid, as a lookup would
// answer it (its re-minted token as delivered).
func (l *WithdrawLedger) Payout(rid string) (nipcash.Payout, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.payouts[rid]
	if p == nil {
		return nipcash.Payout{}, false
	}
	return l.payoutLocked(p), true
}

// Versions lists the txids of every version signed for rid, in order.
func (l *WithdrawLedger) Versions(rid string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	if p := l.payouts[rid]; p != nil {
		for _, v := range p.versions {
			out = append(out, v.tx.TxHash().String())
		}
	}
	return out
}

// Invalidation is the txid of rid's invalidating transaction, "" without one.
func (l *WithdrawLedger) Invalidation(rid string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if p := l.payouts[rid]; p != nil && p.invalidation != nil {
		return p.invalidation.TxHash().String()
	}
	return ""
}

// Archive is what the fake recorded at each change of rid's state.
func (l *WithdrawLedger) Archive(rid string) []ArchiveFact {
	l.mu.Lock()
	defer l.mu.Unlock()
	if p := l.payouts[rid]; p != nil {
		return slices.Clone(p.archive)
	}
	return nil
}

// ErrHubDeleteRefused is a Cash Hub delete refused while a payout is open or
// its record kept (NIP-CASH §Lifecycle and Deletion).
var ErrHubDeleteRefused = errors.New("cashtest: the Cash Hub has a payout not final or cancelled, or a withdrawal record still kept")

// DeleteHub is the owner's Cash Hub delete as far as withdrawals decide it:
// refused while any record blocks it. Nothing is deleted.
func (l *WithdrawLedger) DeleteHub() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, p := range l.payouts {
		if nipcash.WithdrawBlocksHubDelete(l.retentionLocked(p), l.nowLocked()) {
			return ErrHubDeleteRefused
		}
	}
	return nil
}

func (l *WithdrawLedger) retentionLocked(p *payout) nipcash.WithdrawRetention {
	return nipcash.WithdrawRetention{Deadline: p.deadline, Horizon: l.h.Limits.MaxRequestAgeSeconds, EndedAt: p.endedAt,
		TombstoneWindow: int64(l.h.TombstoneWindow / time.Second), RemintLive: p.remint != nil && !p.remint.destroyed}
}

func (l *WithdrawLedger) retainedLocked(p *payout) bool {
	return nipcash.WithdrawRecordRetained(l.retentionLocked(p), l.nowLocked())
}

// --- quote ---

func (l *WithdrawLedger) sign(ev *nip01.Event) error { return ev.Sign(l.h.NodePriv) }

// quoteLocked is cash_withdraw_quote (NIP-CASH §Quoting a Withdrawal).
func (l *WithdrawLedger) quoteLocked(it *ledgerItem) *transport.Result {
	var req nipcash.CashWithdrawQuoteRequest
	if json.Unmarshal(it.c.Item.Params, &req) != nil {
		return errResult(nipcash.ErrCodeBadRequest, "params", "")
	}
	if l.rateLimited {
		return errResult(nipcash.ErrCodeRateLimited, "too many quotes", "")
	}
	s, found, claimable := l.quoteSliceLocked(it, req)
	now := l.nowLocked()
	tip := l.chain.Tip()
	earliest := now + WithdrawEarliestSend
	check := nipcash.QuoteCheck{Found: found, Address: req.Address, NetworkHRP: FakeAddressHRP, Pays: l.terms.ScriptTypeList(),
		Claimable: claimable, MinMillis: l.terms.MinMillis, MaxMillis: l.terms.MaxMillis, SendBefore: req.SendBefore,
		EarliestSentBy: earliest}
	var hubFee, fee, pay uint64
	if s != nil {
		check.AmountMillis = s.amount
		check.PayoutFor = func(st nipcash.ScriptType) (uint64, uint64, error) {
			redeemFee, _, err := nipcash.RedeemFee(s.amount, s.redeemBase, s.redeemPpm)
			if err != nil {
				return 0, 0, err
			}
			hubFee, fee, pay, err = nipcash.WithdrawFee(s.amount, WithdrawNetworkFeeMillis, l.terms.FeeBase, l.terms.FeePpm, redeemFee)
			return pay, dustMillis(st), err
		}
	}
	if err := nipcash.CheckQuoteRequest(check); err != nil {
		return errCode(err)
	}
	sentBy := now + WithdrawSentByAfter
	if req.SendBefore != nil {
		sentBy = min(sentBy, *req.SendBefore)
	}
	f := nipcash.QuoteFields{Wallet: it.b.wallet, IdentityValue: s.idValue, IAPubkey: s.ia, Address: req.Address,
		AmountMillis: s.amount, NetworkFeeMillis: WithdrawNetworkFeeMillis, HubFeeMillis: hubFee, PayoutMillis: pay,
		SentBy: sentBy, HoldsUntil: tip + WithdrawHoldBlocks}
	ev, err := nipcash.NewWithdrawQuoteEvent(f, it.c.Now.Unix(), l.sign)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "signer", "")
	}
	raw, _ := json.Marshal(ev)
	return okResult(nipcash.CashWithdrawQuoteResult{Quote: string(raw), Address: req.Address, AmountMillis: s.amount,
		NetworkFeeMillis: WithdrawNetworkFeeMillis, HubFeeMillis: hubFee, FeeMillis: fee, PayoutMillis: pay, SentBy: sentBy,
		HoldsUntil: tip + WithdrawHoldBlocks})
}

// quoteSliceLocked locates the quoted slice: a cash-mode bill's one slice for a
// proofless item; a connection_key slice by the attestation the params carry,
// whose p must be the item proof's signer; else the signer's pubkey slice, an
// unclaimed one first.
func (l *WithdrawLedger) quoteSliceLocked(it *ledgerItem, req nipcash.CashWithdrawQuoteRequest) (s *ledgerSlice, found, claimable bool) {
	now := l.nowLocked()
	live := func(s *ledgerSlice) bool { return s.live() && nipcash.SliceLive(now, it.b.expiresAt) }
	if !it.c.Item.HasProof() {
		s = it.b.slices[0]
		return s, true, live(s)
	}
	if req.IdentityValue != "" || req.IAPubkey != "" || req.AttestationEvent != "" {
		for _, c := range it.b.slices {
			if c.idType != "connection_key" || c.idValue != req.IdentityValue || c.ia != req.IAPubkey {
				continue
			}
			trusted, err := nipcash.VerifySliceAttestation(req.AttestationEvent, nipcash.AttestationExpectation{
				SliceValue: c.idValue, SliceIA: c.ia, Signer: it.signer, IATrusted: l.iaTrusted}, it.c.Now.Unix())
			if err != nil {
				continue
			}
			l.ckHolder[sliceKey(c)] = it.signer
			if s == nil || live(c) && trusted {
				s, claimable = c, live(c) && trusted
			}
		}
		return s, s != nil, claimable
	}
	for _, c := range it.b.slices {
		if c.idType == "pubkey" && c.idValue == it.signer && (s == nil || live(c)) {
			s = c
		}
	}
	return s, s != nil, s != nil && live(s)
}

func (l *WithdrawLedger) iaTrusted(ia string) bool {
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	return l.h.TrustedIAs[ia]
}

// --- call ---

// withdrawLocked is cash_withdraw (NIP-CASH §Processing Algorithm), a call.
func (l *WithdrawLedger) withdrawLocked(it *ledgerItem) *transport.Result {
	b := it.b
	cashSlice := b.slices[0]
	ws := nipcash.WithdrawSlice{CashMode: b.cashMode}
	if b.cashMode {
		ws.Commitment = cashSlice.idValue
	}
	req, err := nipcash.ParseCashWithdrawRequest(it.c.Item.Params, ws)
	if err != nil {
		return errCode(err)
	}
	q, err := nipcash.ParseWithdrawQuote(req.Quote)
	if err != nil {
		return errResult(nipcash.ErrCodeBadRequest, "malformed quote", "")
	}
	now := l.nowLocked()
	// Step 1: locate the slice.
	var s *ledgerSlice
	if b.cashMode && req.CashSecret != "" {
		s = cashSlice
	} else if req.IdentityType == "pubkey" || req.IdentityType == "connection_key" {
		for _, c := range b.slices {
			if c.idType == req.IdentityType && c.idValue == req.IdentityValue && (s == nil || c.live()) {
				s = c
			}
		}
	}
	switch {
	case s == nil:
		return errResult(nipcash.ErrCodeNotFound, "no slice", "")
	case !s.live() || !nipcash.SliceLive(now, b.expiresAt):
		return errResult(nipcash.ErrCodeRestricted, "slice claimed, terminal or expired", "")
	}
	// Step 2: authorize; the request_id becomes used.
	var verdict nipcash.ClaimVerdict
	if s.idType == "cash" {
		if !secretMatches(req.CashSecret, s.idValue) {
			return errResult(nipcash.ErrCodeUnauthorized, "cash_secret", "")
		}
	} else {
		verdict, err = nipcash.VerifyClaimProof(req.IdentityEvent, nipcash.ClaimExpectation{
			Binding:   nipcash.ClaimBinding{Method: nipcash.MethodCashWithdraw, Wallet: b.wallet, QuoteID: q.ID},
			SliceType: s.idType, SliceValue: s.idValue, SliceIA: s.ia, Attestation: req.AttestationEvent,
			IATrusted: l.iaTrusted, Consumed: func(id string) bool { _, ok := l.consumed[id]; return ok },
		}, it.c.Now)
		if err != nil {
			return errCode(err)
		}
		if !nipcash.ItemSignerMatchesClaim(it.signer, verdict) {
			return errResult(nipcash.ErrCodeUnauthorized, "the item proof is not the claim proof's signer", "")
		}
		if s.idType == "connection_key" {
			l.ckHolder[sliceKey(s)] = verdict.Signer
		}
	}
	if l.used[req.RequestID] {
		return errResult(nipcash.ErrCodeRequestReused, "request_id used", "")
	}
	l.used[req.RequestID] = true
	// Step 3: check the payout.
	quoteOK := nipcash.VerifyWithdrawQuote(q, l.h.nodeXOnly) == nil && q.Wallet == b.wallet && q.IdentityValue == s.idValue && q.IAPubkey == s.ia
	coin, haveCoin := l.pickCoinLocked()
	var unconfirmed uint64
	for _, p := range l.payouts {
		if st := l.stateLocked(p); st == nipcash.PayoutQueued || st == nipcash.PayoutBroadcast {
			unconfirmed += p.quote.PayoutMillis
		}
	}
	if err := nipcash.CheckWithdrawPayout(nipcash.PayoutCheck{
		QuoteOK: quoteOK, QuoteValid: nipcash.QuoteValidAt(q.HoldsUntil, l.chain.Tip()),
		AtUnconfirmedBound: unconfirmed+q.PayoutMillis > l.bound, CoinsSetAside: haveCoin,
		OwnAddress: l.ownAddressLocked(q.Address),
	}); err != nil {
		return errCode(err)
	}
	// Step 4: commit, rechecking the deadline, the quote and the slice.
	if !nipcash.CommitAllowed(it.c.Envelope.NotAfter, l.h.Clock.Now().Unix()) {
		return errResult(nipcash.ErrCodeBadRequest, "the call reached its commit past its deadline", "")
	}
	if !nipcash.QuoteValidAt(q.HoldsUntil, l.chain.Tip()) {
		return errResult(nipcash.ErrCodeRestricted, "quote expired", nipcash.DetailQuoteExpired)
	}
	// The receipt is signed before anything moves.
	rc, err := nipcash.NewWithdrawReceiptEvent(nipcash.ReceiptFields{Wallet: b.wallet, QuoteID: q.ID, RequestID: req.RequestID,
		Address: q.Address, PayoutMillis: q.PayoutMillis, SentBy: q.SentBy}, it.c.Now.Unix(), l.sign)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "signer", "")
	}
	rcRaw, _ := json.Marshal(rc)
	s.state, s.claimedAt, s.withdrawRID = nipcash.ReasonRedeemed, now, req.RequestID
	l.setAside[coin] = req.RequestID
	if verdict.RecomputedID != "" {
		var ev nip01.Event
		_ = json.Unmarshal([]byte(req.IdentityEvent), &ev)
		l.consumed[verdict.RecomputedID] = nipcash.ClaimRetainUntil(int64(ev.CreatedAt))
	}
	p := &payout{rid: req.RequestID, wallet: b.wallet, bill: b, slice: s, authorizer: verdict.Signer, remintCommit: req.RemintCommitment,
		quote: q, quoteRaw: req.Quote, receipt: string(rcRaw), deadline: it.c.Envelope.NotAfter, finalDepth: uint32(l.terms.FinalDepth),
		notify: req.Notify, relay: it.c.Relay, coin: coin}
	if s.idType == "cash" {
		p.cashCommitment = s.idValue
	}
	l.payouts[req.RequestID] = p
	l.archiveLocked(p)
	l.destroyIfDrainedLocked(b, s)
	// Step 5.
	return okResult(l.payoutLocked(p))
}

func (l *WithdrawLedger) ownAddressLocked(addr string) bool {
	v, prog, err := nipcash.DecodeWitnessAddress(addr, FakeAddressHRP)
	return err == nil && slices.Equal(nipcash.WitnessScript(v, prog), l.hubScript)
}

// pickCoinLocked is a coin at final_depth no payout has set aside.
func (l *WithdrawLedger) pickCoinLocked() (wire.OutPoint, bool) {
	if l.starve {
		return wire.OutPoint{}, false
	}
	for _, c := range l.coins {
		if _, taken := l.setAside[c]; !taken && l.chain.Depth(c.Hash) >= uint32(l.terms.FinalDepth) {
			return c, true
		}
	}
	return wire.OutPoint{}, false
}

// --- cancel request ---

// cancelLocked is a cancel request (NIP-CASH §Cancelling a Payout), served as
// the cash_lookup of the call it names.
func (l *WithdrawLedger) cancelLocked(it *ledgerItem) *transport.Result {
	req, _, err := nipcash.ParseWithdrawCancel(it.c.Item.Params)
	if err != nil {
		return errCode(err)
	}
	p := l.payouts[req.RequestID]
	if p == nil || !l.retainedLocked(p) {
		return errResult(nipcash.ErrCodeNotFound, "no record", "")
	}
	if p.wallet != it.b.wallet || !l.authorizesLocked(p, it) {
		return errResult(nipcash.ErrCodeUnauthorized, "not the call's authorizer", "")
	}
	invalidate, err := nipcash.CancelRequestAnswer(l.cancelFactsLocked(p), l.nowLocked())
	if err != nil {
		return errCode(err)
	}
	if invalidate && p.invalidation == nil {
		l.invalidateLocked(p)
	}
	return okResult(l.payoutLocked(p))
}

func (l *WithdrawLedger) cancelFactsLocked(p *payout) nipcash.CancelFacts {
	return nipcash.CancelFacts{AboutToSign: len(p.aboutToSign) > 0, Broadcast: p.broadcastAny(), State: l.stateLocked(p), SentBy: p.quote.SentBy}
}

func (p *payout) broadcastAny() bool {
	for _, v := range p.versions {
		if v.broadcast {
			return true
		}
	}
	return false
}

// --- state ---

// confirmedLocked is the version the chain confirms, and its depth.
func (l *WithdrawLedger) confirmedLocked(p *payout) (*payoutVersion, uint32) {
	for _, v := range p.versions {
		if d := l.chain.Depth(v.tx.TxHash()); d > 0 {
			return v, d
		}
	}
	return nil, 0
}

func (l *WithdrawLedger) stateLocked(p *payout) nipcash.PayoutState {
	_, depth := l.confirmedLocked(p)
	return nipcash.PayoutStateOf(nipcash.PayoutFacts{Cancelled: p.cancelled, Broadcast: p.broadcastAny(),
		FinalReached: p.finalReached, Depth: depth, FinalDepth: p.finalDepth})
}

// payoutLocked is the payout's answer now (NIP-CASH §Response).
func (l *WithdrawLedger) payoutLocked(p *payout) nipcash.Payout {
	out := nipcash.Payout{State: l.stateLocked(p), Address: p.quote.Address, AmountMillis: p.quote.AmountMillis,
		FeeMillis: p.quote.FeeMillis(), PayoutMillis: p.quote.PayoutMillis, SentBy: p.quote.SentBy, FinalDepth: p.finalDepth,
		Signed: len(p.aboutToSign) > 0, Receipt: p.receipt}
	if out.State == nipcash.PayoutCancelled {
		out.NewWalletPubkey = p.remint.wallet
		if p.remint.destroyed {
			out.NewWalletToken.Tombstone = &nipcash.Tombstone{Status: nipcash.StatusSpent, Reason: nipcash.TombstoneReason(p.remint.reason)}
			if l.nowLocked() <= p.remint.retainedUntil {
				until := p.remint.retainedUntil
				out.NewWalletToken.Tombstone.RetainedUntil = &until
			}
		} else {
			out.NewWalletToken.Token = p.newToken
		}
		return out
	}
	if len(p.versions) > 0 {
		out.Tx = TxHex(p.versions[len(p.versions)-1].tx)
	}
	v, depth := l.confirmedLocked(p)
	if v == nil {
		for i := len(p.versions) - 1; i >= 0; i-- {
			if p.versions[i].broadcast {
				v = p.versions[i]
				break
			}
		}
	}
	if v != nil {
		out.Tx = TxHex(v.tx)
		vout, d := uint32(0), min(depth, p.finalDepth)
		out.Txid, out.Vout, out.Depth = v.tx.TxHash().String(), &vout, &d
		if p.finalReached {
			out.Depth = &p.finalDepth
		}
	}
	return out
}

func (l *WithdrawLedger) archiveLocked(p *payout) {
	f := ArchiveFact{State: l.stateLocked(p)}
	if v, _ := l.confirmedLocked(p); v != nil || p.broadcastAny() {
		if v == nil {
			v = p.versions[len(p.versions)-1]
		}
		f.Txid = v.tx.TxHash().String()
		f.MinerFeeSat = versionFee(v.tx)
	}
	if n := len(p.archive); n > 0 && p.archive[n-1] == f {
		return
	}
	p.archive = append(p.archive, f)
}

// versionFee is a version's miner fee: the coin less its outputs.
func versionFee(tx *wire.MsgTx) int64 {
	fee := int64(ledgerCoinSats)
	for _, o := range tx.TxOut {
		fee -= o.Value
	}
	return fee
}

// --- engine ---

// Tick runs the payout engine once over every payout, then publishes the state
// notices that came due.
func (l *WithdrawLedger) Tick() {
	type due struct {
		relay  *Relay
		notify string
	}
	var notices []due
	l.mu.Lock()
	now := l.nowLocked()
	for _, rid := range slices.Sorted(maps.Keys(l.payouts)) {
		p := l.payouts[rid]
		l.stepLocked(p, now)
		l.archiveLocked(p)
		kept := p.notices[:0]
		for _, at := range p.notices {
			if now >= at {
				notices = append(notices, due{p.relay, p.notify})
			} else {
				kept = append(kept, at)
			}
		}
		p.notices = kept
	}
	l.mu.Unlock()
	for _, n := range notices {
		ev, err := nipCO.NewOrderNotice(n.notify)
		if err != nil {
			continue
		}
		if n.relay != nil {
			n.relay.Publish(ev)
			continue
		}
		for _, r := range l.h.Relays {
			r.Publish(ev)
		}
	}
}

func (l *WithdrawLedger) scheduleNoticeLocked(p *payout, now int64) {
	d, err := nipcash.WithdrawNoticeDelay(l.rng)
	if err != nil {
		return
	}
	p.notices = append(p.notices, now+int64(d/time.Second)+1)
}

// stepLocked moves one payout as far as the chain, the clock and the faults
// allow.
func (l *WithdrawLedger) stepLocked(p *payout, now int64) {
	if p.cancelled || p.finalReached {
		return
	}
	tip := l.chain.Tip()
	if v, depth := l.confirmedLocked(p); v != nil {
		v.confirmedOnce = true
		p.invalidation = nil // a version confirmed: paid, not cancelled
		if depth >= p.finalDepth {
			p.finalReached, p.endedAt = true, now
			// The change comes back as a coin of the Hub's.
			l.coins = append(l.coins, wire.OutPoint{Hash: v.tx.TxHash(), Index: 1})
		}
		return
	}
	if p.invalidation != nil {
		h := p.invalidation.TxHash()
		switch {
		case l.chain.Depth(h) >= p.finalDepth:
			l.cancelLocked2(p, now)
			l.coins = append(l.coins, wire.OutPoint{Hash: h, Index: 0})
		case l.chain.Depth(h) == 0 && !l.chain.InMempool(h):
			_ = l.chain.Broadcast(p.invalidation)
		}
		return
	}
	switch nipcash.CancelDue(l.cancelFactsLocked(p), now) {
	case nipcash.CancelNow:
		l.cancelLocked2(p, now)
		return
	case nipcash.InvalidateThenCancel:
		l.invalidateLocked(p)
		return
	}
	if len(p.aboutToSign) == 0 {
		if l.holdSign {
			return
		}
		p.aboutToSign = []string{outpointString(p.coin)}
		p.versions = append(p.versions, &payoutVersion{tx: l.versionTx(p, 1)})
		if l.crash {
			p.crashed = true
		}
	}
	cur := p.versions[len(p.versions)-1]
	if l.holdCast || p.crashed {
		return
	}
	switch {
	case !cur.broadcast:
		if l.chain.Broadcast(cur.tx) == nil {
			cur.broadcast, cur.castAt = true, tip
			if len(p.versions) == 1 {
				l.scheduleNoticeLocked(p, now)
			}
		}
	case !l.chain.InMempool(cur.tx.TxHash()):
		// Evicted, or reorganised out: rebroadcast the identical transaction.
		if l.chain.Spendable(cur.tx) && l.chain.Broadcast(cur.tx) == nil {
			cur.castAt = tip
			if p.child != nil {
				_ = l.chain.Broadcast(p.child)
			}
		}
	case tip-cur.castAt >= WithdrawBumpAfterBlocks && cur.confirmedOnce:
		if p.child == nil {
			p.child = childTx(cur.tx, l.hubScript)
			_ = l.chain.Broadcast(p.child)
		}
	case tip-cur.castAt >= WithdrawBumpAfterBlocks:
		next := &payoutVersion{tx: l.versionTx(p, len(p.versions)+1)}
		if !nipcash.SpendsFromEach(p.versionInputs(), txInputs(next.tx)) {
			panic("cashtest: a bump that does not spend from every earlier version")
		}
		p.versions = append(p.versions, next)
		if l.chain.Broadcast(next.tx) == nil {
			next.broadcast, next.castAt = true, tip
		}
	}
}

// versionTx is version n of a payout: the set-aside coin, the payout output
// first, then the change, paying n times the base fee.
func (l *WithdrawLedger) versionTx(p *payout, n int) *wire.MsgTx {
	v, prog, err := nipcash.DecodeWitnessAddress(p.quote.Address, FakeAddressHRP)
	if err != nil {
		panic("cashtest: a committed address does not decode: " + err.Error())
	}
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: p.coin, Sequence: 0xfffffffd, Witness: wire.TxWitness{l.dummySig(n)}})
	pay := int64(p.quote.PayoutMillis / 1000)
	tx.AddTxOut(wire.NewTxOut(pay, nipcash.WitnessScript(v, prog)))
	tx.AddTxOut(wire.NewTxOut(ledgerCoinSats-pay-int64(n)*versionFeeSats, l.hubScript))
	return tx
}

// dummySig stands for the signature by key 0x11×32: the fake checks no script.
func (l *WithdrawLedger) dummySig(n int) []byte {
	return []byte(fmt.Sprintf("cashtest-sig-%d-%s", n, randHex(4)))
}

func childTx(parent *wire.MsgTx, script []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Hash: parent.TxHash(), Index: 1}, Sequence: 0xfffffffd,
		Witness: wire.TxWitness{[]byte("cashtest-child")}})
	tx.AddTxOut(wire.NewTxOut(parent.TxOut[1].Value-5*versionFeeSats, script))
	return tx
}

func outpointString(o wire.OutPoint) string { return fmt.Sprintf("%s:%d", o.Hash.String(), o.Index) }

func txInputs(tx *wire.MsgTx) []string {
	var out []string
	for _, in := range tx.TxIn {
		out = append(out, outpointString(in.PreviousOutPoint))
	}
	return out
}

// versionInputs are the inputs of every version that may have been signed: the
// about-to-sign record's and each stored version's.
func (p *payout) versionInputs() [][]string {
	sets := [][]string{p.aboutToSign}
	for _, v := range p.versions {
		sets = append(sets, txInputs(v.tx))
	}
	return sets
}

// invalidateLocked broadcasts a self-spend of the set-aside coin: it pays none
// of the versions and spends an input of every one that may have been signed.
func (l *WithdrawLedger) invalidateLocked(p *payout) {
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: p.coin, Sequence: 0xfffffffd, Witness: wire.TxWitness{[]byte("cashtest-invalidate")}})
	tx.AddTxOut(wire.NewTxOut(ledgerCoinSats-20*versionFeeSats, l.hubScript))
	if !nipcash.SpendsFromEach(p.versionInputs(), txInputs(tx)) {
		panic("cashtest: an invalidation that does not spend from every version")
	}
	p.invalidation = tx
	_ = l.chain.Broadcast(tx)
}

// cancelLocked2 cancels a payout no version can confirm any more: re-mints the
// whole amount as a new bill for the same holder, rewrites the source slice
// redeemed → transferred, and schedules the cancel notice.
func (l *WithdrawLedger) cancelLocked2(p *payout, now int64) {
	s := p.slice
	r := nipcash.RecipientParam{IdentityType: s.idType, IdentityValue: s.idValue, IAPubkey: s.ia, AmountMillis: p.quote.AmountMillis}
	if s.idType == "cash" {
		r.IdentityValue = p.remintCommit
	}
	// The fake's default expiry is never, so a re-minted bill never expires.
	b, err := l.newBillLocked([]nipcash.RecipientParam{r}, nipcash.RemintExpiry(p.bill.expiresAt, now, nil), s)
	if err != nil {
		panic("cashtest: re-mint: " + err.Error())
	}
	p.remint, p.newToken = b, b.token
	if s.idType != "cash" {
		ct, err := deliverTo(b.walletPriv, p.authorizer, b.token)
		if err != nil {
			panic("cashtest: deliver the re-minted token: " + err.Error())
		}
		p.newToken = ct
	}
	p.cancelled, p.cancelAt, p.endedAt = true, now, now
	if len(p.aboutToSign) == 0 {
		delete(l.setAside, p.coin) // never signed: the coin is free again
	}
	s.state = nipcash.ReasonTransferred
	if p.bill.destroyed && p.bill.endedBy == p.rid {
		p.bill.reason = nipcash.ReasonTransferred
	}
	l.scheduleNoticeLocked(p, now)
}

// deliverTo seals token for the claim-proof signer as a spin-off's (NIP-CASH
// §Delivery — Nested Encryption): NIP-44 between the new wallet's key and the
// signer's.
func deliverTo(newWalletPriv, signerXOnly, token string) (string, error) {
	priv, err := utils.ParsePrivateKeyHex(newWalletPriv)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(signerXOnly)
	if err != nil {
		return "", err
	}
	pub, err := schnorr.ParsePubKey(raw)
	if err != nil {
		return "", err
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(token, key)
}
