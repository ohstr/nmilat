package cashtest

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// The bill ledger behind ServeWithdrawals: bills minted by mint_cash on the
// Cash Hub connection (or MintBill), their slices, cash_status, and the private
// transport's per-item order I2 to I9 for items naming them. cash_redeem (paid
// to the fake payee's invoices, ledger_spend.go), cash_transfer (in place,
// split, spin-off and zap) and cash_consolidate (ledger_merge.go) are served,
// and with WithCircleHub the circle's joins and join lookups
// (ledger_circle.go).

// Fee terms every slice the ledger mints carries (fixed at creation, never the
// Hub's current terms): a redeem fee of 5000 ppm, so a 21000000-millis slice
// pays 105000 as in NIP-CASH §The Withdraw Fee's example.
const (
	LedgerRedeemFeeBase    = 0
	LedgerRedeemFeePpm     = 5000
	LedgerMinTransfer      = 1000
	ledgerWalletCeiling    = 1_000_000_000_000
	ledgerMaxExpirySeconds = 100 * 365 * 86400
)

type ledgerBill struct {
	walletPriv, wallet  string
	connSecret, connPub string
	token               string
	slices              []*ledgerSlice
	expiresAt           *int64
	cashMode            bool

	destroyed     bool
	reason        string
	retainedUntil int64
	// endedBy is the withdrawal that ended its last slice, for the tombstone's
	// withdraw_request_id.
	endedBy string
}

type ledgerSlice struct {
	idType, idValue, ia                string
	amount                             uint64
	redeemBase, redeemPpm, minTransfer uint64
	// state is "" while live, else the terminal state.
	state       string
	claimedAt   int64
	ordered     bool
	reminted    bool
	withdrawRID string
}

func (s *ledgerSlice) live() bool { return s.state == "" }

// MintBill mints a bill to recipients as mint_cash would, bypassing the
// connection, and returns its token. expiry 0 is never.
func (l *WithdrawLedger) MintBill(t testing.TB, expiry time.Duration, recipients ...nipcash.RecipientParam) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var at *int64
	if expiry > 0 {
		v := l.nowLocked() + int64(expiry/time.Second)
		at = &v
	}
	b, err := l.newBillLocked(recipients, at, nil)
	if err != nil {
		t.Fatalf("cashtest: mint: %v", err)
	}
	return b.token
}

// newBillLocked creates, funds and signs a bill in one step. from, when set, is
// the slice a cancelled withdrawal re-mints: its fee terms and ordered mark carry
// over.
func (l *WithdrawLedger) newBillLocked(recipients []nipcash.RecipientParam, expiresAt *int64, from *ledgerSlice) (*ledgerBill, error) {
	b := &ledgerBill{expiresAt: expiresAt}
	b.walletPriv, b.wallet = mustKeypair()
	b.connSecret, b.connPub = mustKeypair()
	var sum uint64
	for _, r := range recipients {
		s := &ledgerSlice{idType: r.IdentityType, idValue: r.IdentityValue, ia: r.IAPubkey, amount: r.AmountMillis,
			redeemBase: LedgerRedeemFeeBase, redeemPpm: LedgerRedeemFeePpm, minTransfer: LedgerMinTransfer}
		if from != nil {
			s.redeemBase, s.redeemPpm, s.minTransfer, s.ordered, s.reminted = from.redeemBase, from.redeemPpm, from.minTransfer, from.ordered, true
		}
		if s.idType == "cash" {
			b.cashMode = true
		}
		sum += r.AmountMillis
		b.slices = append(b.slices, s)
	}
	sign, err := nipcash.LocalMintSigner(l.h.NodePriv, "satscash")
	if err != nil {
		return nil, err
	}
	tok, err := nipcash.SignToken(nipcash.Token{HRP: "satscash", WalletPubkey: b.wallet, Secret: b.connSecret,
		RelayURLs: l.h.RelayURLs(), AttestedAmountMillis: &sum}, nipcash.SchemeMintV1, nil, l.h.nodeXOnly, sign)
	if err != nil {
		return nil, err
	}
	if b.token, err = nipcash.Encode(tok); err != nil {
		return nil, err
	}
	l.bills[b.wallet] = b
	return b, nil
}

func mustKeypair() (priv, xonly string) {
	priv = randHex(32)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		panic("cashtest: " + err.Error())
	}
	return priv, pub
}

// serveMint is mint_cash on the Cash Hub connection (NIP-CASH §Minting Cash),
// steps 2 to 8, against the ledger.
func (l *WithdrawLedger) serveMint(ev *nip01.Event, params json.RawMessage) (any, *nip47.Error) {
	refuse := func(code, msg string) (any, *nip47.Error) { return nil, &nip47.Error{Code: code, Message: msg} }
	var fields map[string]json.RawMessage
	if json.Unmarshal(params, &fields) != nil {
		return refuse(nipcash.ErrCodeBadRequest, "params")
	}
	var req nipcash.MintCashRequest
	if json.Unmarshal(params, &req) != nil || !nipcash.ValidRequestID(req.RequestID) {
		return refuse(nipcash.ErrCodeBadRequest, "request_id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[req.RequestID] {
		return refuse(nipcash.ErrCodeRequestReused, "request_id used")
	}
	l.used[req.RequestID] = true
	now := l.h.Clock.Now().Unix()
	exp, err := utils.FindUniqueEventTagValue(ev.Tags, "expiration")
	deadline, perr := strconv.ParseInt(exp, 10, 64)
	if err != nil || perr != nil || nipcash.CheckDeadline(deadline, now, l.h.Limits.MaxRequestAgeSeconds) != nil {
		return refuse(nipcash.ErrCodeBadRequest, "expiration")
	}
	for _, k := range []string{"idempotency_key", "min_transfer_millis"} {
		if _, ok := fields[k]; ok {
			return refuse(nipcash.ErrCodeBadRequest, k+" is not allowed")
		}
	}
	if len(req.Recipients) == 0 {
		return refuse(nipcash.ErrCodeBadRequest, "no recipients")
	}
	var sum uint64
	seen := map[[3]string]bool{}
	for _, r := range req.Recipients {
		k := [3]string{r.IdentityType, r.IdentityValue, r.IAPubkey}
		switch {
		case r.AmountMillis == 0, sum+r.AmountMillis < sum:
			return refuse(nipcash.ErrCodeBadRequest, "amount")
		case seen[k]:
			return refuse(nipcash.ErrCodeBadRequest, "duplicate recipient")
		case r.IdentityType == "cash" && (len(req.Recipients) != 1 || r.IAPubkey != "" || !nipcash.ValidCommitment(r.IdentityValue)):
			return refuse(nipcash.ErrCodeBadRequest, "cash recipient")
		case r.IdentityType == "connection_key" && r.IAPubkey == "":
			return refuse(nipcash.ErrCodeBadRequest, "ia_pubkey")
		case r.IdentityType != "cash" && r.IdentityType != "pubkey" && r.IdentityType != "connection_key":
			return refuse(nipcash.ErrCodeBadRequest, "identity_type")
		}
		seen[k] = true
		sum += r.AmountMillis
	}
	if sum > ledgerWalletCeiling {
		return refuse(nipcash.ErrCodeQuotaExceeded, "over the per-wallet ceiling")
	}
	if l.ext.liveCap > 0 && l.liveBillsLocked() >= l.ext.liveCap {
		return refuse(nipcash.ErrCodeQuotaExceeded, "over the Cash Hub's live-wallet cap")
	}
	l.h.mu.Lock()
	for _, r := range req.Recipients {
		if r.IdentityType == "connection_key" && !l.h.TrustedIAs[r.IAPubkey] {
			l.h.mu.Unlock()
			return refuse(nipcash.ErrCodeRestricted, "IA not trusted")
		}
	}
	l.h.mu.Unlock()
	if req.Expiry < 0 || req.Expiry > ledgerMaxExpirySeconds {
		return refuse(nipcash.ErrCodeBadRequest, "expiry")
	}
	var at *int64
	if req.Expiry > 0 {
		v := l.nowLocked() + req.Expiry
		at = &v
	}
	if !nipcash.CommitAllowed(deadline, l.h.Clock.Now().Unix()) {
		return refuse(nipcash.ErrCodeBadRequest, "past the deadline")
	}
	b, err := l.newBillLocked(req.Recipients, at, nil)
	if err != nil {
		return refuse(nipcash.ErrCodeInternal, "token")
	}
	res := map[string]any{"wallet_pubkey": b.wallet, "cash_token": b.token, "recipients": req.Recipients}
	if at != nil {
		res["expires_at"] = *at
	}
	if raw, err := json.Marshal(res); err == nil {
		// The record cash_lookup answers from: the connection's client key
		// authorized the call.
		l.calls[req.RequestID] = &callRecord{wallet: l.h.walletXOnly, authorizer: ev.PubKey, result: raw, minted: b}
	}
	return res, nil
}

// errResult is a refusal with an optional detail.
func errResult(code, msg string, detail nipcash.Detail) *transport.Result {
	return &transport.Result{Error: &transport.ResultError{Code: code, Message: msg, Detail: string(detail)}}
}

func okResult(v any) *transport.Result {
	raw, err := json.Marshal(v)
	if err != nil {
		return errResult(nipcash.ErrCodeInternal, "encode", "")
	}
	return &transport.Result{Result: raw}
}

// heldLocked reports whether the ledger still holds target for method (I2): a
// live bill; a destroyed one inside its tombstone window; for a lookup, any
// bill it minted; for a cancel request, a bill whose withdrawal record is kept.
func (l *WithdrawLedger) heldLocked(b *ledgerBill, method, serving string) bool {
	switch {
	case b == nil:
		return false
	case !b.destroyed || l.nowLocked() <= b.retainedUntil:
		return true
	case method == nipcash.MethodCashLookup:
		// The fake can always derive a bill's pairing key, so it answers a lookup
		// naming a bill it destroyed long ago (NIP-CASH §Looking Up a Call).
		return true
	case serving != nipcash.MethodCashLookup:
		return false
	}
	for _, p := range l.payouts {
		if p.wallet == b.wallet && l.retainedLocked(p) {
			return true
		}
	}
	return false
}

// item is one item being served against a ledger bill, after I3.
type ledgerItem struct {
	c       ItemCtx
	b       *ledgerBill
	serving string
	binding transport.ProofBinding
	// signer is the verified item proof's signer, "" without a proof.
	signer   string
	proofErr error
	secret   string
}

// decide serves one item naming a ledger bill, in the order of NIP-CASH
// §Serving an Envelope.
func (l *WithdrawLedger) decide(c ItemCtx) *transport.Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.Item.Target == l.h.walletXOnly {
		return l.mintLookupLocked(c)
	}
	b := l.bills[c.Item.Target]
	serving, servingErr := nipcash.ServingMethod(c.Item.Method, c.Item.Params)
	if servingErr != nil {
		serving = nipcash.MethodCashLookup // a malformed cancel request is held as one
	}
	if !l.heldLocked(b, c.Item.Method, serving) { // I2
		return nil
	}
	hash, err := transport.CanonicalParamsHash(c.Item.Params)
	if err != nil {
		return nil
	}
	it := &ledgerItem{c: c, b: b, serving: serving, binding: transport.ProofBinding{Target: b.wallet, HubXOnly: l.h.nodeXOnly,
		Method: c.Item.Method, ParamsHash: hash, Nonce: c.Envelope.Nonce, NotAfter: c.Envelope.NotAfter}}
	if signer, err := transport.VerifyBillProof(c.Item.BillProof, it.binding, c.Now); err != nil || signer != b.connPub { // I3
		return nil
	}
	if c.Item.HasProof() {
		it.signer, it.proofErr = transport.VerifyItemProof(c.Item.Proof, it.binding, c.Now)
		if it.proofErr != nil {
			it.signer = ""
		}
	}
	var p struct {
		CashSecret string `json:"cash_secret"`
	}
	_ = json.Unmarshal(c.Item.Params, &p)
	it.secret = p.CashSecret
	if b.destroyed && nipcash.AnswersWithTombstone(serving) && servingErr == nil { // I4
		return okResult(l.tombstoneLocked(b, it.signer))
	}
	if servingErr != nil {
		return errResult(nipcash.ErrCodeBadRequest, servingErr.Error(), "")
	}
	switch { // I5
	case !transport.IsServableMethod(serving):
		return errResult(nipcash.ErrCodeNotImplemented, serving+" is not served on this transport", "")
	case (serving == nipcash.MethodCashWithdrawQuote || serving == nipcash.MethodCashWithdraw) && !l.offered:
		return errResult(nipcash.ErrCodeNotImplemented, "this Hub does not offer on-chain withdrawals", "")
	case serving != nipcash.MethodCashStatus && serving != nipcash.MethodCashLookup &&
		serving != nipcash.MethodCashWithdrawQuote && serving != nipcash.MethodCashWithdraw &&
		serving != nipcash.MethodCashRedeem && serving != nipcash.MethodCashTransfer && serving != nipcash.MethodCashConsolidate:
		return errResult(nipcash.ErrCodeNotImplemented, "the fake ledger does not serve "+serving, "")
	}
	var rid struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(c.Item.Params, &rid)
	if nipcash.RequiresRequestID(serving) && !nipcash.ValidRequestID(rid.RequestID) { // I6
		return errResult(nipcash.ErrCodeBadRequest, "malformed request_id", "")
	}
	if nipcash.ReuseCheckApplies(serving) && l.used[rid.RequestID] { // I7
		return errResult(nipcash.ErrCodeRequestReused, "request_id used", "")
	}
	if !transport.BearerShapeOK(serving, c.Item.HasProof(), it.secret != "") { // I8
		return errResult(nipcash.ErrCodeBadRequest, "proof and cash_secret", "")
	}
	if it.proofErr != nil { // I9
		return errResult(nipcash.ErrCodeUnauthorized, "item proof", "")
	}
	if !c.Item.HasProof() && !b.cashMode && serving != nipcash.MethodCashLookup {
		return errResult(nipcash.ErrCodeUnauthorized, "a proofless item on a slice that is not cash-mode", "")
	}
	switch serving { // I10
	case nipcash.MethodCashStatus:
		return l.statusLocked(it)
	case nipcash.MethodCashWithdrawQuote:
		return l.quoteLocked(it)
	case nipcash.MethodCashWithdraw:
		return l.withdrawLocked(it)
	case nipcash.MethodCashRedeem:
		return l.redeemLocked(it)
	case nipcash.MethodCashTransfer:
		return l.transferLocked(it)
	case nipcash.MethodCashConsolidate:
		return l.consolidateLocked(it)
	}
	if c.Item.Method == nipcash.MethodCashWithdraw {
		return l.cancelLocked(it)
	}
	return l.lookupLocked(it)
}

// tombstoneLocked is a destroyed bill's tombstone, with withdraw_request_id for
// the authorizer of the withdrawal that ended its last slice.
func (l *WithdrawLedger) tombstoneLocked(b *ledgerBill, signer string) nipcash.Tombstone {
	until := b.retainedUntil
	t := nipcash.Tombstone{Status: nipcash.StatusSpent, Reason: nipcash.TombstoneReason(b.reason), RetainedUntil: &until}
	if p := l.payouts[b.endedBy]; p != nil && signer != "" && p.authorizer == signer && l.retainedLocked(p) {
		t.WithdrawRequestID = p.rid
	}
	return t
}

// destroyIfDrainedLocked destroys a bill whose every slice is terminal: its
// tombstone says the last slice's state.
func (l *WithdrawLedger) destroyIfDrainedLocked(b *ledgerBill, last *ledgerSlice) {
	for _, s := range b.slices {
		if s.live() || s.state == slicePaying {
			return
		}
	}
	b.destroyed, b.reason = true, last.state
	b.retainedUntil = l.nowLocked() + int64(l.h.TombstoneWindow/time.Second)
	b.endedBy = last.withdrawRID
}

// statusLocked is cash_status (NIP-CASH §Cash Status) with the withdraw object.
func (l *WithdrawLedger) statusLocked(it *ledgerItem) *transport.Result {
	var req struct {
		Scope *string `json:"scope"`
	}
	if json.Unmarshal(it.c.Item.Params, &req) != nil || (req.Scope != nil && !nipcash.IsValidCashStatusScope(*req.Scope)) {
		return errResult(nipcash.ErrCodeBadRequest, "scope", "")
	}
	all := req.Scope != nil && *req.Scope == nipcash.ScopeAll
	var rows []nipcash.RecipientStatus
	mine := false
	for _, s := range it.b.slices {
		own := it.b.cashMode && it.signer == "" || l.ownsLocked(s, it.signer)
		mine = mine || own
		if !all && !own {
			continue
		}
		fee, net, _ := nipcash.RedeemFee(s.amount, s.redeemBase, s.redeemPpm)
		row := nipcash.RecipientStatus{IdentityType: s.idType, IdentityValue: s.idValue, IAPubkey: s.ia, AmountMillis: s.amount,
			Claimed: !s.live(), RedeemFeeMillis: fee, NetRedeemableMillis: net, MinTransferMillis: s.minTransfer}
		if !s.live() {
			at := s.claimedAt
			row.ClaimedAt = &at
		}
		if it.b.expiresAt != nil {
			row.ExpiresAt = nipcash.Expiry{At: *it.b.expiresAt, Present: true}
		}
		if p := l.payouts[s.withdrawRID]; p != nil && it.signer != "" && p.authorizer == it.signer && l.retainedLocked(p) {
			row.WithdrawRequestID = p.rid
		}
		rows = append(rows, row)
	}
	if !mine {
		return errResult(nipcash.ErrCodeNotFound, "this bill is not addressed to you", "")
	}
	res := nipcash.CashStatusResult{Recipients: rows}
	if l.offered {
		terms := l.terms
		res.Withdraw = &terms
	}
	return okResult(res)
}

// ownsLocked reports signer holding s: a pubkey slice's key, or the key a
// connection_key slice's attestation named when it last verified here.
func (l *WithdrawLedger) ownsLocked(s *ledgerSlice, signer string) bool {
	switch {
	case signer == "":
		return false
	case s.idType == "pubkey":
		return s.idValue == signer
	case s.idType == "connection_key":
		return l.ckHolder[s.idValue+":"+s.ia] == signer
	}
	return false
}

// lookupLocked is cash_lookup of a withdrawal naming this bill (NIP-CASH
// §Looking Up a Call, §Withdrawals).
func (l *WithdrawLedger) lookupLocked(it *ledgerItem) *transport.Result {
	var req nipcash.CashLookupRequest
	if json.Unmarshal(it.c.Item.Params, &req) != nil || req.Validate() != nil || req.ConnectionPubkey != "" {
		return errResult(nipcash.ErrCodeBadRequest, "lookup", "")
	}
	if c := l.calls[req.RequestID]; c != nil {
		if c.wallet != it.b.wallet || !authorizes(c.cashCommitment, c.authorizer, it) {
			return errResult(nipcash.ErrCodeUnauthorized, "not the call's authorizer", "")
		}
		return okResult(map[string]any{"status": nipcash.LookupDone, "result": c.result})
	}
	p := l.payouts[req.RequestID]
	if p != nil && !l.retainedLocked(p) {
		p = nil
	}
	if p != nil {
		if p.wallet != it.b.wallet || !l.authorizesLocked(p, it) {
			return errResult(nipcash.ErrCodeUnauthorized, "not the call's authorizer", "")
		}
		return okResult(map[string]any{"status": nipcash.LookupDone, "result": l.payoutLocked(p)})
	}
	if !it.c.Item.HasProof() && req.CashSecret != "" {
		if !it.b.cashMode || !secretMatches(req.CashSecret, it.b.slices[0].idValue) {
			return errResult(nipcash.ErrCodeUnauthorized, "cash_secret", "")
		}
	}
	d := nipcash.DecideLookup(nipcash.LookupInput{Now: l.nowLocked(), Deadline: req.Deadline, Horizon: l.h.Limits.MaxRequestAgeSeconds})
	out := map[string]any{"status": d.Status}
	if d.Status == nipcash.LookupPending {
		out["retry_after"] = d.RetryAfter
	}
	return okResult(out)
}

// authorizesLocked is a lookup's (or a cancel request's) authorization against
// the record: the recorded authorizer's item proof, or, for a call a cash
// commitment authorized, no proof and the matching cash_secret.
func (l *WithdrawLedger) authorizesLocked(p *payout, it *ledgerItem) bool {
	return authorizes(p.cashCommitment, p.authorizer, it)
}

// authorizes is a lookup's authorization against a record by cashCommitment
// (for a call a cash commitment authorized) or authorizer.
func authorizes(cashCommitment, authorizer string, it *ledgerItem) bool {
	if cashCommitment != "" {
		var s struct {
			CashSecret string `json:"cash_secret"`
		}
		_ = json.Unmarshal(it.c.Item.Params, &s)
		return !it.c.Item.HasProof() && secretMatches(s.CashSecret, cashCommitment)
	}
	return it.signer != "" && it.signer == authorizer
}

func secretMatches(secret, commitment string) bool {
	if !nipcash.ValidCashSecret(secret) {
		return false
	}
	c, err := nipcash.CashCommitment(secret)
	return err == nil && nipcash.CommitmentsEqual(c, commitment)
}

// errCode reads a refusal's code, detail and message from a nipcash error.
func errCode(err error) *transport.Result {
	var we *nipcash.WithdrawError
	if errors.As(err, &we) {
		return errResult(we.Code, we.Reason, we.Detail)
	}
	var ce *nipcash.ClaimError
	if errors.As(err, &ce) {
		return errResult(ce.Code, ce.Reason, "")
	}
	return errResult(nipcash.ErrCodeInternal, "internal error", "")
}

// sliceKey names a connection_key slice by its value and IA.
func sliceKey(s *ledgerSlice) string { return s.idValue + ":" + s.ia }
