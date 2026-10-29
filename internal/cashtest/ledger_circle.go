package cashtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// The circle behind a ledger Hub made WithCircleHub: create_circle_wallet and
// its join lookups on the private transport (NIP-CW §Processing Algorithm, §Lost
// Join Reply, §Private Join), member requests submitted by the host
// (§Recovering a Lost Connection), several connections of the circle, and each
// issued Circle Wallet's own NWC connection (get_info, get_balance and
// delete_circle_wallet).
//
// Proofs are judged on the Hub's clock; everything else, the commit-time
// freshness check included, on the ledger's (the Hub's plus Advance).

// The circle's limits, reported in get_info and applied at step 6, and the rest
// of its terms.
const (
	CirclePerWalletMax        = 500_000
	CirclePerWalletMaxReceive = 500_000
	CircleMinRenewal          = nipcw.RenewalWeekly
	CircleMaxExpSecs          = 2_592_000
	CircleDefaultExpSecs      = 604_800
	CircleDustMillis          = 1000
	CircleRotationDelaySecs   = 432_000
	CircleHoldingsCeiling     = 1_000_000
	// CircleJoinRate joins per CircleJoinRateWindow pass step 7 per member.
	CircleJoinRate       = 3
	CircleJoinRateWindow = time.Hour
)

// circleDesk is the ledger's circle.
type circleDesk struct {
	conns    []*circleConn
	consumed map[string]int64 // join proof and member request ids, kept until
	joins    []*joinRecord
	wallets  map[string]*circleWallet // by wallet pubkey
	keys     map[string]*circleWallet // by authorized connection key
	rate     map[string][]int64       // member -> times a join passed step 7
	ceiling  uint64
}

type circleConn struct {
	secret, client string // client is the secret's pubkey, the bill-proof key
	revoked        bool
}

type joinRecord struct {
	signer, connPub string
	deadline        int64
	details         nipcw.CircleWalletDetails
	reply           string
	wallet          *circleWallet
}

type circleWallet struct {
	priv, pub, member, key string
	balance                uint64
	deleted                bool
	frozen                 bool
	join                   *joinRecord
	// pending is the rotation in progress; installed the one that set key.
	pending, installed *circleRotation
}

type circleRotation struct {
	newKey      string
	completesAt int64
}

// initCircleLocked sets the circle up when the Hub has one.
func (l *WithdrawLedger) initCircleLocked() {
	h := l.h
	if h.circle == nil {
		return
	}
	d := &circleDesk{consumed: map[string]int64{}, wallets: map[string]*circleWallet{}, keys: map[string]*circleWallet{},
		rate: map[string][]int64{}, ceiling: CircleHoldingsCeiling}
	client, _ := utils.GetPublicKey(h.circle.secret)
	d.conns = []*circleConn{{secret: h.circle.secret, client: client}}
	l.ext.circle = d
	block := maps.Clone(h.circle.wallet)
	block["per_wallet_max_millis"] = CirclePerWalletMax
	block["per_wallet_max_receive_millis"] = CirclePerWalletMaxReceive
	block["min_budget_renewal"] = CircleMinRenewal
	block["max_exp_secs"] = CircleMaxExpSecs
	block["dust_threshold_millis"] = CircleDustMillis
	block["rotation_delay_secs"] = CircleRotationDelaySecs
	h.circle.wallet = block
}

// circleTarget reports target naming the ledger's circle.
func (l *WithdrawLedger) circleTarget(target string) bool {
	return l.ext.circle != nil && l.h.circle != nil && target == l.h.circle.xonly
}

func (d *circleDesk) liveClients() []string {
	var out []string
	for _, c := range d.conns {
		if !c.revoked {
			out = append(out, c.client)
		}
	}
	return out
}

// circleClient reports pub being a live connection's client key.
func (l *WithdrawLedger) circleClient(pub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ext.circle != nil && slices.Contains(l.ext.circle.liveClients(), pub)
}

func (l *WithdrawLedger) acceptingLocked() bool {
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	on, _ := l.h.circle.wallet["accepting"].(bool)
	return on
}

// holdingsLocked is what the circle's Active wallets hold together.
func (l *WithdrawLedger) holdingsLocked() uint64 {
	var n uint64
	for _, w := range l.ext.circle.wallets {
		if !w.deleted && l.memberLocked(w.member) {
			n += w.balance
		}
	}
	return n
}

func (l *WithdrawLedger) memberLocked(pub string) bool {
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	return l.h.members[pub]
}

// circleAvailable is get_info's available_millis: the ceiling minus holdings,
// at least 0, capped at the per-wallet ceiling. ok is false without a circle.
func (l *WithdrawLedger) circleAvailable() (n uint64, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.ext.circle
	if d == nil {
		return 0, false
	}
	if held := l.holdingsLocked(); held < d.ceiling {
		n = d.ceiling - held
	}
	return min(n, CirclePerWalletMax), true
}

// decideCircle serves one item targeting the circle: a join or a join lookup.
func (l *WithdrawLedger) decideCircle(c ItemCtx) *transport.Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.ext.circle
	hash, err := transport.CanonicalParamsHash(c.Item.Params)
	if err != nil {
		return nil
	}
	binding := transport.ProofBinding{Target: c.Item.Target, HubXOnly: l.h.nodeXOnly, Method: c.Item.Method,
		ParamsHash: hash, Nonce: c.Envelope.Nonce, NotAfter: c.Envelope.NotAfter}
	if _, err := transport.VerifyBillProofAny(c.Item.BillProof, binding, c.Now, d.liveClients()); err != nil { // I3
		return nil
	}
	switch c.Item.Method { // I5
	case nipcw.MethodCreateCircleWallet, nipcash.MethodCashLookup:
	default:
		return errResult(nipcash.ErrCodeNotImplemented, "a Circle Wallet Hub connection serves joins and join lookups", "")
	}
	if c.Item.Method == nipcw.MethodCreateCircleWallet && !l.acceptingLocked() {
		// Refused before anything is consumed: the same proof joins once the
		// circle reopens.
		return errResult(nipcash.ErrCodeRestricted, "this circle is not accepting joins", "")
	}
	var signer string
	var proofErr error
	if c.Item.HasProof() {
		signer, proofErr = transport.VerifyItemProof(c.Item.Proof, binding, c.Now)
	}
	var p struct {
		CashSecret string `json:"cash_secret"`
	}
	_ = json.Unmarshal(c.Item.Params, &p)
	if !transport.BearerShapeOK(c.Item.Method, c.Item.HasProof(), p.CashSecret != "") { // I8
		return errResult(nipcash.ErrCodeBadRequest, "proof and cash_secret", "")
	}
	if proofErr != nil || !c.Item.HasProof() { // I9: both a join and its lookup carry the joiner's proof
		return errResult(nipcash.ErrCodeUnauthorized, "item proof", "")
	}
	if c.Item.Method == nipcash.MethodCashLookup {
		return l.joinLookupLocked(c, signer)
	}
	return l.joinLocked(c, signer)
}

// joinLocked is create_circle_wallet, steps 1 to 11.
func (l *WithdrawLedger) joinLocked(c ItemCtx, signer string) *transport.Result {
	d := l.ext.circle
	refuse := func(code, msg string) *transport.Result { return errResult(code, msg, "") }
	req, err := nipcw.ParseCreateCircleWalletRequest(c.Item.Params)
	if err != nil {
		return refuse(nipcw.ErrBadRequest, err.Error())
	}
	// Step 1 first, so a malformed request consumes nothing; then the item
	// proof's signer, which must be the request's pubkey; then steps 2 and 3.
	id, verr := nipcw.VerifyJoinProof(req, l.h.circle.xonly, c.Now, nil)
	var pe *nipcw.JoinProofError
	if errors.As(verr, &pe) && pe.Code == nipcw.ErrBadRequest {
		return refuse(pe.Code, pe.Reason)
	}
	if signer != req.Pubkey {
		return refuse(nipcw.ErrUnauthorized, "the item proof is not signed by the request's pubkey")
	}
	if verr != nil {
		if pe != nil {
			return refuse(pe.Code, pe.Reason)
		}
		return refuse(nipcw.ErrUnauthorized, verr.Error())
	}
	var proof nip01.Event
	_ = json.Unmarshal([]byte(req.IdentityEvent), &proof)
	createdAt := int64(proof.CreatedAt)
	if _, used := d.consumed[id]; used { // step 3
		return refuse(nipcw.ErrRequestReused, "proof already used")
	}
	d.consumed[id] = nipcw.JoinProofRetainUntil(createdAt)
	if !l.memberLocked(req.Pubkey) { // step 4
		return refuse(nipcw.ErrRestricted, "not a member of this circle")
	}
	if w := d.walletOf(req.Pubkey); w != nil { // step 5
		return refuse(nipcw.ErrWalletExists, "the member already holds a wallet here")
	}
	renewal := req.BudgetRenewal
	if renewal == "" {
		renewal = nipcw.RenewalNever
	}
	switch { // step 6
	case req.MaxAmount > CirclePerWalletMax:
		return refuse(nipcw.ErrLimitExceeded, "max_amount is over the per-wallet ceiling")
	case req.MaxReceive > CirclePerWalletMaxReceive:
		return refuse(nipcw.ErrLimitExceeded, "max_receive is over the per-wallet ceiling")
	case !nipcw.RenewalAtLeast(renewal, CircleMinRenewal):
		return refuse(nipcw.ErrLimitExceeded, "budget_renewal is tighter than the floor")
	case req.Expiry > CircleMaxExpSecs:
		return refuse(nipcw.ErrLimitExceeded, "expiry is over the ceiling")
	}
	now := l.nowLocked()
	var recent []int64 // step 7
	for _, at := range d.rate[req.Pubkey] {
		if at > now-int64(CircleJoinRateWindow/time.Second) {
			recent = append(recent, at)
		}
	}
	if len(recent) >= CircleJoinRate {
		d.rate[req.Pubkey] = recent
		return refuse(nipcw.ErrRateLimited, "too many joins")
	}
	d.rate[req.Pubkey] = append(recent, now)
	// Step 8 holds: the whole join is one critical section. Step 9.
	if now > createdAt+nipcw.JoinFreshness {
		return refuse(nipcw.ErrBadRequest, "the proof passed its freshness window before the join could commit")
	}
	if l.holdingsLocked() >= d.ceiling {
		return refuse(nipcw.ErrInsufficientCapacity, "the circle is at its holdings ceiling")
	}
	if d.keyTaken(req.ConnectionPubkey) {
		return refuse(nipcw.ErrRestricted, "connection_pubkey is in use or pending in a rotation")
	}
	exp := req.Expiry
	if exp == 0 {
		exp = CircleDefaultExpSecs
	}
	w := &circleWallet{member: req.Pubkey, key: req.ConnectionPubkey}
	w.priv, w.pub = mustKeypair()
	rot := uint64(CircleRotationDelaySecs)
	det := nipcw.CircleWalletDetails{WalletPubkey: w.pub, ConnectionPubkey: req.ConnectionPubkey, Relays: l.h.RelayURLs(),
		MaxAmount: req.MaxAmount, MaxReceive: req.MaxReceive, ExpiresAt: now + int64(exp), FeesPpm: 0,
		DustThresholdMillis: CircleDustMillis, RotationDelaySecs: &rot, BudgetRenewal: renewal}
	reply, err := nipcw.EncryptDetails(l.h.circle.priv, req.Pubkey, det)
	if err != nil {
		return refuse(nipcash.ErrCodeInternal, "details")
	}
	w.join = &joinRecord{signer: req.Pubkey, connPub: req.ConnectionPubkey, deadline: createdAt + nipcw.JoinFreshness,
		details: det, reply: reply, wallet: w}
	d.joins = append(d.joins, w.join)
	d.wallets[w.pub] = w
	d.keys[w.key] = w
	return &transport.Result{Result: json.RawMessage(reply)}
}

// walletOf is member's Active or Suspended wallet.
func (d *circleDesk) walletOf(member string) *circleWallet {
	for _, w := range d.wallets {
		if w.member == member && !w.deleted {
			return w
		}
	}
	return nil
}

// keyTaken reports key authorized for a connection on the node, or pending in a
// rotation on it.
func (d *circleDesk) keyTaken(key string) bool {
	if _, ok := d.keys[key]; ok {
		return true
	}
	for _, w := range d.wallets {
		if w.pending != nil && w.pending.newKey == key {
			return true
		}
	}
	return false
}

// settleLocked completes or cancels w's pending rotation once it is due.
func (l *WithdrawLedger) settleLocked(w *circleWallet) {
	r := w.pending
	if r == nil || l.nowLocked() < r.completesAt {
		return
	}
	w.pending = nil
	if other, used := l.ext.circle.keys[r.newKey]; used && other != w {
		return // the new key is in use by then: cancelled
	}
	delete(l.ext.circle.keys, w.key)
	w.key, w.installed, w.frozen = r.newKey, r, false
	l.ext.circle.keys[w.key] = w
}

// joinLookupLocked is cash_lookup on the circle (NIP-CW §Lost Join Reply). It
// writes nothing.
func (l *WithdrawLedger) joinLookupLocked(c ItemCtx, signer string) *transport.Result {
	var req nipcash.CashLookupRequest
	if json.Unmarshal(c.Item.Params, &req) != nil || req.Validate() != nil || req.ConnectionPubkey == "" {
		return errResult(nipcash.ErrCodeBadRequest, "a join lookup names connection_pubkey and deadline", "")
	}
	d := l.ext.circle
	now := l.nowLocked()
	for _, j := range d.joins {
		if j.signer == signer && j.connPub == req.ConnectionPubkey && (!j.wallet.deleted || now <= j.deadline+nipcash.JoinLookupWindow) {
			return okResult(map[string]any{"status": nipcash.LookupDone, "result": json.RawMessage(j.reply)})
		}
	}
	for _, w := range d.wallets {
		if w.member != signer || w.deleted {
			continue
		}
		l.settleLocked(w)
		switch {
		case w.pending != nil && w.pending.newKey == req.ConnectionPubkey:
			return okResult(map[string]any{"status": nipcash.LookupPending, "retry_after": w.pending.completesAt})
		case w.installed != nil && w.installed.newKey == req.ConnectionPubkey:
			det := w.join.details
			det.ConnectionPubkey = w.key
			reply, err := nipcw.EncryptDetails(l.h.circle.priv, w.member, det)
			if err != nil {
				return errResult(nipcash.ErrCodeInternal, "details", "")
			}
			return okResult(map[string]any{"status": nipcash.LookupDone, "result": json.RawMessage(reply)})
		}
	}
	dec := nipcash.DecideLookup(nipcash.LookupInput{Now: now, Deadline: req.Deadline, Join: true})
	out := map[string]any{"status": dec.Status}
	if dec.Status == nipcash.LookupPending {
		out["retry_after"] = dec.RetryAfter
	}
	return okResult(out)
}

// MemberRequestError is a member request the Hub refused, with its code.
type MemberRequestError struct{ Code, Reason string }

func (e *MemberRequestError) Error() string {
	return "cashtest: member request: " + e.Code + ": " + e.Reason
}

// MemberRequest is the host submitting a member's request (NIP-CW §Recovering
// a Lost Connection), checked in the spec's order: a rotate becomes pending
// for CircleRotationDelaySecs on the ledger's clock; a freeze or unfreeze
// applies at once.
func (l *WithdrawLedger) MemberRequest(ev *nip01.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.ext.circle
	if d == nil {
		return &MemberRequestError{Code: nipcw.ErrNotImplemented, Reason: "no circle"}
	}
	refuse := func(code, msg string) error { return &MemberRequestError{Code: code, Reason: msg} }
	mr, err := nipcw.VerifyMemberRequest(ev, l.h.circle.xonly, l.nowTimeLocked(), func(id string) bool {
		_, used := d.consumed[id]
		d.consumed[id] = nipcw.MemberRequestRetainUntil(int64(ev.CreatedAt))
		return used
	})
	if err != nil {
		var pe *nipcw.JoinProofError
		if errors.As(err, &pe) {
			return refuse(pe.Code, pe.Reason)
		}
		return refuse(nipcw.ErrUnauthorized, err.Error())
	}
	w := d.wallets[mr.Wallet]
	switch {
	case w == nil || w.deleted:
		return refuse(nipcw.ErrNotFound, "no such wallet")
	case mr.Pubkey != w.member:
		return refuse(nipcw.ErrUnauthorized, "not the wallet's member")
	case w.join.details.RotationDelaySecs == nil:
		return refuse(nipcw.ErrNotImplemented, "the wallet cannot be rotated")
	}
	l.settleLocked(w)
	switch mr.Action {
	case nipcw.ActionFreeze:
		w.frozen = true
	case nipcw.ActionUnfreeze:
		w.frozen = false
	case nipcw.ActionRotate:
		if w.pending != nil {
			return refuse(nipcw.ErrRotationPending, "a rotation is pending")
		}
		if err := mr.CheckConnection(); err != nil || d.keyTaken(mr.Connection) {
			return refuse(nipcw.ErrRestricted, "the new key is invalid, in use or pending")
		}
		w.pending = &circleRotation{newKey: mr.Connection, completesAt: l.nowLocked() + int64(*w.join.details.RotationDelaySecs)}
	}
	return nil
}

// AddCircleConnection issues another connection of the circle (the same Hub
// pubkey, its own secret) and returns its signed circlehub1 string.
func (l *WithdrawLedger) AddCircleConnection() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ext.circle == nil {
		return "", errors.New("cashtest: the ledger has no circle")
	}
	secret, client := mustKeypair()
	l.ext.circle.conns = append(l.ext.circle.conns, &circleConn{secret: secret, client: client})
	return l.h.circleConnectionString(secret)
}

// RevokeCircleConnection revokes the connection whose circlehub1 string is s:
// its bill proofs verify nothing from then on.
func (l *WithdrawLedger) RevokeCircleConnection(s string) error {
	c, err := nipcw.DecodeCircleHubConnection(s)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ext.circle == nil {
		return errors.New("cashtest: the ledger has no circle")
	}
	for _, cc := range l.ext.circle.conns {
		if cc.secret == c.Secret {
			cc.revoked = true
			return nil
		}
	}
	return errors.New("cashtest: no such circle connection")
}

// SetCircleAccepting opens or closes the circle to joins (get_info accepting).
func (l *WithdrawLedger) SetCircleAccepting(on bool) {
	l.h.mu.Lock()
	defer l.h.mu.Unlock()
	block := maps.Clone(l.h.circle.wallet)
	block["accepting"] = on
	l.h.circle.wallet = block
}

// FundCircleWallet credits millis to the circle wallet wallet, as a payment
// received would.
func (l *WithdrawLedger) FundCircleWallet(wallet string, millis uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ext.circle == nil {
		return errors.New("cashtest: the ledger has no circle")
	}
	w := l.ext.circle.wallets[wallet]
	if w == nil || w.deleted {
		return ErrNoSuchBill
	}
	w.balance += millis
	return nil
}

// circleConnectionString is a circlehub1 string for the circle with secret,
// signed by the node identity.
func (h *FakeHub) circleConnectionString(secret string) (string, error) {
	sign, err := nipcash.LocalChainSigner(h.NodePriv, FakeChain)
	if err != nil {
		return "", err
	}
	c, err := nipcw.SignCircleHubConnection(nipcw.CircleHubConnection{
		Pubkey: h.circle.xonly, Secret: secret, Relays: h.RelayURLs(),
		Label: "Fake Circle", HasLabel: true, HubIdentity: h.nodeXOnly, Chain: FakeChain,
	}, sign, h.nodeXOnly)
	if err != nil {
		return "", err
	}
	return nipcw.EncodeCircleHubConnection(c)
}

// CircleWalletMethods are the methods an issued Circle Wallet's connection
// answers on the fake.
var CircleWalletMethods = []string{"get_info", "get_balance", nipcw.MethodDeleteCircleWallet}

// serveCircleWallet answers a kind-23194 request to an issued Circle Wallet,
// signed by its current key (or, while a rotation is pending, the old one,
// which cancels it). It reports whether ev was for one of them.
func (l *WithdrawLedger) serveCircleWallet(r *Relay, ev *nip01.Event) bool {
	var reply *nip01.Event
	defer func() { // published once the ledger is unlocked
		if reply != nil {
			r.Publish(reply)
		}
	}()
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.ext.circle
	if d == nil {
		return false
	}
	var w *circleWallet
	for _, c := range d.wallets {
		if taggedP(ev, c.pub) {
			w = c
		}
	}
	if w == nil || w.deleted {
		return w != nil
	}
	l.settleLocked(w)
	if ev.PubKey != w.key {
		return true // not this wallet's key: no answer
	}
	req, err := nip47.ParseRequestEvent(ev, w.priv)
	if err != nil {
		return true
	}
	encryption := nip47.EncryptionNIP04 // legacy-check: NIP-47's reading of a request with no encryption tag
	if enc, err := utils.FindUniqueEventTagValue(ev.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}
	answer := func(res any, e *nip47.Error) {
		var resp *nip01.Event
		var err error
		if e != nil {
			resp, err = nip47.NewErrorResponseEvent(w.priv, ev.PubKey, req.Method, *e, ev, encryption)
		} else {
			resp, err = nip47.NewResponseEvent(w.priv, ev.PubKey, req.Method, res, ev, encryption)
		}
		if err == nil && resp.Sign(w.priv) == nil {
			reply = resp
		}
	}
	if w.frozen {
		answer(nil, &nip47.Error{Code: nipcw.ErrFrozen, Message: "the wallet is frozen"})
		return true
	}
	w.pending = nil // a request by the current key cancels a pending rotation
	switch req.Method {
	case "get_info":
		answer(nip47.GetInfoResult{Pubkey: w.pub, Network: FakeNetwork, Chain: FakeChain, Methods: CircleWalletMethods}, nil)
	case "get_balance":
		answer(map[string]any{"balance": w.balance}, nil)
	case nipcw.MethodDeleteCircleWallet:
		if w.balance > w.join.details.DustThresholdMillis {
			answer(nil, &nip47.Error{Code: nipcw.ErrRestricted, Message: fmt.Sprintf("the wallet holds %d, more than dust", w.balance)})
			return true
		}
		w.deleted = true
		delete(d.keys, w.key)
		answer(map[string]any{}, nil)
	default:
		answer(nil, &nip47.Error{Code: nipcw.ErrNotImplemented, Message: req.Method + " is not served by the fake circle wallet"})
	}
	return true
}
