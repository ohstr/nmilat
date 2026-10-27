package client

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/utils"
)

// The WP-11 scenarios (T11-*, E-MINT-*, E-XFER-*, E-STAT-*, E-RED-*, E-LK-*,
// E-ENV-*) that run end to end against the fake Hub's bill ledger.

const mapAmount = uint64(21_000_000)

// mapEnv is a fake Hub with a bill ledger, a manual clock, a one-shot fault for
// the next item of one method, and a log of the items it served.
type mapEnv struct {
	h     *cashtest.FakeHub
	l     *cashtest.WithdrawLedger
	clock *cashtest.ManualClock

	fault atomic.Pointer[mapFault]

	mu    sync.Mutex
	items []transport.Item
}

type mapFault struct {
	method string
	f      cashtest.Fault
}

func newMapEnv(t *testing.T, opts ...cashtest.Option) *mapEnv {
	t.Helper()
	e := &mapEnv{clock: cashtest.NewManualClock(time.Now())}
	opts = append([]cashtest.Option{cashtest.WithClock(e.clock), cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
		f := e.fault.Load()
		if f == nil {
			return cashtest.FaultNone
		}
		if serving, _ := nipcash.ServingMethod(c.Item.Method, c.Item.Params); serving == f.method && e.fault.CompareAndSwap(f, nil) {
			return f.f
		}
		return cashtest.FaultNone
	})}, opts...)
	e.h = cashtest.NewFakeHub(t, opts...)
	e.l = e.h.ServeWithdrawals(t, nil)
	served := e.h.Decide
	e.h.Decide = func(c cashtest.ItemCtx) *transport.Result {
		e.mu.Lock()
		e.items = append(e.items, c.Item)
		e.mu.Unlock()
		return served(c)
	}
	return e
}

// faultNext makes the next item of method suffer f.
func (e *mapEnv) faultNext(method string, f cashtest.Fault) {
	e.fault.Store(&mapFault{method: method, f: f})
}

func (e *mapEnv) served() []transport.Item {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]transport.Item(nil), e.items...)
}

func (e *mapEnv) connect(t *testing.T, token string) *Client {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	c, err := Connect(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// pubkeyBill mints a one-slice pubkey bill and returns its client and key.
func (e *mapEnv) pubkeyBill(t *testing.T) (*Client, string, string) {
	t.Helper()
	priv, pub := sessionKeypair(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: mapAmount})
	return e.connect(t, tok), priv, tok
}

// cashBill mints a one-slice cash-mode bill and returns its client and secret.
func (e *mapEnv) cashBill(t *testing.T) (*Client, string) {
	t.Helper()
	target := mustCashTarget(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "cash", IdentityValue: target.Commitment(), AmountMillis: mapAmount})
	return e.connect(t, tok), target.Secret()
}

// published is every event the Hub's relays accepted.
func (e *mapEnv) published() []*nip01.Event {
	var out []*nip01.Event
	for _, r := range e.h.Relays {
		out = append(out, r.Accepted()...)
	}
	return out
}

// codeOf is the Hub's refusal code behind a client error, "" for none.
func codeOf(err error) string {
	var ie *IndeterminateError
	if errors.As(err, &ie) {
		return ie.Code
	}
	var fe *FinalError
	if errors.As(err, &fe) {
		return fe.Code
	}
	var we *relayclient.WalletError
	if errors.As(err, &we) {
		return we.Code
	}
	return ""
}

func pendingOf(t *testing.T, err error) nipcash.PendingCall {
	t.Helper()
	var ie *IndeterminateError
	if !errors.As(err, &ie) {
		t.Fatalf("err = %v, want an IndeterminateError", err)
	}
	return ie.Call
}

func mapCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := e2eContext(t)
	t.Cleanup(cancel)
	return ctx
}

// E-MINT-01, T11-06, T11-39: a mint over the Cash Hub connection is written
// ahead before the request is published, carries a fresh valid request_id and
// a NIP-47 expiration equal to the journalled deadline (≤ now + H), and its
// token's provenance verifies against the get_info identity.
func TestEMINT01_MintWrittenAheadWithExpiration(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	h, err := ConnectCashHub(ctx, e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	j := newTestJournal()
	var writtenFirst bool
	pctx := WithPublishFilter(ctx, func(ev *nip01.Event) bool {
		writtenFirst = len(j.all()) == 1
		return true
	})
	_, pub := sessionKeypair(t)
	res, err := h.MintCash(pctx, nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(pub), 5000)}}, j, "dev")
	if err != nil {
		t.Fatalf("MintCash: %v", err)
	}
	if !writtenFirst {
		t.Fatal("the mint was published before it was written ahead")
	}
	pc := j.all()[0]
	if !nipcash.ValidRequestID(pc.RequestID) || pc.Method != nipcash.MethodMintCash {
		t.Fatalf("written call %+v", pc)
	}
	if pc.Deadline > time.Now().Unix()+pc.MaxRequestAge {
		t.Errorf("deadline %d beyond now + H %d", pc.Deadline, pc.MaxRequestAge)
	}
	var mints int
	for _, ev := range e.published() {
		if ev.Kind != 23194 {
			continue
		}
		exp, err := utils.FindUniqueEventTagValue(ev.Tags, "expiration")
		if err != nil {
			continue // the get_info read
		}
		mints++
		if exp != strconv.FormatInt(pc.Deadline, 10) {
			t.Errorf("expiration %s, journalled deadline %d", exp, pc.Deadline)
		}
	}
	if mints != 1 {
		t.Fatalf("%d mint requests with an expiration", mints)
	}
	tok, err := nipcash.Decode(res.CashToken)
	if err != nil {
		t.Fatal(err)
	}
	minter, ok := nipcash.VerifyProvenance(tok)
	if !ok || !nipcash.HubIdentityEqual(e.h.NodeXOnly(), minter) {
		t.Fatalf("token provenance %q %v, want the get_info identity", minter, ok)
	}

	// T11-06: a second call gets its own fresh id.
	if _, err := h.MintCash(ctx, nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(pub), 5000)}}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	if all := j.all(); len(all) != 2 || all[1].RequestID == pc.RequestID || !nipcash.ValidRequestID(all[1].RequestID) {
		t.Fatalf("second mint's id: %+v", all)
	}
}

// E-MINT-10, E-MINT-06 (the REQUEST_REUSED half): a mint whose expiration has
// passed on arrival is BAD_REQUEST, final; a corrected call with a fresh id
// commits; the old id resent is REQUEST_REUSED, pending, never final.
func TestEMINT10_ExpiredOnArrival(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	h, err := ConnectCashHub(ctx, e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	_, pub := sessionKeypair(t)
	p := nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(pub), 5000)}}
	if _, err := h.Info(ctx); err != nil { // the session is open before the clock moves
		t.Fatal(err)
	}
	e.clock.Advance(10 * time.Minute)
	j := newTestJournal()
	_, err = h.MintCash(ctx, p, j, "dev")
	var fe *FinalError
	if !errors.As(err, &fe) || fe.Code != nipcash.ErrCodeBadRequest {
		t.Fatalf("expired on arrival: %v, want a BAD_REQUEST FinalError", err)
	}
	old := j.all()[0].RequestID
	e.clock.Set(time.Now())
	if _, err := h.MintCash(ctx, p, j, "dev"); err != nil {
		t.Fatalf("corrected mint: %v", err)
	}
	p.RequestID = old
	_, err = h.MintCash(ctx, p, j, "dev")
	pc := pendingOf(t, err)
	if !pc.SawReused || pc.LastCode != "" {
		t.Fatalf("old id resent: %+v, want SawReused and no LastCode", pc)
	}
}

// E-MINT-12, T11-13 (mint), T11-55: a mint lookup names the Cash Hub
// connection's TLV 0 as its target, both of its proofs are signed by the
// connection key, and it goes to the Hub identity of TLV 4.
func TestEMINT12_LookupMintWiring(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	conn, err := nipcash.DecodeCashHubConnection(e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := utils.GetPublicKey(conn.Secret)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ConnectCashHub(ctx, e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	pc := nipcash.PendingCall{RequestID: testRequestID, Method: nipcash.MethodMintCash, Deadline: time.Now().Unix() + 30}
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _ = h.LookupMint(short, pc) // the ledger holds no record under TLV 0: omitted

	s, err := h.batchSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.HubIdentity() != conn.HubIdentity {
		t.Fatalf("lookup session Hub identity %s, want TLV 4 %s", s.HubIdentity(), conn.HubIdentity)
	}
	envs := e.h.Envelopes()
	if len(envs) != 1 || len(envs[0].Items) != 1 {
		t.Fatalf("envelopes %+v", envs)
	}
	item := envs[0].Items[0]
	if item.Target != conn.Pubkey || item.Method != nipcash.MethodCashLookup {
		t.Fatalf("lookup item target %s method %s, want TLV 0 %s", item.Target, item.Method, conn.Pubkey)
	}
	hash, err := transport.CanonicalParamsHash(item.Params)
	if err != nil {
		t.Fatal(err)
	}
	b := transport.ProofBinding{Target: conn.Pubkey, HubXOnly: conn.HubIdentity, Method: item.Method, ParamsHash: hash,
		Nonce: envs[0].Nonce, NotAfter: envs[0].NotAfter}
	if signer, err := transport.VerifyBillProof(item.BillProof, b, time.Now()); err != nil || signer != clientKey {
		t.Errorf("bill proof signer %s %v, want the connection key %s", signer, err, clientKey)
	}
	if signer, err := transport.VerifyItemProof(item.Proof, b, time.Now()); err != nil || signer != clientKey {
		t.Errorf("item proof signer %s %v, want the connection key %s", signer, err, clientKey)
	}
}

// E-XFER-01: a full transfer of a pubkey slice moves it in place; the old
// identity then gets NOT_FOUND and the new one redeems.
func TestEXFER01_FullTransferInPlace(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	newPriv, newPub := sessionKeypair(t)
	res, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(priv), To: nipcash.Pubkey(newPub),
		CurrentAmount: mapAmount}, newTestJournal(), "dev")
	if err != nil || res.NewWalletToken != "" || res.IdentityValue != newPub {
		t.Fatalf("transfer: %+v %v, want in place", res, err)
	}
	if _, err := c.CashStatus(ctx, nipcash.BySigning(priv), nipcash.ScopeMine); codeOf(err) != nipcash.ErrCodeNotFound {
		t.Fatalf("old identity status: %v, want NOT_FOUND", err)
	}
	fee, net, _ := nipcash.RedeemFee(mapAmount, cashtest.LedgerRedeemFeeBase, cashtest.LedgerRedeemFeePpm)
	r, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: e.l.Invoice(net), Credential: nipcash.BySigning(newPriv)})
	if err != nil || r.FeesPaid != fee {
		t.Fatalf("new identity redeem: %+v %v", r, err)
	}
}

// E-XFER-06, E-XFER-08, T11-17: a split whose reply is dropped after the commit
// is indeterminate; the lookup is done with both tokens, which decrypt with the
// original credential.
func TestEXFER06_ReplyLostAfterCommit(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	_, to := sessionKeypair(t)
	split := uint64(5_000_000)
	p := nipcash.CashTransferParams{Credential: nipcash.BySigning(priv), To: nipcash.Pubkey(to), CurrentAmount: mapAmount, SplitAmount: &split}
	e.faultNext(nipcash.MethodCashTransfer, cashtest.FaultCommitThenDropReply)
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := c.CashTransfer(short, p, newTestJournal(), "dev")
	pc := pendingOf(t, err)
	lo, err := c.LookupTransfer(ctx, pc, nipcash.BySigning(priv))
	if err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup: %+v %v", lo, err)
	}
	res, err := p.ParseLookupResult(lo.Result)
	if err != nil {
		t.Fatalf("the looked-up result does not open with the original credential: %v", err)
	}
	for _, tok := range []string{res.NewWalletToken, res.RemainderWalletToken} {
		if _, err := nipcash.Decode(tok); err != nil {
			t.Fatalf("token %q: %v", tok, err)
		}
	}
	if res.AmountMillis != split || res.RemainingAmountMillis == nil || *res.RemainingAmountMillis != mapAmount-split {
		t.Fatalf("result %+v", res)
	}
}

// E-XFER-07: a transfer dropped before the commit is pending, then unknown past
// its deadline; Recover re-places it automatically on the owner device under
// the derived id, and the re-placed call is done.
func TestEXFER07_DroppedBeforeCommitReplaced(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	cred := nipcash.BySigning(priv)
	_, to := sessionKeypair(t)
	p := nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to), CurrentAmount: mapAmount}
	e.faultNext(nipcash.MethodCashTransfer, cashtest.FaultDropBeforeCommit)
	j := newTestJournal()
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := c.CashTransfer(short, p, j, "dev")
	pc := pendingOf(t, err)
	if lo, err := c.LookupTransfer(ctx, pc, cred); err != nil || lo.Status != nipcash.LookupPending {
		t.Fatalf("before the deadline: %+v %v, want pending", lo, err)
	}
	e.l.Advance(2 * time.Minute)
	lookup := func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		return c.LookupTransfer(ctx, pc, cred)
	}
	act, err := Recover(ctx, pc, lookup, "dev", time.Now())
	if err != nil || act.Kind != ActionReplace {
		t.Fatalf("Recover: %+v %v, want ActionReplace", act, err)
	}
	send := func(ctx context.Context, next nipcash.PendingCall) error {
		again := p
		again.RequestID = next.RequestID
		_, err := c.CashTransfer(ctx, again, j, "dev")
		return err
	}
	if act, err := Replace(ctx, pc, j, ReplaceOptions{}, send); err != nil || act.Kind != ActionWait {
		t.Fatalf("Replace: %+v %v", act, err)
	}
	derived, _ := nipcash.DerivedRequestID(pc.RequestID)
	next, ok := j.call(derived)
	if !ok || next.DerivedFrom != pc.RequestID {
		t.Fatalf("derived call %+v", next)
	}
	if lo, err := c.LookupTransfer(ctx, next, cred); err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("derived lookup: %+v %v, want done", lo, err)
	}
}

// E-XFER-09: a transfer whose commit stalls past its deadline is BAD_REQUEST,
// final; its lookup is unknown and the source proof is still unconsumed.
func TestEXFER09_StallPastDeadline(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	cred := nipcash.BySigning(priv)
	_, to := sessionKeypair(t)
	p := nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to), CurrentAmount: mapAmount}
	until := e.clock.Now().Add(2 * time.Minute)
	e.faultNext(nipcash.MethodCashTransfer, cashtest.FaultStallUntil(until))
	go func() {
		for len(e.h.Envelopes()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		e.clock.Set(until)
	}()
	j := newTestJournal()
	_, err := c.CashTransfer(ctx, p, j, "dev")
	var fe *FinalError
	if !errors.As(err, &fe) || fe.Code != nipcash.ErrCodeBadRequest {
		t.Fatalf("stalled past the deadline: %v, want a BAD_REQUEST FinalError", err)
	}
	pc := j.all()[0]
	e.clock.Set(time.Now())
	e.l.Advance(2 * time.Minute) // the ledger's D+1..D+H
	if lo, err := c.LookupTransfer(ctx, pc, cred); err != nil || lo.Status != nipcash.LookupUnknown {
		t.Fatalf("lookup: %+v %v, want unknown", lo, err)
	}
	if st, err := c.CashStatus(ctx, cred, nipcash.ScopeMine); err != nil || len(st.Recipients) != 1 || st.Recipients[0].Claimed {
		t.Fatalf("source after the refused commit: %+v %v, want unclaimed", st, err)
	}
}

// E-XFER-10, T11-08: a resend under a committed id is REQUEST_REUSED, pending
// (never the original's outcome); the lookup reads it as done.
func TestEXFER10_ResendSameID(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	cred := nipcash.BySigning(priv)
	_, to := sessionKeypair(t)
	j := newTestJournal()
	p := nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to), CurrentAmount: mapAmount, RequestID: testRequestID}
	if _, err := c.CashTransfer(ctx, p, j, "dev"); err != nil {
		t.Fatal(err)
	}
	_, err := c.CashTransfer(ctx, p, j, "dev")
	pc := pendingOf(t, err)
	if !pc.SawReused || pc.LastCode != "" || codeOf(err) != nipcash.ErrCodeRequestReused {
		t.Fatalf("resend: %+v %v", pc, err)
	}
	if lo, err := c.LookupTransfer(ctx, pc, cred); err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup: %+v %v, want done", lo, err)
	}
}

// E-XFER-13, T11-32, T11-15 (end to end): a split of a cash source whose reply
// is lost: the remainder secret is written ahead with role remainder and a
// commitment other than the source's; the bearer lookup goes without the secret
// (UNAUTHORIZED), then with it (done); the giver's old secret moves nothing.
func TestEXFER13_CashSplitReplyLost(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, secret := e.cashBill(t)
	cred := nipcash.BySecret(secret)
	remainder := mustCashTarget(t)
	_, to := sessionKeypair(t)
	split := uint64(5_000_000)
	p := nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to), CurrentAmount: mapAmount, SplitAmount: &split, RemainderTarget: remainder}
	e.faultNext(nipcash.MethodCashTransfer, cashtest.FaultCommitThenDropReply)
	j := newTestJournal()
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := c.CashTransfer(short, p, j, "dev")
	pc := pendingOf(t, err)
	written := j.all()[0]
	src, _ := nipcash.CashTargetFromSecret(secret)
	var role bool
	for _, s := range written.Secrets {
		if s.Role == "remainder" && s.Secret == remainder.Secret() {
			role = true
		}
	}
	if !role || written.SourceSecret != secret || nipcash.CommitmentsEqual(remainder.Commitment(), src.Commitment()) {
		t.Fatalf("written call %+v", written)
	}
	before := len(e.served())
	lo, err := c.LookupTransfer(ctx, pc, cred)
	if err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("bearer lookup: %+v %v", lo, err)
	}
	var withSecret []bool
	for _, it := range e.served()[before:] {
		var q nipcash.CashLookupRequest
		_ = json.Unmarshal(it.Params, &q)
		withSecret = append(withSecret, q.CashSecret != "")
	}
	if len(withSecret) != 2 || withSecret[0] || !withSecret[1] {
		t.Fatalf("lookup items carried the secret %v, want [false true]", withSecret)
	}
	_, to2 := sessionKeypair(t)
	if _, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to2), CurrentAmount: mapAmount},
		newTestJournal(), "dev"); err == nil {
		t.Fatal("the giver's old secret moved the source again")
	}
}

// E-XFER-16: a transfer naming a destroyed bill gets its tombstone: *BillGone,
// nothing moved.
func TestEXFER16_DestroyedBill(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, tok := e.pubkeyBill(t)
	decoded, _ := nipcash.Decode(tok)
	if err := e.l.DeleteBill(decoded.WalletPubkey); err != nil {
		t.Fatal(err)
	}
	_, to := sessionKeypair(t)
	_, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(priv), To: nipcash.Pubkey(to), CurrentAmount: mapAmount},
		newTestJournal(), "dev")
	var gone *nipcash.BillGone
	if !errors.As(err, &gone) {
		t.Fatalf("err = %v, want *BillGone", err)
	}
}

// E-STAT-01, E-STAT-02, E-STAT-03, E-STAT-05, T11-27 (end to end): scope mine
// is the caller's row, all the roster, an unknown scope refused before
// sending; a holder without a slice gets NOT_FOUND; a destroyed bill is spent;
// a dropped reply is indeterminate, never spent.
func TestESTAT_StatusEndToEnd(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	pa, xa := sessionKeypair(t)
	_, xb := sessionKeypair(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: mapAmount},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xb, AmountMillis: mapAmount})
	c := e.connect(t, tok)
	cred := nipcash.BySigning(pa)
	if st, err := c.CashStatus(ctx, cred, ""); err != nil || len(st.Recipients) != 1 || st.Recipients[0].IdentityValue != xa {
		t.Fatalf("scope absent: %+v %v, want the own row", st, err)
	}
	if st, err := c.CashStatus(ctx, cred, nipcash.ScopeAll); err != nil || len(st.Recipients) != 2 {
		t.Fatalf("scope all: %+v %v, want the roster", st, err)
	}
	n := len(e.h.Envelopes())
	if _, err := c.CashStatus(ctx, cred, "everyone"); err == nil {
		t.Fatal("scope everyone accepted")
	}
	if len(e.h.Envelopes()) != n {
		t.Fatal("an unknown scope was sent")
	}
	stranger, _ := sessionKeypair(t)
	if _, err := c.CashStatus(ctx, nipcash.BySigning(stranger), nipcash.ScopeMine); codeOf(err) != nipcash.ErrCodeNotFound {
		t.Fatalf("a holder without a slice: %v, want NOT_FOUND", err)
	}

	// A dropped reply: indeterminate.
	for _, r := range e.h.Relays {
		r.Drop(func(ev *nip01.Event) bool { return ev.Kind == transport.KindPrivateResponse })
	}
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if state, _, err := c.State(short, cred); state != BillIndeterminate || err == nil {
		t.Fatalf("dropped reply: %v %v, want indeterminate with an error", state, err)
	}
	for _, r := range e.h.Relays {
		r.Drop(nil)
	}

	decoded, _ := nipcash.Decode(tok)
	if err := e.l.DeleteBill(decoded.WalletPubkey); err != nil {
		t.Fatal(err)
	}
	if state, st, err := c.State(ctx, cred); state != BillSpent || err != nil || st.Tombstone == nil {
		t.Fatalf("destroyed: %v %+v %v, want spent with the tombstone", state, st, err)
	}
}

// E-STAT-04: a cash-mode bill's status item carries neither a proof nor the
// cash secret on the wire.
func TestESTAT04_CashModeStatusWire(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, secret := e.cashBill(t)
	if _, err := c.CashStatus(ctx, nipcash.BySecret(secret), nipcash.ScopeMine); err != nil {
		t.Fatal(err)
	}
	items := e.served()
	if len(items) != 1 {
		t.Fatalf("%d items", len(items))
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(items[0].Params, &params)
	if _, ok := params["cash_secret"]; ok || items[0].HasProof() {
		t.Fatalf("cash-mode status item %s carries a secret or a proof", items[0].Params)
	}
}

// E-RED-04, T11-24, T11-25: the bill's own TLV 2 secret is refused locally as a
// cash secret; a wrong secret on a cash-mode slice, or any bearer item on a
// pubkey slice, is UNAUTHORIZED, surfaced as such.
func TestERED04_BearerSecrets(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, _ := e.cashBill(t)
	if _, err := c.CashSecretCredential(c.connSecret); !errors.Is(err, ErrSecretIsConnectionSecret) {
		t.Fatalf("TLV 2 as cash secret: %v", err)
	}
	_, net, _ := nipcash.RedeemFee(mapAmount, cashtest.LedgerRedeemFeeBase, cashtest.LedgerRedeemFeePpm)
	wrong := mustCashTarget(t).Secret()
	if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: e.l.Invoice(net), Credential: nipcash.BySecret(wrong)}); codeOf(err) != nipcash.ErrCodeUnauthorized {
		t.Fatalf("a wrong secret: %v, want UNAUTHORIZED", err)
	}
	pk, _, _ := e.pubkeyBill(t)
	if _, err := pk.CashStatus(ctx, nipcash.BySecret(wrong), nipcash.ScopeMine); codeOf(err) != nipcash.ErrCodeUnauthorized {
		t.Fatalf("a bearer item on a pubkey slice: %v, want UNAUTHORIZED", err)
	}
}

// E-RED-06, E-LK-01, T11-21: across status, transfer, redeem and lookups, no
// proof kind (23192, 23193, 23198, 23187, 23188) is ever published in the
// clear, and no bill method or lookup goes out as kind 23194.
func TestERED06_NothingInTheClear(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	cred := nipcash.BySigning(priv)
	if _, err := c.CashStatus(ctx, cred, nipcash.ScopeMine); err != nil {
		t.Fatal(err)
	}
	_, to := sessionKeypair(t)
	split := uint64(5_000_000)
	j := newTestJournal()
	res, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(to), CurrentAmount: mapAmount, SplitAmount: &split}, j, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if lo, err := c.LookupTransfer(ctx, j.all()[0], cred); err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup: %+v %v", lo, err)
	}
	rc := e.connect(t, res.RemainderWalletToken)
	_, net, _ := nipcash.RedeemFee(mapAmount-split, cashtest.LedgerRedeemFeeBase, cashtest.LedgerRedeemFeePpm)
	if _, err := rc.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: e.l.Invoice(net), Credential: cred}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range e.published() {
		switch ev.Kind {
		case transport.KindItemProof, transport.KindBillProof, 23198, 23187, 23188:
			t.Errorf("kind %d published in the clear", ev.Kind)
		case 23194:
			t.Errorf("a kind-23194 event from a bill session")
		}
	}
}

// E-ENV-08: a request the relay hands the Hub twice is served once: one
// envelope, one reply.
func TestEENV08_DuplicatedRequest(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, priv, _ := e.pubkeyBill(t)
	if _, err := c.CashStatus(ctx, nipcash.BySigning(priv), nipcash.ScopeMine); err != nil {
		t.Fatal(err)
	}
	count := func(kind int) (n int) {
		for _, ev := range e.published() {
			if ev.Kind == kind {
				n++
			}
		}
		return n
	}
	for _, r := range e.h.Relays {
		for _, ev := range r.Accepted() {
			if ev.Kind == transport.KindPrivateRequest {
				r.Publish(ev) // the same request, delivered again
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(e.h.Envelopes()); n != 1 {
		t.Fatalf("the Hub served %d envelopes, want 1", n)
	}
	if n := count(transport.KindPrivateResponse); n != 1 {
		t.Fatalf("%d replies, want 1", n)
	}
}

// E-LK-05: a lookup answered done without a result is malformed, never done.
func TestELK05_DoneWithoutResult(t *testing.T) {
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"status":"done"}`)}
	})
	relay := startFakeHub(t, hub)
	priv, target := sessionKeypair(t)
	ctx := mapCtx(t)
	s, err := OpenBatchSession(ctx, hub.hubXOnly, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	lo, err := s.lookup(ctx, mustBill(t, target), nipcash.BySigning(priv), nipcash.PendingCall{RequestID: testRequestID, Deadline: 1_900_000_000}, "")
	if err != nil || !lo.Malformed || lo.Status == nipcash.LookupDone {
		t.Fatalf("lookup = %+v, %v; want malformed", lo, err)
	}
}

// T11-23: SelectVerifiedCopy takes the copy whose provenance verifies against
// the expected minter, skipping a tampered one.
func TestT11_23_SelectVerifiedCopy(t *testing.T) {
	e := newMapEnv(t)
	_, pub := sessionKeypair(t)
	good, err := nipcash.Decode(e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: mapAmount}))
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	more := *good.AttestedAmountMillis + 1
	bad.AttestedAmountMillis = &more
	got, err := SelectVerifiedCopy([]nipcash.Token{bad, good}, nil, e.h.NodeXOnly())
	if err != nil || *got.AttestedAmountMillis != mapAmount {
		t.Fatalf("SelectVerifiedCopy = %+v, %v; want the verifying copy", got, err)
	}
	if _, err := SelectVerifiedCopy([]nipcash.Token{bad}, nil, e.h.NodeXOnly()); err == nil {
		t.Fatal("a tampered copy alone was selected")
	}
	if _, err := SelectVerifiedCopy([]nipcash.Token{good}, nil, pub); err == nil {
		t.Fatal("a copy verified against another minter")
	}
}

// T11-53: a cashhub1 string whose connection signature does not verify (TLV 3
// changed) still connects, with HubInfo.Verified false.
func TestT11_53_UnverifiedConnectionConnects(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	conn, err := nipcash.DecodeCashHubConnection(e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	conn.Label, conn.HasLabel = conn.Label+"x", true
	s, err := nipcash.EncodeCashHubConnection(conn)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ConnectCashHub(ctx, s)
	if err != nil {
		t.Fatalf("ConnectCashHub: %v", err)
	}
	defer h.Close()
	info, err := h.Info(ctx)
	if err != nil || info.Verified {
		t.Fatalf("Info = %+v, %v; want Verified false", info, err)
	}
}

// E-ENV-04 (partial), T11-20 (partial): the Hub lowers max_items 20 → 10 after
// the session read its announcement; 15 items packed against the stale copy are
// refused whole with an envelope-level QUOTA_EXCEEDED. The SDK refreshes on its
// own only for a local packing failure, so the caller refreshes; the items then
// go out as two envelopes, each answered.
func TestEENV04_LoweredMaxItemsRepacks(t *testing.T) {
	limits := transport.DefaultLimits()
	limits.MaxItems = 20
	e := newMapEnv(t, cashtest.WithLimits(limits))
	ctx := mapCtx(t)
	s, err := OpenBatchSession(ctx, e.h.NodeXOnly(), e.h.RelayURLs())
	if err != nil {
		t.Fatal(err)
	}
	if s.Limits().MaxItems != 20 {
		t.Fatalf("session max_items %d", s.Limits().MaxItems)
	}
	var items []BatchStatus
	for i := range 15 {
		priv, pub := sessionKeypair(t)
		tok, err := nipcash.Decode(e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: mapAmount}))
		if err != nil {
			t.Fatal(err)
		}
		bill, err := BillFor(tok)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, BatchStatus{ID: strconv.Itoa(i), Bill: bill, Credential: nipcash.BySigning(priv)})
	}
	e.h.Limits.MaxItems = 10
	ann := e.h.Announcement()
	ann.CreatedAt++
	if err := ann.Sign(e.h.NodePriv); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.h.Relays {
		if ok, msg := r.Publish(ann); !ok {
			t.Fatal(msg)
		}
	}
	out, err := s.StatusMany(ctx, items)
	if err != nil {
		t.Fatalf("StatusMany: %v", err)
	}
	for _, o := range out {
		if o.Succeeded() || o.Error == nil || o.Error.Code != nipcash.ErrCodeQuotaExceeded {
			t.Fatalf("item %s against the stale copy: %+v %+v, want QUOTA_EXCEEDED", o.ID, o.ItemOutcome, o.Error)
		}
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	stale := len(e.h.Envelopes())
	if out, err = s.StatusMany(ctx, items); err != nil {
		t.Fatalf("StatusMany after the refresh: %v", err)
	}
	for _, o := range out {
		if !o.Succeeded() {
			t.Fatalf("item %s: %+v %+v", o.ID, o.ItemOutcome, o.Error)
		}
	}
	if len(out) != 15 || s.Limits().MaxItems != 10 {
		t.Fatalf("%d outcomes, max_items %d", len(out), s.Limits().MaxItems)
	}
	envs := e.h.Envelopes()[stale:]
	if len(envs) != 2 {
		t.Fatalf("the Hub served %d envelopes, want 2", len(envs))
	}
	for _, env := range envs {
		if len(env.Items) > 10 {
			t.Errorf("an envelope of %d items", len(env.Items))
		}
	}
}

// T11-04: a write-ahead that finishes fewer than MinPublishMargin seconds
// before the deadline publishes nothing: ErrNotSent wrapping
// ErrDeadlineTooClose. With H 60 the window is 30 s, so the journal stalls 11 s.
func TestT11_04_DeadlineTooClose(t *testing.T) {
	if testing.Short() {
		t.Skip("stalls the journal for 11 s")
	}
	hub := newTestHub(t, answerTransfer)
	hub.limits = transport.DefaultLimits()
	hub.limits.MaxRequestAgeSeconds = 60
	w := newWATransfer(t, hub)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if w.s.MaxRequestAge() != 60 {
		t.Fatalf("H %d", w.s.MaxRequestAge())
	}
	j := &slowJournal{testJournal: newTestJournal(), delay: time.Duration(nipcash.DeadlineWindow(60)-nipcash.MinPublishMargin+1) * time.Second}
	_, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d")
	if !errors.Is(err, ErrNotSent) || !errors.Is(err, ErrDeadlineTooClose) {
		t.Fatalf("err = %v, want ErrNotSent wrapping ErrDeadlineTooClose", err)
	}
	if n := len(requestsOn(w.relay)); n != 0 {
		t.Fatalf("%d requests published", n)
	}
}

// slowJournal is a journal whose WriteAhead takes delay.
type slowJournal struct {
	*testJournal
	delay time.Duration
}

func (j *slowJournal) WriteAhead(ctx context.Context, calls []nipcash.PendingCall) error {
	time.Sleep(j.delay)
	return j.testJournal.WriteAhead(ctx, calls)
}

// T11-28: the SDK never calls get_balance on a bill connection: no source file
// of the package names the method.
func TestT11_28_NeverGetBalance(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "get_balance") || strings.Contains(string(src), "GetBalance") {
			t.Errorf("%s names get_balance", f)
		}
	}
}

// T11-38 (the single-transfer path): RekeyCashSlice writes its transfer ahead
// with the fresh cash secret before sending, and the re-keyed slice answers to
// that secret.
func TestT11_38_RekeyJournalled(t *testing.T) {
	e := newMapEnv(t)
	ctx := mapCtx(t)
	c, secret := e.cashBill(t)
	to := mustCashTarget(t)
	j := newTestJournal()
	res, err := c.RekeyCashSlice(ctx, RekeyCashSliceParams{
		CashSlice: nipcash.Source{WalletPubkey: c.WalletPubkey(), Amount: mapAmount, Credential: nipcash.BySecret(secret)},
		NewTarget: to, Journal: j, Device: "dev",
	})
	if err != nil {
		t.Fatalf("RekeyCashSlice: %v", err)
	}
	calls := j.all()
	if len(calls) != 1 || len(calls[0].Secrets) != 1 || calls[0].Secrets[0].Secret != to.Secret() || calls[0].SourceSecret != secret {
		t.Fatalf("journal %+v", calls)
	}
	if st, err := c.CashStatus(ctx, nipcash.BySecret(res.NewSecret), nipcash.ScopeMine); err != nil || len(st.Recipients) != 1 {
		t.Fatalf("status with the new secret: %+v %v", st, err)
	}
}
