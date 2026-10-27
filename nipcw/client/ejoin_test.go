package client

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/nipcw"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// The E-JOIN cases: Join and LookupJoin end to end against the fake ledger's
// circle, which runs NIP-CW's processing algorithm for real (VerifyJoinProof,
// membership, limits, holdings, join records, rotation).

// ledgerCircle is a fake Hub whose ledger serves its circle. answer, when set,
// replaces the ledger's answer to a join (it sees the ledger's own).
type ledgerCircle struct {
	*cashtest.FakeHub
	l *cashtest.WithdrawLedger
	// serve is the ledger's own decision.
	serve func(cashtest.ItemCtx) *transport.Result

	mu     sync.Mutex
	answer func(c cashtest.ItemCtx, served *transport.Result) *transport.Result
	drop   atomic.Bool
}

func newLedgerCircle(t *testing.T) *ledgerCircle {
	t.Helper()
	lc := &ledgerCircle{}
	lc.FakeHub = cashtest.NewFakeHub(t, cashtest.WithCircleHub(), cashtest.WithClock(cashtest.RealClock{}),
		cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
			if lc.drop.Load() && c.Item.Method == nipcw.MethodCreateCircleWallet {
				return cashtest.FaultCommitThenDropReply
			}
			return cashtest.FaultNone
		}))
	lc.l = lc.ServeWithdrawals(t, nil)
	lc.serve = lc.Decide
	lc.Decide = func(c cashtest.ItemCtx) *transport.Result {
		r := lc.serve(c)
		lc.mu.Lock()
		f := lc.answer
		lc.mu.Unlock()
		if f != nil && c.Item.Method == nipcw.MethodCreateCircleWallet {
			return f(c, r)
		}
		return r
	}
	return lc
}

func (lc *ledgerCircle) setAnswer(f func(cashtest.ItemCtx, *transport.Result) *transport.Result) {
	lc.mu.Lock()
	lc.answer = f
	lc.mu.Unlock()
}

// member admits a fresh key.
func (lc *ledgerCircle) member(t *testing.T) string {
	t.Helper()
	priv, pub := keypair(t)
	lc.AddMember(t, pub, true)
	return priv
}

func connectLedger(t *testing.T, ctx context.Context, lc *ledgerCircle) *Client {
	t.Helper()
	cl, err := Connect(ctx, lc.CircleHubConnection(), Options{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(cl.Close)
	return cl
}

// walletInfo is get_info over the member's own wallet connection.
func walletInfo(ctx context.Context, w nipcw.WalletConnection) (*nip47.GetInfoResult, error) {
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{WalletPubkey: w.WalletPubkey, RelayURLs: w.Relays, Secret: w.Secret},
		nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, err
	}
	defer nwc.Close()
	return nwc.GetInfo(ctx)
}

// E-JOIN-01, E-JOIN-02 (S-CW-125): a private join is done, its proof checked by
// the Hub's VerifyJoinProof and its details naming the journalled key; the
// reply lands on the relay the join was sent to; a hand-built join on the
// standard transport is NOT_IMPLEMENTED.
func TestEJoin01_02_PrivateJoin(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	j := &journal{}
	res, err := cl.Join(ctx, params(t, priv), JoinOptions{}, j)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	pj := j.all()[0]
	if res.ConnectionPubkey != pj.ConnectionPubkey || len(res.MissingTerms) > 0 || len(res.LeakedFields) > 0 {
		t.Fatalf("details %+v for %s", res.CreateCircleWalletResponse, pj.ConnectionPubkey)
	}
	if _, err := walletInfo(ctx, res.Wallet()); err != nil {
		t.Fatalf("the wallet over wallet_pubkey, relays and the journalled secret: %v", err)
	}
	// The relay that carried the request also carried its reply.
	for _, r := range lc.Relays {
		var req, rep bool
		for _, ev := range r.Accepted() {
			req = req || ev.Kind == transport.KindPrivateRequest
			rep = rep || ev.Kind == transport.KindPrivateResponse
		}
		if req && !rep {
			t.Errorf("relay %s carried the join but not its reply", r.URL())
		}
	}
	resp, err := cl.nwc.Call(ctx, nipcw.MethodCreateCircleWallet, json.RawMessage(`{}`))
	if err != nil || resp.Error == nil || resp.Error.Code != nipcw.ErrNotImplemented {
		t.Fatalf("a join on the standard transport: %+v %v, want NOT_IMPLEMENTED", resp, err)
	}
}

// E-JOIN-03 (S-CW-16): the reply is lost; LookupJoin is done and the wallet is
// held with the journalled secret.
func TestEJoin03_ReplyLost(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	lc.drop.Store(true)
	j := &journal{}
	short, stop := context.WithTimeout(ctx, 3*time.Second)
	_, err := cl.Join(short, params(t, priv), JoinOptions{}, j)
	stop()
	var ie *JoinIndeterminateError
	if !errors.As(err, &ie) {
		t.Fatalf("a lost reply: %v, want JoinIndeterminateError", err)
	}
	lc.drop.Store(false)
	act, err := cl.LookupJoin(ctx, ie.Pending, nipcw.BySigning(priv))
	if err != nil || act.Kind != JoinClose {
		t.Fatalf("lookup: %+v %v", act, err)
	}
	w := nipcw.WalletConnection{WalletPubkey: act.Response.WalletPubkey, Relays: act.Response.Relays, Secret: ie.Pending.ConnectionSecret}
	if _, err := walletInfo(ctx, w); err != nil {
		t.Fatalf("the looked-up wallet with the journalled secret: %v", err)
	}
}

// E-JOIN-04, E-JOIN-05, E-JOIN-06, E-JOIN-14 (S-CASH-23, S-CW-19, 22): with no
// record a lookup before the deadline waits until deadline + 1, after it may
// rejoin (and nothing is sent by itself), long after it shows the join; a
// lookup by another signer of a made join is answered by its deadline only.
func TestEJoin04_06_14_LookupWindows(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	k, _ := nipcw.NewConnectionKey()
	cred := nipcw.BySigning(priv)
	pj := PendingJoin{HubPubkey: lc.CirclePubkey(), Pubkey: "", ConnectionPubkey: k.Pubkey(), ConnectionSecret: k.Secret()}
	now := time.Now().Unix()
	pj.Deadline = now + 120
	if act, err := cl.LookupJoin(ctx, pj, cred); err != nil || act.Kind != JoinWait || act.Until != pj.Deadline+1 {
		t.Fatalf("before the deadline: %+v %v, want JoinWait until %d", act, err, pj.Deadline+1)
	}
	pj.Deadline = now - 10
	before := len(lc.Envelopes())
	if act, err := cl.LookupJoin(ctx, pj, cred); err != nil || act.Kind != JoinMayRejoin {
		t.Fatalf("past the deadline: %+v %v, want JoinMayRejoin", act, err)
	}
	if n := len(lc.Envelopes()) - before; n != 1 {
		t.Fatalf("%d envelopes for one lookup: nothing is sent automatically", n)
	}
	pj.Deadline = now - 400
	if act, err := cl.LookupJoin(ctx, pj, cred); err != nil || act.Kind != JoinShow || act.Reason != "join_expired" {
		t.Fatalf("long past the deadline: %+v %v, want JoinShow join_expired", act, err)
	}

	j := &journal{}
	if _, err := cl.Join(ctx, params(t, priv), JoinOptions{}, j); err != nil {
		t.Fatal(err)
	}
	other, _ := keypair(t)
	if act, err := cl.LookupJoin(ctx, j.all()[0], nipcw.BySigning(other)); err != nil || act.Kind == JoinClose {
		t.Fatalf("another signer's lookup: %+v %v, want an answer by the deadline", act, err)
	}
}

// E-JOIN-07 (S-CW-13): the join is front-run by a copy of itself; the client's
// own is REQUEST_REUSED, and the lookup is done.
func TestEJoin07_FrontRun(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	var once atomic.Bool
	lc.setAnswer(func(c cashtest.ItemCtx, served *transport.Result) *transport.Result {
		if once.CompareAndSwap(false, true) {
			// The copy that got there first made the wallet; the client's own
			// arrives second.
			return lc.serve(c)
		}
		return served
	})
	j := &journal{}
	_, err := cl.Join(ctx, params(t, priv), JoinOptions{}, j)
	var ie *JoinIndeterminateError
	if !errors.As(err, &ie) || ie.Code != nipcw.ErrRequestReused {
		t.Fatalf("a front-run join: %v, want REQUEST_REUSED, indeterminate", err)
	}
	if act, err := cl.LookupJoin(ctx, ie.Pending, nipcw.BySigning(priv)); err != nil || act.Kind != JoinClose {
		t.Fatalf("lookup after REQUEST_REUSED: %+v %v, want done", act, err)
	}
}

// E-JOIN-08 (S-CW-34, 36): LIMIT_EXCEEDED and INSUFFICIENT_CAPACITY reach the
// caller as final refusals, and the next Join signs a new proof. NOT_READY
// cannot happen on the fake's allowlist circle.
func TestEJoin08_Refusals(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	// get_info stops reporting the per-wallet ceiling, so only the Hub refuses.
	lc.SetCircleWallet(cashtest.DefaultCircleWallet(lc.NodeXOnly()))
	p := params(t, priv)
	p.MaxAmountMillis = cashtest.CirclePerWalletMax + 1
	var we *relayclient.WalletError
	if _, err := cl.Join(ctx, p, JoinOptions{}, &journal{}); !errors.As(err, &we) || we.Code != nipcw.ErrLimitExceeded || errors.Is(err, ErrJoinNotSent) {
		t.Fatalf("over the Hub's ceiling: %v, want a final LIMIT_EXCEEDED", err)
	}
	full := lc.member(t)
	res, err := cl.Join(ctx, params(t, full), JoinOptions{}, &journal{})
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.l.FundCircleWallet(res.WalletPubkey, cashtest.CircleHoldingsCeiling); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Join(ctx, params(t, priv), JoinOptions{}, &journal{}); !errors.As(err, &we) || we.Code != nipcw.ErrInsufficientCapacity {
		t.Fatalf("a full circle: %v, want INSUFFICIENT_CAPACITY", err)
	}
	seen := map[string]bool{}
	for _, c := range lc.Committed() {
		var req nipcw.CreateCircleWalletRequest
		_ = json.Unmarshal(c.Item.Params, &req)
		if seen[req.IdentityEvent] {
			t.Fatal("a refused proof was sent again")
		}
		seen[req.IdentityEvent] = true
	}
}

// E-JOIN-09, E-JOIN-10 (S-CW-38): details without connection_pubkey, and an
// old genuine reply replayed for a new join, are rejected: the join stays
// pending, to be looked up.
func TestEJoin09_10_BadDetails(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	first, err := cl.Join(ctx, params(t, priv), JoinOptions{}, &journal{})
	if err != nil {
		t.Fatal(err)
	}
	var memberPub string
	lc.setAnswer(func(c cashtest.ItemCtx, _ *transport.Result) *transport.Result {
		var req nipcw.CreateCircleWalletRequest
		_ = json.Unmarshal(c.Item.Params, &req)
		memberPub = req.Pubkey
		s, err := nipcw.EncryptDetails(lc.CirclePriv(), req.Pubkey, nipcw.CircleWalletDetails{WalletPubkey: first.WalletPubkey,
			Relays: first.Relays, MaxAmount: 100000, MaxReceive: 200000, DustThresholdMillis: 1000, BudgetRenewal: nipcw.RenewalMonthly})
		if err != nil {
			t.Error(err)
		}
		return &transport.Result{Result: json.RawMessage(s)}
	})
	other := lc.member(t)
	var ie *JoinIndeterminateError
	if _, err := cl.Join(ctx, params(t, other), JoinOptions{}, &journal{}); !errors.As(err, &ie) {
		t.Fatalf("details without connection_pubkey: %v, want rejected (indeterminate)", err)
	}
	if memberPub == "" {
		t.Fatal("the join never reached the Hub")
	}
	// An old genuine reply: a member's first join's details, replayed for its
	// next join.
	var mu sync.Mutex
	var old json.RawMessage
	lc.setAnswer(func(_ cashtest.ItemCtx, served *transport.Result) *transport.Result {
		mu.Lock()
		defer mu.Unlock()
		if old == nil {
			old = served.Result
			return served
		}
		return &transport.Result{Result: old}
	})
	again := lc.member(t)
	if _, err := cl.Join(ctx, params(t, again), JoinOptions{}, &journal{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Join(ctx, params(t, again), JoinOptions{}, &journal{}); !errors.As(err, &ie) {
		t.Fatalf("an old genuine reply replayed: %v, want rejected (indeterminate)", err)
	}
}

// E-JOIN-12 (S-CW-105): a Hub without rotation_delay_secs and no
// WarnNoRotation: refused before anything is sent.
func TestEJoin12_NoRotation(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	block := cashtest.DefaultCircleWallet(lc.NodeXOnly())
	delete(block, "rotation_delay_secs")
	lc.SetCircleWallet(block)
	before := len(lc.Envelopes())
	j := &journal{}
	if _, err := cl.Join(ctx, params(t, priv), JoinOptions{}, j); !errors.Is(err, ErrRotationWarningRequired) {
		t.Fatalf("no rotation, no warning: %v", err)
	}
	if len(lc.Envelopes()) != before || len(j.all()) != 0 {
		t.Fatal("something was written or sent")
	}
}

// E-JOIN-13 (S-CW-133): a rotation accepted at R: the lookup naming the new key
// waits until completes_at, then is done with the new key.
func TestEJoin13_Rotation(t *testing.T) {
	ctx, cancel := testContext(t)
	defer cancel()
	lc := newLedgerCircle(t)
	priv := lc.member(t)
	cl := connectLedger(t, ctx, lc)
	j := &journal{}
	res, err := cl.Join(ctx, params(t, priv), JoinOptions{}, j)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := nipcw.NewConnectionKey()
	req, err := nipcw.NewMemberRequest(priv, lc.CirclePubkey(), nipcw.ActionRotate, res.WalletPubkey, k.Pubkey())
	if err != nil {
		t.Fatal(err)
	}
	r := time.Now().Unix()
	if err := lc.l.MemberRequest(req); err != nil {
		t.Fatal(err)
	}
	rotated := j.all()[0]
	rotated.ConnectionPubkey, rotated.ConnectionSecret = k.Pubkey(), k.Secret()
	act, err := cl.LookupJoin(ctx, rotated, nipcw.BySigning(priv))
	if err != nil || act.Kind != JoinWait || act.Until < r+cashtest.CircleRotationDelaySecs {
		t.Fatalf("pending: %+v %v, want JoinWait until completes_at", act, err)
	}
	lc.l.Advance(cashtest.CircleRotationDelaySecs * time.Second)
	act, err = cl.LookupJoin(ctx, rotated, nipcw.BySigning(priv))
	if err != nil || act.Kind != JoinClose || act.Response.ConnectionPubkey != k.Pubkey() || act.Response.WalletPubkey != res.WalletPubkey {
		t.Fatalf("completed: %+v %v, want done with the new key", act, err)
	}
}
