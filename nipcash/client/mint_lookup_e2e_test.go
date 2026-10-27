package client

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
)

// The E-MINT cases: a mint over the Cash Hub connection against the fake
// Hub's bill ledger, looked up over the private transport (target TLV 0, both
// proofs by the connection's client key).

type mintEnv struct {
	hub   *cashtest.FakeHub
	l     *cashtest.WithdrawLedger
	h     *HubClient
	fault atomic.Pointer[cashtest.Fault]
	armed atomic.Bool
}

func newMintEnv(t *testing.T) *mintEnv {
	t.Helper()
	e := &mintEnv{}
	e.fault.Store(&cashtest.FaultNone)
	e.hub = cashtest.NewFakeHub(t, cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
		if c.Kind == nip47.KindNWCRequest && c.Item.Method == nipcash.MethodMintCash && e.armed.CompareAndSwap(true, false) {
			return *e.fault.Load()
		}
		return cashtest.FaultNone
	}))
	e.l = e.hub.ServeWithdrawals(t, nil)
	ctx, cancel := e2eContext(t)
	defer cancel()
	h, err := ConnectCashHub(ctx, e.hub.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	e.h = h
	return e
}

// faultNextMint makes the next mint_cash suffer f.
func (e *mintEnv) faultNextMint(f cashtest.Fault) { e.fault.Store(&f); e.armed.Store(true) }

func mintParams(t *testing.T) (nipcash.MintCashParams, *nipcash.CashTarget) {
	t.Helper()
	target := mustCashTarget(t)
	return nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(target, wdAmount)}}, target
}

// lostMint places a mint that ends without a result and returns its call.
func (e *mintEnv) lostMint(t *testing.T, ctx context.Context, p nipcash.MintCashParams, j Journal) nipcash.PendingCall {
	t.Helper()
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := e.h.MintCash(short, p, j, "dev")
	var ie *IndeterminateError
	if !errors.As(err, &ie) {
		t.Fatalf("MintCash: %v, want an IndeterminateError", err)
	}
	return ie.Call
}

// lookup looks pc up with e's client and fails the test on a send error.
func (e *mintEnv) lookup(t *testing.T, pc nipcash.PendingCall) LookupOutcome {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	lo, err := e.h.LookupMint(ctx, pc)
	if err != nil {
		t.Fatalf("LookupMint: %v", err)
	}
	return lo
}

// pastDeadline moves the ledger's lookup clock past pc's deadline plus extra.
func (e *mintEnv) pastDeadline(pc nipcash.PendingCall, extra time.Duration) {
	e.l.Advance(time.Unix(pc.Deadline, 0).Sub(e.l.Now()) + extra + time.Second)
}

func (e *mintEnv) recover(t *testing.T, pc nipcash.PendingCall) Action {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	act, err := Recover(ctx, pc, e.h.LookupMint, "dev", time.Now())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return act
}

// E-MINT-02 (S-CASH-02, S-CASH-18): the reply is dropped after the commit:
// IndeterminateError, then the lookup is done with the bill, byte-identical on
// every lookup, signed by the Hub's identity; Recover closes it.
func TestEMINT02_ReplyDroppedAfterCommit(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, target := mintParams(t)
	e.faultNextMint(cashtest.FaultCommitThenDropReply)
	pc := e.lostMint(t, ctx, p, newTestJournal())

	first, second := e.lookup(t, pc), e.lookup(t, pc)
	if first.Status != nipcash.LookupDone || string(first.Result) != string(second.Result) {
		t.Fatalf("lookups %+v / %+v, want done twice, byte-identical", first, second)
	}
	res, err := p.ParseLookupResult(first.Result)
	if err != nil || res.CashToken == "" || res.Recipients[0].IdentityValue != target.Commitment() {
		t.Fatalf("result %+v, %v", res, err)
	}
	tok, err := nipcash.Decode(res.CashToken)
	if err != nil {
		t.Fatal(err)
	}
	if minter, ok := nipcash.VerifyProvenance(tok); !ok || !nipcash.HubIdentityEqual(e.hub.NodeXOnly(), minter) {
		t.Fatalf("token provenance %q, %v", minter, ok)
	}
	if act := e.recover(t, pc); act.Kind != ActionClose || string(act.Result) != string(first.Result) {
		t.Fatalf("Recover = %+v, want Close with the result", act)
	}
}

// E-MINT-03 (S-CASH-08): a lookup before the deadline while the mint is still
// held answers pending with retry_after = deadline + 1, changes nothing, and
// once the original commits the lookup is done.
func TestEMINT03_LookupBeforeTheDeadline(t *testing.T) {
	e := newMintEnv(t)
	clock := e.hub.Clock.(*cashtest.ManualClock)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, _ := mintParams(t)
	e.faultNextMint(cashtest.FaultStallUntil(clock.Now().Add(10 * time.Second)))
	pc := e.lostMint(t, ctx, p, newTestJournal())

	lo := e.lookup(t, pc)
	if lo.Status != nipcash.LookupPending || lo.RetryAfter != pc.Deadline+1 {
		t.Fatalf("lookup %+v, want pending until %d", lo, pc.Deadline+1)
	}
	if act := e.recover(t, pc); act.Kind != ActionWait || act.Until != pc.Deadline+1 {
		t.Fatalf("Recover = %+v, want Wait until the deadline + 1", act)
	}
	clock.Advance(10 * time.Second)
	for range 200 {
		if lo = e.lookup(t, pc); lo.Status == nipcash.LookupDone {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lookup %+v after the mint committed, want done", lo)
}

// E-MINT-04 (S-CASH-20, S-CASH-22): the mint never arrives: unknown, which the
// owner re-places only with confirmation, under the derived id, with the same
// commitment; the re-placed mint is done.
func TestEMINT04_MintNeverArrives(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, target := mintParams(t)
	j := newTestJournal()
	lost := WithPublishFilter(ctx, func(ev *nip01.Event) bool { return ev.Kind != nip47.KindNWCRequest })
	pc := e.lostMint(t, lost, p, j)
	if pc.LastCode != "" {
		t.Fatalf("LastCode %q after a lost request", pc.LastCode)
	}
	e.pastDeadline(pc, 0)
	if lo := e.lookup(t, pc); lo.Status != nipcash.LookupUnknown {
		t.Fatalf("lookup %+v, want unknown", lo)
	}
	if act := e.recover(t, pc); act.Kind != ActionConfirmReplace {
		t.Fatalf("Recover = %+v, want ConfirmReplace", act)
	}
	send := func(ctx context.Context, next nipcash.PendingCall) error {
		q := p
		q.RequestID = next.RequestID
		_, err := e.h.MintCash(ctx, q, j, "dev")
		return err
	}
	if _, err := Replace(ctx, pc, j, ReplaceOptions{}, send); !errors.Is(err, ErrReplaceNeedsConfirmation) {
		t.Fatalf("Replace without confirmation: %v", err)
	}
	if _, err := Replace(ctx, pc, j, ReplaceOptions{Confirmed: true}, send); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	derived, _ := nipcash.DerivedRequestID(pc.RequestID)
	next, ok := j.call(derived)
	if !ok || next.DerivedFrom != pc.RequestID || next.Attempt != 1 || next.Secrets[0].Secret != target.Secret() {
		t.Fatalf("derived call %+v", next)
	}
	lo := e.lookup(t, next)
	res, err := p.ParseLookupResult(lo.Result)
	if lo.Status != nipcash.LookupDone || err != nil || res.Recipients[0].IdentityValue != target.Commitment() {
		t.Fatalf("derived lookup %+v, %+v, %v", lo, res, err)
	}
}

// E-MINT-05 (S-CASH-21): a lookup past deadline + H with no record is expired:
// shown, never re-placed.
func TestEMINT05_LookupAfterTheHorizon(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, _ := mintParams(t)
	lost := WithPublishFilter(ctx, func(ev *nip01.Event) bool { return ev.Kind != nip47.KindNWCRequest })
	pc := e.lostMint(t, lost, p, newTestJournal())
	e.pastDeadline(pc, time.Duration(pc.MaxRequestAge)*time.Second)
	if lo := e.lookup(t, pc); lo.Status != nipcash.LookupExpired {
		t.Fatalf("lookup %+v, want expired", lo)
	}
	if act := e.recover(t, pc); act.Kind != ActionShow || act.Reason != "lookup_expired" {
		t.Fatalf("Recover = %+v, want Show{lookup_expired}", act)
	}
}

// E-MINT-07 (S-CASH-24): a lookup whose bill proof does not verify (signed by
// another key than the connection's) is omitted, and the call stays pending:
// Recover waits, never reading it as unknown, though a verifying lookup at the
// same moment is unknown.
func TestEMINT07_CorruptedBillProof(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, _ := mintParams(t)
	lost := WithPublishFilter(ctx, func(ev *nip01.Event) bool { return ev.Kind != nip47.KindNWCRequest })
	pc := e.lostMint(t, lost, p, newTestJournal())
	e.pastDeadline(pc, 0)

	conn, err := nipcash.DecodeCashHubConnection(e.hub.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	conn.Secret, _ = sessionKeypair(t)
	bad := &HubClient{conn: conn}
	lo, err := bad.LookupMint(ctx, pc)
	if err != nil || !lo.NotServed || lo.Status != "" {
		t.Fatalf("corrupted lookup %+v, %v; want omitted", lo, err)
	}
	act, err := Recover(ctx, pc, bad.LookupMint, "dev", time.Now())
	if err != nil || act.Kind != ActionWait {
		t.Fatalf("Recover = %+v, %v; want Wait", act, err)
	}
	if lo := e.lookup(t, pc); lo.Status != nipcash.LookupUnknown {
		t.Fatalf("verifying lookup %+v, want unknown", lo)
	}
}

// E-MINT-09 (S-CASH-50; §10.3): the Hub's signer fails: INTERNAL, pending with
// LastCode INTERNAL; the lookup is pending, then unknown, and Recover closes
// the call refused, with no confirmation asked and nothing re-placed.
func TestEMINT09_BrokenSigner(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, _ := mintParams(t)
	e.faultNextMint(cashtest.FaultBreakSigner)
	_, err := e.h.MintCash(ctx, p, newTestJournal(), "dev")
	var ie *IndeterminateError
	if !errors.As(err, &ie) || ie.Code != nipcash.ErrCodeInternal || ie.Call.LastCode != nipcash.ErrCodeInternal {
		t.Fatalf("MintCash: %v, want an IndeterminateError with LastCode INTERNAL", err)
	}
	pc := ie.Call
	if lo := e.lookup(t, pc); lo.Status != nipcash.LookupPending {
		t.Fatalf("lookup %+v, want pending", lo)
	}
	e.pastDeadline(pc, 0)
	if lo := e.lookup(t, pc); lo.Status != nipcash.LookupUnknown {
		t.Fatalf("lookup %+v, want unknown", lo)
	}
	if act := e.recover(t, pc); act.Kind != ActionCloseRefused || act.Reason != nipcash.ErrCodeInternal {
		t.Fatalf("Recover = %+v, want CloseRefused{INTERNAL}", act)
	}
}

// E-MINT-11 (S-CASH-29): the minted bill is redeemed; its mint's lookup is done
// with the tombstone in place of cash_token, wallet_pubkey kept, and no
// pairing_uri.
func TestEMINT11_DestroyedBillInsideDone(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, target := mintParams(t)
	j := newTestJournal()
	res, err := e.h.MintCash(ctx, p, j, "dev")
	if err != nil {
		t.Fatalf("MintCash: %v", err)
	}
	c, err := Connect(ctx, res.CashToken)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: e.l.Invoice(0), Credential: nipcash.BySecret(target.Secret())},
		RedeemOptions{AutoAmount: true}); err != nil {
		t.Fatalf("CashRedeem: %v", err)
	}
	pc := j.all()[0]
	lo := e.lookup(t, pc)
	got, err := p.ParseLookupResult(lo.Result)
	if lo.Status != nipcash.LookupDone || err != nil || got.TokenTombstone == nil ||
		got.TokenTombstone.Reason != nipcash.ReasonRedeemed || got.CashToken != "" || got.WalletPubkey != res.WalletPubkey {
		t.Fatalf("lookup %+v, result %+v, %v", lo, got, err)
	}
	if strings.Contains(string(lo.Result), "pairing_uri") {
		t.Fatal("the rebuilt result carries a pairing_uri")
	}
}

// E-MINT-13 (S-CASH-118): a cash recipient's secret, the id and the exact
// deadline are written ahead before the mint is published; after a restart
// (a new connection, the journal alone) the lookup is done, and the token with
// the journalled secret opens the bill.
func TestEMINT13_RestartAfterPublish(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, target := mintParams(t)
	j := newTestJournal()
	var atPublish []nipcash.PendingCall
	published := WithAfterPublish(ctx, func() { atPublish = j.all() })
	e.faultNextMint(cashtest.FaultCommitThenDropReply)
	pc := e.lostMint(t, published, p, j)
	if len(atPublish) != 1 || atPublish[0].RequestID != pc.RequestID || atPublish[0].Deadline != pc.Deadline ||
		len(atPublish[0].Secrets) != 1 || atPublish[0].Secrets[0].Secret != target.Secret() {
		t.Fatalf("written ahead at publish: %+v", atPublish)
	}

	restarted, err := ConnectCashHub(ctx, e.hub.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	saved := j.all()[0]
	lo, err := restarted.LookupMint(ctx, saved)
	if err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup after restart %+v, %v", lo, err)
	}
	res, err := p.ParseLookupResult(lo.Result)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Connect(ctx, res.CashToken)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.CashStatus(ctx, nipcash.BySecret(saved.Secrets[0].Secret), nipcash.ScopeMine)
	if err != nil || len(st.Recipients) != 1 || st.Recipients[0].AmountMillis != wdAmount {
		t.Fatalf("status with the journalled secret %+v, %v", st, err)
	}
}
