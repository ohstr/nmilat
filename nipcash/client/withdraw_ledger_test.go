package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
)

// The E-WD end-to-end cases that need a chain or a clock: the SDK's withdraw
// flows against the fake Hub's bill ledger.

type ledEnv struct {
	h     *cashtest.FakeHub
	l     *cashtest.WithdrawLedger
	fault atomic.Pointer[cashtest.Fault]
	once  atomic.Bool
}

func newLedEnv(t *testing.T) *ledEnv {
	t.Helper()
	e := &ledEnv{}
	e.fault.Store(&cashtest.FaultNone)
	// One fault, on the next cash_withdraw call (never a cancel request).
	e.h = cashtest.NewFakeHub(t, cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
		if serving, _ := nipcash.ServingMethod(c.Item.Method, c.Item.Params); serving == nipcash.MethodCashWithdraw && e.once.CompareAndSwap(true, false) {
			return *e.fault.Load()
		}
		return cashtest.FaultNone
	}))
	e.l = e.h.ServeWithdrawals(t, nil)
	return e
}

// faultNextWithdraw makes the next cash_withdraw call suffer f.
func (e *ledEnv) faultNextWithdraw(f cashtest.Fault) {
	e.fault.Store(&f)
	e.once.Store(true)
}

func (e *ledEnv) connect(t *testing.T, token string) *Client {
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

func (e *ledEnv) pubkey(t *testing.T) (*Client, nipcash.Credential) {
	t.Helper()
	priv, pub := sessionKeypair(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: wdAmount})
	return e.connect(t, tok), nipcash.BySigning(priv)
}

func (e *ledEnv) cash(t *testing.T) (*Client, string) {
	t.Helper()
	target := mustCashTarget(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "cash", IdentityValue: target.Commitment(), AmountMillis: wdAmount})
	return e.connect(t, tok), target.Secret()
}

func ledAddr() string {
	return cashtest.ExternalAddress(nipcash.ScriptType{Version: 0, ProgramLen: 20})
}

// shortCtx is for a call whose reply never comes.
func shortCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func (e *ledEnv) quote(t *testing.T, c *Client, cred nipcash.Credential, status *nipcash.CashStatusResult) *nipcash.WithdrawQuote {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	q, err := c.QuoteWithdraw(ctx, nipcash.CashWithdrawQuoteParams{Address: ledAddr(), Credential: cred, Status: status})
	if err != nil {
		t.Fatalf("QuoteWithdraw: %v", err)
	}
	return q
}

func (e *ledEnv) lookup(t *testing.T, c *Client, pc nipcash.PendingCall, cred nipcash.Credential) (LookupOutcome, *nipcash.Payout) {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	lo, p, err := c.LookupWithdraw(ctx, pc, cred)
	if err != nil {
		t.Fatalf("LookupWithdraw: %v", err)
	}
	return lo, p
}

// indeterminate places a withdrawal that does not end in a verified reply.
func indeterminate(t *testing.T, c *Client, p nipcash.CashWithdrawParams, j Journal) *IndeterminateError {
	t.Helper()
	ctx, cancel := shortCtx()
	defer cancel()
	_, err := c.Withdraw(ctx, p, j, "dev")
	var ie *IndeterminateError
	if !errors.As(err, &ie) {
		t.Fatalf("Withdraw: %v, want an IndeterminateError", err)
	}
	return ie
}

// E-WD-02: the reply is lost after the commit: indeterminate; the lookup is
// done with a receipt that verifies, the payout followed to final, and the
// call never sent again.
func TestEWD02_ReplyLostAfterCommit(t *testing.T) {
	e := newLedEnv(t)
	c, cred := e.pubkey(t)
	q := e.quote(t, c, cred, nil)
	e.faultNextWithdraw(cashtest.FaultCommitThenDropReply)
	j := newTestJournal()
	pc := indeterminate(t, c, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, j).Call
	if lo, p := e.lookup(t, c, pc, cred); lo.Status != nipcash.LookupDone || p == nil || p.State != nipcash.PayoutQueued {
		t.Fatalf("lookup after the lost reply: %+v %+v", lo, p)
	}
	e.l.Chain().Mine(8)
	if _, p := e.lookup(t, c, pc, cred); !PayoutFinished(p) || p.State != nipcash.PayoutFinal || p.TxErr != nil {
		t.Fatalf("payout %+v, want final", p)
	}
	if n := j.writes[pc.RequestID]; n != 1 || len(j.all()) != 1 {
		t.Errorf("the call was written %d times, %d calls", n, len(j.all()))
	}
}

// E-WD-03: the call is dropped before the commit: unknown once its deadline
// passed; Recover re-places it automatically under the derived id, with the
// same notify, quote and re-mint secret; the receipt hashes the derived id.
func TestEWD03_DroppedBeforeCommitReplaced(t *testing.T) {
	e := newLedEnv(t)
	c, secret := e.cash(t)
	cred := nipcash.BySecret(secret)
	q := e.quote(t, c, cred, nil)
	e.faultNextWithdraw(cashtest.FaultDropBeforeCommit)
	j := newTestJournal()
	pc := indeterminate(t, c, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, j).Call
	if lo, _ := e.lookup(t, c, pc, cred); lo.Status != nipcash.LookupPending {
		t.Fatalf("before the deadline: %+v, want pending", lo)
	}
	e.l.Advance(2 * time.Minute)
	lookup := func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		lo, _, err := c.LookupWithdraw(ctx, pc, cred)
		return lo, err
	}
	ctx, cancel := e2eContext(t)
	defer cancel()
	act, err := Recover(ctx, pc, lookup, "dev", time.Now())
	if err != nil || act.Kind != ActionReplace {
		t.Fatalf("Recover after unknown: %+v %v, want ActionReplace", act, err)
	}
	send := func(ctx context.Context, next nipcash.PendingCall) error {
		nq, err := nipcash.ParseWithdrawQuote(next.Quote)
		if err != nil {
			return err
		}
		remint, err := nipcash.CashTargetFromSecret(next.Secrets[0].Secret)
		if err != nil {
			return err
		}
		_, err = c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: nq, Credential: cred, RequestID: next.RequestID, Notify: next.Notify, Remint: remint}, j, "dev")
		return err
	}
	if act, err := Replace(ctx, pc, j, ReplaceOptions{ChainTip: e.l.Chain().Tip()}, send); err != nil || act.Kind != ActionWait {
		t.Fatalf("Replace: %+v %v", act, err)
	}
	derived, _ := nipcash.DerivedRequestID(pc.RequestID)
	next, ok := j.call(derived)
	if !ok || next.DerivedFrom != pc.RequestID || next.Notify != pc.Notify || next.Quote != pc.Quote ||
		len(next.Secrets) != 1 || next.Secrets[0].Secret != pc.Secrets[0].Secret {
		t.Fatalf("the re-placed call %+v", next)
	}
	p, ok := e.l.Payout(derived)
	if !ok || p.State != nipcash.PayoutQueued {
		t.Fatalf("no payout under the derived id")
	}
	if _, ok := e.l.Payout(pc.RequestID); ok {
		t.Fatal("the dropped call committed")
	}
	if err := nipcash.VerifyWithdrawReceipt(p.Receipt, nipcash.ReceiptExpectation{HubXOnly: e.h.NodeXOnly(), Target: pc.Target, QuoteID: q.ID,
		RequestID: derived, Address: q.Address, PayoutMillis: q.PayoutMillis, SentBy: q.SentBy}); err != nil {
		t.Errorf("the receipt does not hash the derived id: %v", err)
	}
}

// E-WD-04: the tip passes holds_until before the call: RESTRICTED
// quote_expired, indeterminate with its detail; the lookup is unknown and
// Recover closes the call refused; the slice is still claimable, and a new
// quote and a new call commit.
func TestEWD04_QuoteExpired(t *testing.T) {
	e := newLedEnv(t)
	c, cred := e.pubkey(t)
	q := e.quote(t, c, cred, nil)
	e.l.Chain().Mine(int(q.HoldsUntil-e.l.Chain().Tip()) + 1)
	ie := indeterminate(t, c, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, newTestJournal())
	if ie.Code != nipcash.ErrCodeRestricted || ie.Detail != string(nipcash.DetailQuoteExpired) || ie.Call.LastDetail != nipcash.DetailQuoteExpired {
		t.Fatalf("expired quote: %+v", ie)
	}
	e.l.Advance(2 * time.Minute)
	ctx, cancel := e2eContext(t)
	defer cancel()
	act, err := Recover(ctx, ie.Call, func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		lo, _, err := c.LookupWithdraw(ctx, pc, cred)
		return lo, err
	}, "dev", time.Now())
	if err != nil || act.Kind != ActionCloseRefused || act.Reason != "RESTRICTED/quote_expired" {
		t.Fatalf("Recover: %+v %v", act, err)
	}
	st, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil || st.Recipients[0].Claimed {
		t.Fatalf("the slice after the refusal: %+v %v", st, err)
	}
	if p, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred}, newTestJournal(), "dev"); err != nil || p.State != nipcash.PayoutQueued {
		t.Fatalf("a new quote and call: %+v %v", p, err)
	}
}

// E-WD-05: a cash-mode slice, FaultHoldSign: quoted on the bill proof alone,
// withdrawn with remint_commitment; a day after sent_by it is cancelled, the
// whole amount re-minted in the clear, bound to the re-mint commitment, never
// expiring; the old secret is refused on it, the source's tombstone says
// transferred, and a notice comes at least 600 s after.
func TestEWD05_CashModeHeldSignCancelled(t *testing.T) {
	e := newLedEnv(t)
	c, secret := e.cash(t)
	cred := nipcash.BySecret(secret)
	e.l.InjectFault(cashtest.FaultHoldSign)
	q := e.quote(t, c, cred, nil)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.all()[0]
	notices, err := c.WatchPayout(ctx, pc.Notify, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	e.l.Advance(26 * time.Hour)
	_, p := e.lookup(t, c, pc, cred)
	if p == nil || p.State != nipcash.PayoutCancelled || p.NewWalletToken.Token == "" {
		t.Fatalf("a day after sent_by: %+v", p)
	}
	select {
	case <-notices:
		t.Fatal("a notice before 600 s")
	case <-time.After(300 * time.Millisecond):
	}
	e.l.Advance(20 * time.Minute)
	select {
	case <-notices:
	case <-time.After(5 * time.Second):
		t.Fatal("no notice after the cancellation")
	}
	nc := e.connect(t, p.NewWalletToken.Token)
	remint := pc.Secrets[0].Secret
	st, err := nc.CashStatus(ctx, nipcash.BySecret(remint), nipcash.ScopeMine)
	commit, _ := nipcash.CashCommitment(remint)
	if err != nil || !nipcash.CommitmentsEqual(st.Recipients[0].IdentityValue, commit) || st.Recipients[0].AmountMillis != wdAmount || !st.Recipients[0].ExpiresAt.Never() {
		t.Fatalf("the re-minted bill: %+v %v", st, err)
	}
	nq := e.quote(t, nc, nipcash.BySecret(remint), nil)
	if _, err := nc.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: nq, Credential: cred}, newTestJournal(), "dev"); err == nil {
		t.Fatal("the old secret withdrew the re-minted bill")
	} else if ie := (*IndeterminateError)(nil); !errors.As(err, &ie) || ie.Code != nipcash.ErrCodeUnauthorized {
		t.Fatalf("the old secret: %v, want UNAUTHORIZED", err)
	}
	src, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil || src.Tombstone == nil || src.Tombstone.Reason != nipcash.ReasonTransferred {
		t.Fatalf("the source bill: %+v %v, want its tombstone, transferred", src, err)
	}
}

// E-WD-06: a connection_key slice whose version is kept out of blocks: 7 days
// after sent_by CancelWithdraw has it invalidated, broadcast until then, then
// cancelled; the re-mint decrypts only with the attestation's p key.
func TestEWD06_ConnectionKeyCancelRequest(t *testing.T) {
	e := newLedEnv(t)
	iaPriv, iaPub := sessionKeypair(t)
	priv, pub := sessionKeypair(t)
	e.h.TrustIA(t, iaPub, true)
	key, err := nipIC.NewConnectionKey("discord", "12345")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{PrivateKey: iaPriv, ConnectionKey: key, UserPubkey: pub, Platform: "discord",
		ExpirationDays: 30, AuthType: "email_code", Evidence: nipIC.Evidence{Platform: "discord", UserID: "12345"}})
	if err != nil {
		t.Fatal(err)
	}
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := nipcash.BySigningConnectionKey(priv, att)
	if err != nil {
		t.Fatal(err)
	}
	c := e.connect(t, e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "connection_key", IdentityValue: key.String(), IAPubkey: iaPub, AmountMillis: wdAmount}))
	// A Hub cannot tell which key holds a connection_key slice before an
	// attestation names it, so the caller supplies its row.
	fee, net, _ := nipcash.RedeemFee(wdAmount, cashtest.LedgerRedeemFeeBase, cashtest.LedgerRedeemFeePpm)
	terms := e.l.Terms()
	status := &nipcash.CashStatusResult{Withdraw: &terms, Recipients: []nipcash.RecipientStatus{{IdentityType: "connection_key",
		IdentityValue: key.String(), IAPubkey: iaPub, AmountMillis: wdAmount, RedeemFeeMillis: fee, NetRedeemableMillis: net}}}
	q := e.quote(t, c, cred, status)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: q, Credential: cred}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.all()[0]
	e.l.Chain().Mine(1)
	_, p := e.lookup(t, c, pc, cred)
	if p.State != nipcash.PayoutBroadcast {
		t.Fatalf("payout %s", p.State)
	}
	e.l.Chain().Withhold(p.Txid, true)
	bill, _ := c.bill()
	s, _ := c.billSession(ctx)
	var refused *CancelRefusedError
	if _, err := s.cancelWithdraw(ctx, bill, pc, cred, e.l.Now().Unix()); !errors.As(err, &refused) || !refused.Local {
		t.Fatalf("a cancel request before 7 days: %v, want refused locally", err)
	}
	e.l.Advance(8 * 24 * time.Hour)
	cp, err := s.cancelWithdraw(ctx, bill, pc, cred, e.l.Now().Unix())
	if err != nil || cp.State != nipcash.PayoutBroadcast {
		t.Fatalf("the cancel request: %+v %v, want broadcast while the invalidation confirms", cp, err)
	}
	e.l.Chain().Mine(6)
	lo, p := e.lookup(t, c, pc, cred)
	if p == nil || p.State != nipcash.PayoutCancelled {
		t.Fatalf("after the invalidation: %+v", p)
	}
	if _, err := (nipcash.CashWithdrawParams{Credential: nipcash.BySigning(iaPriv)}).ParseLookupResult(lo.Result); err == nil {
		t.Error("the re-minted token decrypts with another key")
	}
	if tok, err := nipcash.Decode(p.NewWalletToken.Token); err != nil || tok.WalletPubkey != p.NewWalletPubkey {
		t.Fatalf("the re-minted token: %v", err)
	}
}

// E-WD-08: with every notice dropped, polling still reaches final; with
// notices kept, WatchPayout signals once at the broadcast, at least 600 s
// after it, and never at confirmed or final.
func TestEWD08_Notices(t *testing.T) {
	e := newLedEnv(t)
	for _, r := range e.h.Relays {
		r.Drop(func(ev *nip01.Event) bool { return ev.Kind == 23189 })
	}
	c, cred := e.pubkey(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.all()[0]
	for range 10 {
		e.l.Advance(30 * time.Minute)
		e.l.Chain().Mine(1)
	}
	if _, p := e.lookup(t, c, pc, cred); !PayoutFinished(p) {
		t.Fatalf("polling with every notice dropped: %+v", p)
	}
	for _, r := range e.h.Relays {
		r.Drop(nil)
	}
	c, cred = e.pubkey(t)
	j = newTestJournal()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc = j.all()[0]
	notices, err := c.WatchPayout(ctx, pc.Notify, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	quiet := func(what string) {
		select {
		case <-notices:
			t.Fatalf("a notice %s", what)
		case <-time.After(300 * time.Millisecond):
		}
	}
	e.l.Chain().Mine(1)
	e.l.Advance(599 * time.Second)
	quiet("within 599 s of the broadcast")
	e.l.Advance(601 * time.Second)
	select {
	case <-notices:
	case <-time.After(5 * time.Second):
		t.Fatal("no notice 20 minutes after the broadcast")
	}
	e.l.Chain().Mine(8)
	e.l.Advance(time.Hour)
	quiet("at confirmed or final")
}

// E-WD-09: a reorganisation after one confirmation: confirmed, broadcast,
// confirmed again under the same txid, never reported as failed.
func TestEWD09_Reorg(t *testing.T) {
	e := newLedEnv(t)
	c, cred := e.pubkey(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	pc := j.all()[0]
	e.l.Chain().Mine(2)
	_, p1 := e.lookup(t, c, pc, cred)
	e.l.Chain().Reorg(1)
	_, p2 := e.lookup(t, c, pc, cred)
	e.l.Chain().Mine(1)
	_, p3 := e.lookup(t, c, pc, cred)
	if p1.State != nipcash.PayoutConfirmed || p2.State != nipcash.PayoutBroadcast || p3.State != nipcash.PayoutConfirmed ||
		p1.Txid != p2.Txid || p2.Txid != p3.Txid || p2.TxErr != nil {
		t.Fatalf("states %s %s %s, txids %s %s %s", p1.State, p2.State, p3.State, p1.Txid, p2.Txid, p3.Txid)
	}
}

// E-WD-10: the journal is lost: cash_status' own row carries
// withdraw_request_id; the call recovered from it is looked up with deadline
// now, done, and never re-placed.
func TestEWD10_LostJournal(t *testing.T) {
	e := newLedEnv(t)
	privA, pubA := sessionKeypair(t)
	_, pubB := sessionKeypair(t)
	tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pubA, AmountMillis: wdAmount},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pubB, AmountMillis: wdAmount})
	c, cred := e.connect(t, tok), nipcash.BySigning(privA)
	ctx, cancel := e2eContext(t)
	defer cancel()
	if _, err := c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred}, newTestJournal(), "dev"); err != nil {
		t.Fatal(err)
	}
	st, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil || st.Recipients[0].WithdrawRequestID == "" {
		t.Fatalf("the own row: %+v %v", st, err)
	}
	b, _ := nipcash.Decode(tok)
	pc := nipcash.PendingCall{RequestID: st.Recipients[0].WithdrawRequestID, Method: nipcash.MethodCashWithdraw, Target: b.WalletPubkey, Device: "dev",
		HubIdentity: e.h.NodeXOnly()}
	lo, p := e.lookup(t, c, pc, cred)
	if lo.Status != nipcash.LookupDone || p == nil {
		t.Fatalf("the recovered call's lookup: %+v", lo)
	}
	if qid, err := nipcash.ReceiptQuoteID(p.Receipt); err != nil || len(qid) != 64 {
		t.Errorf("ReceiptQuoteID: %q %v", qid, err)
	}
	act, err := Recover(ctx, pc, func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		lo, _, err := c.LookupWithdraw(ctx, pc, cred)
		return lo, err
	}, "dev", time.Now())
	if err != nil || act.Kind != ActionWait || act.Result == nil {
		t.Fatalf("Recover: %+v %v, want a wait with the payout", act, err)
	}
}

// E-WD-11: the Hub answers REQUEST_REUSED (the fake already holds the id): the
// lookup is unknown, Recover asks for confirmation, Replace refuses without it
// and with it re-places the call under a new verified quote.
func TestEWD11_RequestReused(t *testing.T) {
	e := newLedEnv(t)
	c, cred := e.pubkey(t)
	rid, _ := nipcash.NewRequestID()
	e.l.MarkUsed(rid)
	j := newTestJournal()
	ie := indeterminate(t, c, nipcash.CashWithdrawParams{Quote: e.quote(t, c, cred, nil), Credential: cred, RequestID: rid}, j)
	if ie.Code != nipcash.ErrCodeRequestReused || !ie.Call.SawReused {
		t.Fatalf("a reused id: %+v", ie)
	}
	e.l.Advance(2 * time.Minute)
	ctx, cancel := e2eContext(t)
	defer cancel()
	act, err := Recover(ctx, ie.Call, func(ctx context.Context, pc nipcash.PendingCall) (LookupOutcome, error) {
		lo, _, err := c.LookupWithdraw(ctx, pc, cred)
		return lo, err
	}, "dev", time.Now())
	if err != nil || act.Kind != ActionConfirmReplace {
		t.Fatalf("Recover: %+v %v, want ActionConfirmReplace", act, err)
	}
	nq := e.quote(t, c, cred, nil)
	send := func(ctx context.Context, next nipcash.PendingCall) error {
		q, err := nipcash.ParseWithdrawQuote(next.Quote)
		if err != nil {
			return err
		}
		_, err = c.Withdraw(ctx, nipcash.CashWithdrawParams{Quote: q, Credential: cred, RequestID: next.RequestID, Notify: next.Notify}, j, "dev")
		return err
	}
	if _, err := Replace(ctx, ie.Call, j, ReplaceOptions{Quote: nq}, send); !errors.Is(err, ErrReplaceNeedsConfirmation) {
		t.Fatalf("Replace unconfirmed: %v", err)
	}
	if _, err := Replace(ctx, ie.Call, j, ReplaceOptions{Quote: nq, Confirmed: true}, send); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	derived, _ := nipcash.DerivedRequestID(rid)
	p, ok := e.l.Payout(derived)
	if !ok || p.State != nipcash.PayoutQueued {
		t.Fatalf("no payout under the derived id")
	}
	if qid, _ := nipcash.ReceiptQuoteID(p.Receipt); qid != nq.ID {
		t.Errorf("the receipt's q %s, want the new quote %s", qid, nq.ID)
	}
}
