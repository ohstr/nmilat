package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// T11-58: which redeem outcomes need a status read. INTERNAL, an omission, an
// unanswered or conflicting item and an undecodable result do; any other code,
// a result, an envelope-level refusal (no item ran), a tombstone and an item
// never sent do not.
func TestT11_58_RedeemNeedsStatus(t *testing.T) {
	code := func(c string) *transport.ResultError { return &transport.ResultError{Code: c} }
	for name, tc := range map[string]struct {
		o    ItemOutcome
		want bool
	}{
		"omitted":           {ItemOutcome{State: OutcomeNotServed}, true},
		"unanswered":        {ItemOutcome{State: OutcomeUnanswered}, true},
		"conflict":          {ItemOutcome{State: OutcomeConflict}, true},
		"INTERNAL":          {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal)}, true},
		"undecodable":       {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal), Undecodable: true}, true},
		"result":            {ItemOutcome{State: OutcomeResult}, false},
		"PAYMENT_FAILED":    {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodePaymentFailed)}, false},
		"RATE_LIMITED":      {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeRateLimited)}, false},
		"envelope INTERNAL": {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal), envelopeLevel: true}, false},
		"tombstone":         {ItemOutcome{State: OutcomeError, Error: &transport.ResultError{}, Gone: &nipcash.Tombstone{Status: nipcash.StatusSpent}}, false},
		"not sent":          {ItemOutcome{State: OutcomeNotSent}, false},
	} {
		if got := (RedeemOutcome{ItemOutcome: tc.o}).NeedsStatus(); got != tc.want {
			t.Errorf("%s: NeedsStatus = %v, want %v", name, got, tc.want)
		}
	}
}

// redeemCountHub answers every cash_redeem with answer and counts them.
func redeemCountHub(t *testing.T, answer func(transport.Item) *transport.Result) (*Client, nipcash.Credential, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	priv, _ := sessionKeypair(t)
	hub := newTestHub(t, func(item transport.Item) *transport.Result {
		if item.Method != nipcash.MethodCashRedeem {
			return nil
		}
		n.Add(1)
		return answer(item)
	})
	s, _ := openTestSession(t, hub)
	_, target := sessionKeypair(t)
	return &Client{walletPubkey: target, connSecret: connSecretFor(target), session: s}, nipcash.BySigning(priv), &n
}

// T11-26, T11-58: INTERNAL, an omission and a timeout are a *NeedsStatusError
// that still unwraps to what the redeem returned before, and nothing is
// resent; PAYMENT_FAILED and RATE_LIMITED are definitive.
func TestT11_26_RedeemOutcomes(t *testing.T) {
	refuse := func(c string) func(transport.Item) *transport.Result {
		return func(item transport.Item) *transport.Result {
			return &transport.Result{ID: item.ID, Error: &transport.ResultError{Code: c, Message: "no"}}
		}
	}
	for name, tc := range map[string]struct {
		answer  func(transport.Item) *transport.Result
		timeout time.Duration
		needs   bool
		code    string
		check   func(error) bool
	}{
		"INTERNAL": {answer: refuse(nipcash.ErrCodeInternal), needs: true, code: nipcash.ErrCodeInternal,
			check: func(err error) bool { var we *relayclient.WalletError; return errors.As(err, &we) }},
		"omitted": {answer: func(transport.Item) *transport.Result { return nil }, needs: true,
			check: func(err error) bool { var ns *NotServedError; return errors.As(err, &ns) }},
		"PAYMENT_FAILED": {answer: refuse(nipcash.ErrCodePaymentFailed), code: nipcash.ErrCodePaymentFailed},
		"RATE_LIMITED":   {answer: refuse(nipcash.ErrCodeRateLimited), code: nipcash.ErrCodeRateLimited},
	} {
		t.Run(name, func(t *testing.T) {
			c, cred, n := redeemCountHub(t, tc.answer)
			ctx, cancel := e2eContext(t)
			defer cancel()
			_, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: cred})
			var ns *NeedsStatusError
			if errors.As(err, &ns) != tc.needs || errors.Is(err, ErrNeedsStatus) != tc.needs {
				t.Fatalf("err = %v, needs status %v", err, tc.needs)
			}
			if tc.needs && ns.Code != tc.code {
				t.Errorf("Code = %q, want %q", ns.Code, tc.code)
			}
			if !tc.needs {
				var we *relayclient.WalletError
				if !errors.As(err, &we) || we.Code != tc.code {
					t.Errorf("err = %v, want the %s refusal", err, tc.code)
				}
			}
			if tc.check != nil && !tc.check(err) {
				t.Errorf("err = %v no longer unwraps to the redeem's own error", err)
			}
			if n.Load() != 1 {
				t.Errorf("the Hub saw %d redeems, want 1", n.Load())
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		hub := newTestHub(t, func(item transport.Item) *transport.Result {
			return &transport.Result{ID: item.ID, ResultType: item.Method, Result: []byte(`{}`)}
		})
		hub.dropChunk = 1
		s, _ := openTestSession(t, hub)
		priv, _ := sessionKeypair(t)
		_, target := sessionKeypair(t)
		c := &Client{walletPubkey: target, connSecret: connSecretFor(target), session: s}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: nipcash.BySigning(priv)})
		if !errors.Is(err, ErrNeedsStatus) {
			t.Fatalf("err = %v, want ErrNeedsStatus", err)
		}
	})
}

// redEnv is a bill ledger whose next cash_redeem suffers a fault.
type redEnv struct {
	h     *cashtest.FakeHub
	l     *cashtest.WithdrawLedger
	fault atomic.Pointer[cashtest.Fault]
	once  atomic.Bool
}

func newRedEnv(t *testing.T) *redEnv {
	t.Helper()
	e := &redEnv{}
	e.fault.Store(&cashtest.FaultNone)
	e.h = cashtest.NewFakeHub(t, cashtest.WithFault(func(c cashtest.ItemCtx) cashtest.Fault {
		if c.Item.Method == nipcash.MethodCashRedeem && e.once.CompareAndSwap(true, false) {
			return *e.fault.Load()
		}
		return cashtest.FaultNone
	}))
	e.l = e.h.ServeWithdrawals(t, nil)
	return e
}

func (e *redEnv) faultNextRedeem(f cashtest.Fault) { e.fault.Store(&f); e.once.Store(true) }

// bill mints a pubkey bill of wdAmount to a fresh key, with a second
// recipient when shared, and dials it.
func (e *redEnv) bill(t *testing.T, shared bool) (*Client, nipcash.Credential) {
	t.Helper()
	priv, pub := sessionKeypair(t)
	rs := []nipcash.RecipientParam{{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: wdAmount}}
	if shared {
		_, other := sessionKeypair(t)
		rs = append(rs, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: other, AmountMillis: wdAmount})
	}
	tok := e.l.MintBill(t, 0, rs...)
	ctx, cancel := e2eContext(t)
	defer cancel()
	c, err := Connect(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, nipcash.BySigning(priv)
}

func (e *redEnv) redeem(ctx context.Context, c *Client, cred nipcash.Credential) (*nipcash.CashRedeemResult, error) {
	return c.CashRedeemWith(ctx, nipcash.CashRedeemParams{Invoice: e.l.Invoice(0), Credential: cred}, RedeemOptions{AutoAmount: true})
}

func (e *redEnv) redeems() int {
	n := 0
	for _, c := range e.h.Committed() {
		if c.Item.Method == nipcash.MethodCashRedeem {
			n++
		}
	}
	return n
}

func followUp(t *testing.T, c *Client, cred nipcash.Credential) (nipcash.RedeemProgress, *nipcash.CashStatusResult) {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, st, err := c.RedeemFollowUp(ctx, cred)
	if err != nil {
		t.Fatalf("RedeemFollowUp: %v", err)
	}
	return p, st
}

// E-RED-02 (S-CASH-74): the redeem's reply is lost after it committed: the
// caller is told to read its status, never to resend; its own row is claimed
// (RedeemInFlight) on a bill with another recipient, and the bill is gone
// (RedeemDone, reason redeemed) when it was the only one.
func TestERED02_ReplyOmitted(t *testing.T) {
	e := newRedEnv(t)
	for _, shared := range []bool{true, false} {
		c, cred := e.bill(t, shared)
		before := e.redeems()
		e.faultNextRedeem(cashtest.FaultCommitThenDropReply)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := e.redeem(ctx, c, cred)
		cancel()
		if !errors.Is(err, ErrNeedsStatus) {
			t.Fatalf("shared %v: err = %v, want ErrNeedsStatus", shared, err)
		}
		p, st := followUp(t, c, cred)
		switch {
		case shared && p != nipcash.RedeemInFlight:
			t.Fatalf("shared: progress %v, want RedeemInFlight", p)
		case !shared && (p != nipcash.RedeemDone || st.Tombstone == nil || st.Tombstone.Reason != nipcash.ReasonRedeemed):
			t.Fatalf("sole: progress %v, status %+v; want RedeemDone with reason redeemed", p, st)
		}
		if e.redeems()-before != 1 {
			t.Fatalf("shared %v: the Hub saw %d redeems, want 1", shared, e.redeems()-before)
		}
	}
}

// E-RED-08 (review 3, G3): the Hub answers the redeem INTERNAL while it holds
// the payment: NeedsStatus; the own row is claimed (RedeemInFlight) and nothing
// is resent; a payment that then fails releases the row (RedeemReleased) and a
// fresh invoice and proof is paid; one that settles leaves the tombstone
// (RedeemDone, reason redeemed).
func TestERED08_PaymentHeld(t *testing.T) {
	e := newRedEnv(t)
	held := func(t *testing.T) (*Client, nipcash.Credential) {
		t.Helper()
		c, cred := e.bill(t, false)
		e.faultNextRedeem(cashtest.FaultHoldPayments)
		ctx, cancel := e2eContext(t)
		defer cancel()
		_, err := e.redeem(ctx, c, cred)
		var ns *NeedsStatusError
		if !errors.As(err, &ns) || ns.Code != nipcash.ErrCodeInternal {
			t.Fatalf("err = %v, want a NeedsStatusError for INTERNAL", err)
		}
		if p, _ := followUp(t, c, cred); p != nipcash.RedeemInFlight {
			t.Fatalf("while held: progress %v, want RedeemInFlight", p)
		}
		return c, cred
	}

	t.Run("released", func(t *testing.T) {
		c, cred := held(t)
		before := e.redeems()
		if e.l.FailHeldRedeems() != 1 {
			t.Fatal("no payment was held")
		}
		if p, _ := followUp(t, c, cred); p != nipcash.RedeemReleased {
			t.Fatalf("after failure: progress %v, want RedeemReleased", p)
		}
		if e.redeems() != before {
			t.Fatal("the redeem was resent on its own")
		}
		ctx, cancel := e2eContext(t)
		defer cancel()
		if r, err := e.redeem(ctx, c, cred); err != nil || r == nil || r.Preimage == "" {
			t.Fatalf("a fresh redeem: %+v, %v", r, err)
		}
	})

	t.Run("settled", func(t *testing.T) {
		c, cred := held(t)
		if e.l.SettleHeldRedeems() != 1 {
			t.Fatal("no payment was held")
		}
		p, st := followUp(t, c, cred)
		if p != nipcash.RedeemDone || st.Tombstone == nil || st.Tombstone.Reason != nipcash.ReasonRedeemed {
			t.Fatalf("after settling: progress %v, status %+v", p, st)
		}
	})
}
