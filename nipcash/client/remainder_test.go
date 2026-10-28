package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

// CASH-XFER-05, T11-32 (S-CASH-118, S-CASH-120): a partial split of a cash
// source without a RemainderTarget gets a fresh one; its secret is written
// ahead with role remainder, its commitment is not the source's, and it opens
// the remainder wallet. A caller-supplied target is kept.
func TestT11_32_SplitGeneratesTheRemainder(t *testing.T) {
	e := newRedEnv(t)
	for _, supplied := range []bool{false, true} {
		source := mustCashTarget(t)
		tok := e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "cash", IdentityValue: source.Commitment(), AmountMillis: wdAmount})
		ctx, cancel := e2eContext(t)
		c, err := Connect(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		half := wdAmount / 2
		p := nipcash.CashTransferParams{Credential: nipcash.BySecret(source.Secret()), To: mustCashTarget(t),
			CurrentAmount: wdAmount, SplitAmount: &half}
		var mine *nipcash.CashTarget
		if supplied {
			mine = mustCashTarget(t)
			p.RemainderTarget = mine
		}
		j := newTestJournal()
		s, err := c.billSession(ctx)
		if err != nil {
			t.Fatal(err)
		}
		bill, _ := c.bill()
		out, err := s.TransferMany(ctx, []BatchTransfer{{Bill: bill, Params: p}}, j, "dev")
		if err != nil || len(out) != 1 || out[0].Result == nil {
			t.Fatalf("supplied %v: TransferMany = %+v, %v", supplied, out, err)
		}
		rem := out[0].Remainder
		if rem == nil || nipcash.CommitmentsEqual(rem.Commitment(), source.Commitment()) || (supplied && rem != mine) {
			t.Fatalf("supplied %v: remainder %+v", supplied, rem)
		}
		calls := j.all()
		var journalled string
		for _, sec := range calls[0].Secrets {
			if sec.Role == nipcash.SecretRoleRemainder {
				journalled = sec.Secret
			}
		}
		if journalled != rem.Secret() {
			t.Fatalf("supplied %v: the remainder secret was not written ahead with role remainder: %+v", supplied, calls[0].Secrets)
		}
		// The secret opens the remainder wallet.
		rc, err := Connect(ctx, out[0].Result.RemainderWalletToken)
		if err != nil {
			t.Fatal(err)
		}
		st, err := rc.CashStatus(ctx, nipcash.BySecret(journalled), nipcash.ScopeMine)
		if err != nil || len(st.Recipients) != 1 || st.Recipients[0].IdentityValue != rem.Commitment() ||
			st.Recipients[0].AmountMillis != wdAmount-half {
			t.Fatalf("supplied %v: remainder status %+v, %v", supplied, st, err)
		}
		rc.Close()
		c.Close()
		cancel()
	}
}

// A full transfer, or a split of a pubkey source, gets no remainder target.
func TestRemainderFor_OnlyCashPartialSplits(t *testing.T) {
	half, full := uint64(500), uint64(1000)
	cash := nipcash.BySecret(mustCashTarget(t).Secret())
	priv, _ := sessionKeypair(t)
	for name, p := range map[string]nipcash.CashTransferParams{
		"full cash":     {Credential: cash, CurrentAmount: 1000, SplitAmount: &full},
		"no split":      {Credential: cash, CurrentAmount: 1000},
		"pubkey source": {Credential: nipcash.BySigning(priv), CurrentAmount: 1000, SplitAmount: &half},
	} {
		got, err := remainderFor(context.Background(), p)
		if err != nil || got.RemainderTarget != nil {
			t.Errorf("%s: %+v, %v", name, got.RemainderTarget, err)
		}
	}
}

// A re-placed split keeps the replaced call's remainder secret.
func TestRemainderFor_ReplacementKeepsTheSecret(t *testing.T) {
	half := uint64(500)
	prev := mustCashTarget(t)
	p := nipcash.CashTransferParams{Credential: nipcash.BySecret(mustCashTarget(t).Secret()), CurrentAmount: 1000,
		SplitAmount: &half, RequestID: testRequestID, To: mustCashTarget(t)}
	ctx := withReplacement(context.Background(), nipcash.PendingCall{RequestID: testRequestID,
		Secrets: []nipcash.PendingSecret{{Secret: mustCashTarget(t).Secret()}, {Secret: prev.Secret(), Role: nipcash.SecretRoleRemainder}}})
	got, err := remainderFor(ctx, p)
	if err != nil || got.RemainderTarget == nil || got.RemainderTarget.Secret() != prev.Secret() {
		t.Fatalf("remainder %+v, %v", got.RemainderTarget, err)
	}
	if _, err := p.Request("x"); !errors.Is(err, nipcash.ErrRemainderCommitment) {
		t.Fatalf("Request without a remainder: %v, want ErrRemainderCommitment", err)
	}
}
