package cashtest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip57"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func spendCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func connectTo(t *testing.T, token string) *client.Client {
	t.Helper()
	c, err := client.Connect(spendCtx(t), token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// hubCode is the Hub's refusal code behind a client error, "" for none.
func hubCode(err error) string {
	var ie *client.IndeterminateError
	if errors.As(err, &ie) {
		return ie.Code
	}
	var fe *client.FinalError
	if errors.As(err, &fe) {
		return fe.Code
	}
	var we *relayclient.WalletError
	if errors.As(err, &we) {
		return we.Code
	}
	return ""
}

// cash_redeem against the ledger: the fake payee's invoice for the net amount
// is paid once, its preimage returned with the slice's fee; a wrong amount is
// BAD_REQUEST and an invoice the payee never issued PAYMENT_FAILED, both
// leaving the slice claimable; a redeemed slice is RESTRICTED.
func TestLedgerRedeem(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	pa, xa := cashtest.Keypair(t)
	_, xb := cashtest.Keypair(t)
	tok := l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 21_000_000},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xb, AmountMillis: 21_000_000})
	c := connectTo(t, tok)
	ctx := spendCtx(t)
	cred := nipcash.BySigning(pa)
	const fee, net = 105_000, 21_000_000 - 105_000

	if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: l.Invoice(net + 1), Credential: cred}); hubCode(err) != nipcash.ErrCodeBadRequest {
		t.Fatalf("a wrong amount: %v, want BAD_REQUEST", err)
	}
	foreign := cashtest.FakeBolt11(make([]byte, 32), net)
	if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: foreign, Credential: cred}); hubCode(err) != nipcash.ErrCodePaymentFailed {
		t.Fatalf("an invoice the payee never issued: %v, want PAYMENT_FAILED", err)
	}
	inv := l.Invoice(net)
	res, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: inv, Credential: cred})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	pre, _ := hex.DecodeString(res.Preimage)
	sum := sha256.Sum256(pre)
	decoded, _ := nip57.DecodeBolt11(inv)
	if hex.EncodeToString(sum[:]) != decoded.PaymentHash || res.FeesPaid != fee {
		t.Fatalf("redeem result %+v, want the invoice's preimage and fee %d", res, fee)
	}
	if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: l.Invoice(net), Credential: cred}); hubCode(err) != nipcash.ErrCodeRestricted {
		t.Fatalf("a redeemed slice: %v, want RESTRICTED", err)
	}
	// An amountless invoice with amount.
	amt := uint64(net)
	if _, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: l.Invoice(0), Amount: &amt, Credential: nipcash.BySigning(pa)}); hubCode(err) != nipcash.ErrCodeRestricted {
		t.Fatalf("redeemed again by an amountless invoice: %v, want RESTRICTED", err)
	}
}

// cash_transfer against the ledger: a partial split spins off two wallets
// delivered to the caller, the source tombstoned transferred, the call looked
// up done; a full transfer to a pubkey is in place; to cash on a two-slice
// wallet it spins off; a split below min_transfer is RESTRICTED.
func TestLedgerTransfer(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	ctx := spendCtx(t)
	pa, xa := cashtest.Keypair(t)
	_, xc := cashtest.Keypair(t)
	c := connectTo(t, l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 21_000_000}))
	cred := nipcash.BySigning(pa)

	half := uint64(500)
	if _, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(xc), CurrentAmount: 21_000_000,
		SplitAmount: &half}, &journal{}, "dev"); hubCode(err) != nipcash.ErrCodeRestricted {
		t.Fatalf("a split below min_transfer: %v, want RESTRICTED", err)
	}
	split := uint64(5_000_000)
	j := &journal{}
	res, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(xc), CurrentAmount: 21_000_000,
		SplitAmount: &split}, j, "dev")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if res.AmountMillis != split || res.RemainingAmountMillis == nil || *res.RemainingAmountMillis != 16_000_000 ||
		res.NewWalletToken == "" || res.RemainderWalletToken == "" {
		t.Fatalf("split result %+v", res)
	}
	rem, err := nipcash.Decode(res.RemainderWalletToken)
	if err != nil || rem.WalletPubkey != res.RemainderWalletPubkey {
		t.Fatalf("remainder token: %v", err)
	}
	st, err := connectTo(t, res.RemainderWalletToken).CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil || len(st.Recipients) != 1 || st.Recipients[0].AmountMillis != 16_000_000 || st.Recipients[0].RedeemFeeMillis != 80_000 {
		t.Fatalf("the remainder wallet: %+v %v", st, err)
	}
	if src, err := c.CashStatus(ctx, cred, nipcash.ScopeMine); err != nil || src.Tombstone == nil || src.Tombstone.Reason != nipcash.ReasonTransferred {
		t.Fatalf("the source: %+v %v, want its tombstone, transferred", src, err)
	}
	lo, err := c.LookupTransfer(ctx, j.last(), cred)
	if err != nil || lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup of the split: %+v %v", lo, err)
	}
	if lo, err := c.LookupTransfer(ctx, j.last(), nipcash.BySigning(pa[:62]+"01")); err == nil && lo.Status == nipcash.LookupDone {
		t.Fatal("another signer looked the split up")
	}

	// In place to a pubkey; then, as cash, on a two-slice wallet: a spin-off.
	pd, xd := cashtest.Keypair(t)
	_, xe := cashtest.Keypair(t)
	c2 := connectTo(t, l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xd, AmountMillis: 2_000_000},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xe, AmountMillis: 2_000_000}))
	pf, xf := cashtest.Keypair(t)
	res, err = c2.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(pd), To: nipcash.Pubkey(xf), CurrentAmount: 2_000_000}, &journal{}, "dev")
	if err != nil || res.NewWalletToken != "" || res.IdentityValue != xf {
		t.Fatalf("in place: %+v %v", res, err)
	}
	target, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	res, err = c2.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(pf), To: target, CurrentAmount: 2_000_000}, &journal{}, "dev")
	if err != nil || res.NewWalletToken == "" || res.RemainderWalletToken != "" {
		t.Fatalf("to cash on a two-slice wallet: %+v %v", res, err)
	}
	st, err = connectTo(t, res.NewWalletToken).CashStatus(ctx, nipcash.BySecret(target.Secret()), nipcash.ScopeMine)
	if err != nil || st.Recipients[0].IdentityType != "cash" || st.Recipients[0].AmountMillis != 2_000_000 {
		t.Fatalf("the cash spin-off: %+v %v", st, err)
	}
}

// The owner's delete and removal: refused for a re-minted slice, allowed
// otherwise; a removed slice is no slice.
func TestLedgerOwnerDeleteAndRemove(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	_, xa := cashtest.Keypair(t)
	pb, xb := cashtest.Keypair(t)
	raw := l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 2_000_000},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xb, AmountMillis: 2_000_000})
	tok, _ := nipcash.Decode(raw)
	if err := l.RemoveSlice(tok.WalletPubkey, "pubkey", xa); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := l.RemoveSlice(tok.WalletPubkey, "pubkey", xa); !errors.Is(err, cashtest.ErrNoSuchBill) {
		t.Fatalf("remove twice: %v", err)
	}
	c := connectTo(t, raw)
	if st, err := c.CashStatus(spendCtx(t), nipcash.BySigning(pb), nipcash.ScopeAll); err != nil || len(st.Recipients) != 1 {
		t.Fatalf("after the removal: %+v %v", st, err)
	}
	if err := l.DeleteBill(tok.WalletPubkey); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st, err := c.CashStatus(spendCtx(t), nipcash.BySigning(pb), nipcash.ScopeMine); err != nil || st.Tombstone == nil || st.Tombstone.Reason != nipcash.ReasonReclaimed {
		t.Fatalf("after the delete: %+v %v, want its tombstone, reclaimed", st, err)
	}
	if err := l.DeleteBill(tok.WalletPubkey); !errors.Is(err, cashtest.ErrNoSuchBill) {
		t.Fatalf("delete twice: %v", err)
	}
}
