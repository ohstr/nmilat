package cashtest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
)

// A zap transfer on the ledger: always a spin-off, the new_identity's bill
// signed under the zap scheme over the sender, the target hash, issued_at and
// expires_at the reply carries; a partial one's remainder an ordinary bill.
func TestLedgerZapTransfer(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	ctx := spendCtx(t)
	pa, xa := cashtest.Keypair(t)
	_, xc := cashtest.Keypair(t)
	const target = "30023:" + "0000000000000000000000000000000000000000000000000000000000000001" + ":post"
	c := connectTo(t, l.MintBill(t, 30*24*time.Hour, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 21_000_000}))
	cred := nipcash.BySigning(pa)
	split := uint64(5_000_000)
	res, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: cred, To: nipcash.Pubkey(xc), CurrentAmount: 21_000_000,
		SplitAmount: &split, ZapTarget: target}, &journal{}, "dev")
	if err != nil {
		t.Fatalf("zap: %v", err)
	}
	if !res.ZapSigned() || *res.ExpiresAt == 0 || res.NewWalletToken == "" || res.RemainderWalletToken == "" {
		t.Fatalf("zap result %+v", res)
	}
	zb, err := nipcash.Decode(res.NewWalletToken)
	if err != nil || zb.Scheme != nipcash.SchemeZapV1 {
		t.Fatalf("zap bill: %v scheme %d", err, zb.Scheme)
	}
	z := nipcash.ZapContext{Recipient: xc, Sender: xa, ZapTarget: target, IssuedAt: *res.IssuedAt, ExpiresAt: *res.ExpiresAt}
	if minter, ok := nipcash.VerifyZapProvenance(zb, z); !ok || minter[2:] != h.NodeXOnly() {
		t.Fatalf("zap provenance %q %v", minter, ok)
	}
	z.ZapTarget += "x"
	if minter, ok := nipcash.VerifyZapProvenance(zb, z); ok && minter[2:] == h.NodeXOnly() {
		t.Fatal("the zap bill verifies over another target")
	}
	if rem, err := nipcash.Decode(res.RemainderWalletToken); err != nil || rem.Scheme != nipcash.SchemeMintV1 {
		t.Fatalf("remainder: %v scheme %d", err, rem.Scheme)
	}

	// A full zap of a never-expiring bill: one wallet, expires_at 0.
	pd, xd := cashtest.Keypair(t)
	c2 := connectTo(t, l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xd, AmountMillis: 2_000_000}))
	res, err = c2.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(pd), To: nipcash.Pubkey(xc),
		CurrentAmount: 2_000_000, ZapTarget: "ab"}, &journal{}, "dev")
	if err != nil || !res.ZapSigned() || *res.ExpiresAt != 0 || res.NewWalletToken == "" || res.RemainderWalletToken != "" {
		t.Fatalf("full zap: %+v %v", res, err)
	}
	if st, err := c2.CashStatus(ctx, nipcash.BySigning(pd), nipcash.ScopeMine); err != nil || st.Tombstone == nil {
		t.Fatalf("the zapped source: %+v %v, want its tombstone", st, err)
	}
}

// cash_consolidate on the ledger: two bills of one holder merge into one for a
// pubkey, delivered to the caller; the earliest expiry wins; the sources are
// tombstoned consolidated; a source with another holder is UNAUTHORIZED.
func TestLedgerConsolidate(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	ctx := spendCtx(t)
	pa, xa := cashtest.Keypair(t)
	_, xc := cashtest.Keypair(t)
	ta, _ := nipcash.Decode(l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 3_000_000}))
	rawB := l.MintBill(t, 48*time.Hour, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 2_000_000})
	tb, _ := nipcash.Decode(rawB)
	ta1, _ := nipcash.Encode(ta)
	c := connectTo(t, ta1)
	cred := nipcash.BySigning(pa)
	rid, _ := nipcash.NewRequestID()
	res, err := c.CashConsolidate(ctx, nipcash.CashConsolidateParams{Sources: []nipcash.Source{
		{WalletPubkey: ta.WalletPubkey, Amount: 3_000_000, Credential: cred},
		{WalletPubkey: tb.WalletPubkey, Amount: 2_000_000, Credential: cred}}, To: nipcash.Pubkey(xc), RequestID: rid}, &journal{}, "dev")
	if err != nil {
		t.Fatalf("consolidate: %v", err)
	}
	if res.AmountMillis != 5_000_000 || !res.ExpiresAt.Present || res.NewWalletToken == "" {
		t.Fatalf("consolidate result %+v", res)
	}
	merged, err := nipcash.Decode(res.NewWalletToken)
	if err != nil || merged.WalletPubkey != res.NewWalletPubkey {
		t.Fatalf("merged token: %v", err)
	}
	for _, raw := range []string{ta1, rawB} {
		if st, err := connectTo(t, raw).CashStatus(ctx, cred, nipcash.ScopeMine); err != nil || st.Tombstone == nil || st.Tombstone.Reason != nipcash.ReasonConsolidated {
			t.Fatalf("a source: %+v %v, want its tombstone, consolidated", st, err)
		}
	}

	// A source held by another key: UNAUTHORIZED, nothing claimed.
	_, xe := cashtest.Keypair(t)
	td, _ := nipcash.Decode(l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 1_000_000}))
	te, _ := nipcash.Decode(l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xe, AmountMillis: 1_000_000}))
	td1, _ := nipcash.Encode(td)
	rid, _ = nipcash.NewRequestID()
	_, err = connectTo(t, td1).CashConsolidate(ctx, nipcash.CashConsolidateParams{Sources: []nipcash.Source{
		{WalletPubkey: td.WalletPubkey, Amount: 1_000_000, Credential: cred},
		{WalletPubkey: te.WalletPubkey, Amount: 1_000_000, Credential: cred}}, To: nipcash.Pubkey(xc), RequestID: rid}, &journal{}, "dev")
	if hubCode(err) != nipcash.ErrCodeUnauthorized {
		t.Fatalf("a foreign source: %v, want UNAUTHORIZED", err)
	}
	if st, err := connectTo(t, td1).CashStatus(ctx, cred, nipcash.ScopeMine); err != nil || st.Tombstone != nil || st.Recipients[0].Claimed {
		t.Fatalf("the refused call's first source: %+v %v, want it live", st, err)
	}
}

// The operator's caps: a spin-off over the live-wallet cap is QUOTA_EXCEEDED,
// one over the lineage's spin-off rate RATE_LIMITED; an in-place transfer on
// the same bill is still served; DropArchive keeps a lookup answered.
func TestLedgerCapsAndDropArchive(t *testing.T) {
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	ctx := spendCtx(t)
	pa, xa := cashtest.Keypair(t)
	pb, xb := cashtest.Keypair(t)
	_, xc := cashtest.Keypair(t)
	c := connectTo(t, l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xa, AmountMillis: 4_000_000},
		nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xb, AmountMillis: 4_000_000}))
	split := uint64(1_000_000)
	transfer := func(priv string, to string, s *uint64) error {
		_, err := c.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(priv), To: nipcash.Pubkey(to),
			CurrentAmount: 4_000_000, SplitAmount: s}, &journal{}, "dev")
		return err
	}
	l.SetLiveWalletCap(1)
	if err := transfer(pa, xc, &split); hubCode(err) != nipcash.ErrCodeQuotaExceeded {
		t.Fatalf("over the live-wallet cap: %v, want QUOTA_EXCEEDED", err)
	}
	l.SetLiveWalletCap(0)
	l.SetSpinOffRate(1, time.Hour)
	if err := transfer(pa, xc, &split); err != nil {
		t.Fatalf("the first spin-off: %v", err)
	}
	if err := transfer(pb, xc, &split); hubCode(err) != nipcash.ErrCodeRateLimited {
		t.Fatalf("over the lineage rate: %v, want RATE_LIMITED", err)
	}
	if err := transfer(pb, xc, nil); err != nil {
		t.Fatalf("an in-place transfer after the refusals: %v", err)
	}
	l.SetSpinOffRate(0, 0)

	pd, xd := cashtest.Keypair(t)
	raw := l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: xd, AmountMillis: 2_000_000})
	tok, _ := nipcash.Decode(raw)
	if err := l.DropArchive(tok.WalletPubkey); !errors.Is(err, cashtest.ErrNoSuchBill) {
		t.Fatalf("a live bill's archive: %v", err)
	}
	cd := connectTo(t, raw)
	j := &journal{}
	if _, err := cd.CashTransfer(ctx, nipcash.CashTransferParams{Credential: nipcash.BySigning(pd), To: nipcash.Pubkey(xc),
		CurrentAmount: 2_000_000, SplitAmount: &split}, j, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := l.DropArchive(tok.WalletPubkey); err != nil {
		t.Fatalf("drop: %v", err)
	}
	lo, err := cd.LookupTransfer(ctx, j.last(), nipcash.BySigning(pd))
	if err != nil || lo.Status == nipcash.LookupDone || lo.Status == "" {
		t.Fatalf("lookup after the archive was dropped: %+v %v, want answered by its deadline", lo, err)
	}
}
