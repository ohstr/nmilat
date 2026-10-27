package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

func TestRekeyCashSlice_NoConsolidateWith_OneTransferOnly(t *testing.T) {
	fake := &fakeTransferConsolidater{
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000}, nil
		},
	}
	result, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice: nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		NewTarget: mustCashTarget(t),
	})
	if err != nil {
		t.Fatalf("rekeyCashSlice: %v", err)
	}
	if len(fake.transferCalls) != 1 || len(fake.consolidateCalls) != 0 {
		t.Fatalf("calls: transfer=%d consolidate=%d, want 1/0", len(fake.transferCalls), len(fake.consolidateCalls))
	}
	if result.NewToken != "" {
		t.Fatalf("NewToken = %q, want \"\" (in-place, nothing consolidated)", result.NewToken)
	}
	if result.NewSecret == "" {
		t.Fatal("NewSecret is empty — the only copy of the fresh secret must be returned")
	}
	if result.AmountMillis != 5000 {
		t.Fatalf("AmountMillis = %d, want 5000", result.AmountMillis)
	}
}

func TestRekeyCashSlice_ConsolidateWith_TransfersThenConsolidates(t *testing.T) {
	const privKeyHex = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	fake := &fakeTransferConsolidater{
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000}, nil
		},
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "merged", NewWalletToken: "lokicash1merged"}, nil
		},
	}
	result, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice:         nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySigning(privKeyHex),
		ConsolidateWith:   []nipcash.Source{{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySigning(privKeyHex)}},
		NewTarget:         mustCashTarget(t),
	})
	if err != nil {
		t.Fatalf("rekeyCashSlice: %v", err)
	}
	if len(fake.transferCalls) != 1 || len(fake.consolidateCalls) != 1 {
		t.Fatalf("calls: transfer=%d consolidate=%d, want 1/1", len(fake.transferCalls), len(fake.consolidateCalls))
	}
	if len(fake.consolidateCalls[0].Sources) != 2 {
		t.Fatalf("consolidate sources: got %d, want 2 (the reassigned slice + ConsolidateWith)", len(fake.consolidateCalls[0].Sources))
	}
	if result.NewToken != "lokicash1merged" {
		t.Fatalf("NewToken = %q, want the merged wallet's token", result.NewToken)
	}
	if result.AmountMillis != 8000 {
		t.Fatalf("AmountMillis = %d, want 8000", result.AmountMillis)
	}
}

func TestRekeyCashSlice_BadInterimIdentity_RejectedBeforeAnyWireCall(t *testing.T) {
	// The exact fund-safety issue independent review caught: a cash-mode
	// InterimIdentity here would let the interim CashTransfer succeed for
	// real (consuming the original secret) before CashConsolidate then
	// rejected it. Must be caught before touching the fake at all.
	fake := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			t.Fatal("CashTransfer must not be called when InterimIdentity is invalid")
			return nil, nil
		},
		consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			t.Fatal("CashConsolidate must not be called when InterimIdentity is invalid")
			return nil, nil
		},
	}
	_, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice:       nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		InterimIdentity: mustCashTarget(t), // invalid: not a pubkey target
		ConsolidateWith: []nipcash.Source{{WalletPubkey: "wallet2", Amount: 3000}},
		NewTarget:       mustCashTarget(t),
	})
	if !errors.Is(err, ErrInterimIdentityNotPubkey) {
		t.Fatalf("got %v, want ErrInterimIdentityNotPubkey", err)
	}
	if len(fake.transferCalls) != 0 || len(fake.consolidateCalls) != 0 {
		t.Fatalf("calls: transfer=%d consolidate=%d, want 0/0 — nothing should touch the wire", len(fake.transferCalls), len(fake.consolidateCalls))
	}
}

func TestRekeyCashSlice_InterimTransferLandsButConsolidateFails_PartialProgress(t *testing.T) {
	const privKeyHex = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	consolidateErr := errors.New("consolidate rejected")
	fake := &fakeTransferConsolidater{
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000}, nil
		},
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return nil, consolidateErr
		},
	}
	_, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice:         nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySigning(privKeyHex),
		ConsolidateWith:   []nipcash.Source{{WalletPubkey: "wallet2", Amount: 3000}},
		NewTarget:         mustCashTarget(t),
	})
	var partial *PartialProgressError
	if !errors.As(err, &partial) {
		t.Fatalf("got %v, want *PartialProgressError", err)
	}
	if partial.Transferred == nil {
		t.Fatal("partial.Transferred is nil — the interim transfer's real result must be surfaced")
	}
	if partial.Consolidated != nil {
		t.Fatal("partial.Consolidated must be nil — RekeyCashSlice's interim step is a transfer, not a consolidate")
	}
	if !errors.Is(err, consolidateErr) {
		t.Fatal("the underlying consolidate error must be unwrappable via errors.Is")
	}
}

// H1: a full transfer to cash on a wallet that has had more than one recipient
// is spun off (NIP-CASH §Which outcome a request produces). The new wallet's
// token is then the only way to reach the bill, so it must come back.
func TestRekeyCashSlice_SpinOffReply_ReturnsNewWalletToken(t *testing.T) {
	fake := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000, NewWalletPubkey: "spun", NewWalletToken: "lokicash1spun"}, nil
		},
	}
	result, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice: nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		NewTarget: mustCashTarget(t),
	})
	if err != nil {
		t.Fatalf("rekeyCashSlice: %v", err)
	}
	if result.NewWalletPubkey != "spun" || result.NewToken != "lokicash1spun" {
		t.Fatalf("got wallet %q token %q, want the spin-off's", result.NewWalletPubkey, result.NewToken)
	}
}

func TestRekeyCashSlice_SpinOffWithoutToken_IsError(t *testing.T) {
	fake := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000, NewWalletPubkey: "spun"}, nil
		},
	}
	if _, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice: nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		NewTarget: mustCashTarget(t),
	}); err == nil {
		t.Fatal("a spin-off reply with no token was reported as success")
	}
}

// H1: the interim transfer spins off when the interim identity already holds a
// slice on the wallet; the consolidate must then name the new wallet.
func TestRekeyCashSlice_InterimSpinOff_ConsolidatesTheNewWallet(t *testing.T) {
	const privKeyHex = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	fake := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 5000, NewWalletPubkey: "interim-new", NewWalletToken: "lokicash1interim"}, nil
		},
		consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "merged", NewWalletToken: "lokicash1merged"}, nil
		},
	}
	_, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice:         nipcash.Source{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("old-secret")},
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySigning(privKeyHex),
		ConsolidateWith:   []nipcash.Source{{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySigning(privKeyHex)}},
		NewTarget:         mustCashTarget(t),
	})
	if err != nil {
		t.Fatalf("rekeyCashSlice: %v", err)
	}
	if got := fake.consolidateCalls[0].Sources[0].WalletPubkey; got != "interim-new" {
		t.Fatalf("consolidate source wallet = %q, want the interim spin-off", got)
	}
	if len(fake.reconnectCalls) != 1 || fake.reconnectCalls[0] != "lokicash1interim" || fake.closed != 1 {
		t.Fatalf("reconnects %v closed %d, want one to the interim spin-off's token, closed", fake.reconnectCalls, fake.closed)
	}
}
