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
		InterimIdentity: nipcash.NewCashTarget(), // invalid: not a pubkey target
		ConsolidateWith: []nipcash.Source{{WalletPubkey: "wallet2", Amount: 3000}},
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
			return &nipcash.CashTransferResult{AmountMillis: 5000, NewWalletPubkey: "wallet1"}, nil
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
