package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

func TestTransferFromSources_SingleSource_NoConsolidateCall(t *testing.T) {
	fake := &fakeTransferConsolidater{
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			if params.SplitAmount == nil || *params.SplitAmount != 3000 {
				t.Fatalf("SplitAmount = %v, want 3000", params.SplitAmount)
			}
			return &nipcash.CashTransferResult{AmountMillis: 3000}, nil
		},
	}
	result, err := transferFromSources(context.Background(), fake, TransferFromSourcesParams{
		Sources: []nipcash.Source{{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s")}},
		Amount:  3000,
		To:      nipcash.Pubkey("recipient"),
	})
	if err != nil {
		t.Fatalf("transferFromSources: %v", err)
	}
	if len(fake.transferCalls) != 1 || len(fake.consolidateCalls) != 0 {
		t.Fatalf("calls: transfer=%d consolidate=%d, want 1/0", len(fake.transferCalls), len(fake.consolidateCalls))
	}
	if result.ConsolidatedFirst != nil {
		t.Fatal("ConsolidatedFirst must be nil — a single source never needs a consolidate call")
	}
}

func TestTransferFromSources_MultipleSources_ConsolidatesThenTransfers(t *testing.T) {
	fake := &fakeTransferConsolidater{
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			if len(params.Sources) != 2 {
				t.Fatalf("consolidate sources: got %d, want 2", len(params.Sources))
			}
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "interim"}, nil
		},
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			if params.CurrentAmount != 8000 {
				t.Fatalf("CurrentAmount = %d, want 8000 (the consolidated total)", params.CurrentAmount)
			}
			return &nipcash.CashTransferResult{AmountMillis: 8000}, nil
		},
	}
	result, err := transferFromSources(context.Background(), fake, TransferFromSourcesParams{
		Sources: []nipcash.Source{
			{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s1")},
			{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySecret("s2")},
		},
		Amount:            8000,
		To:                nipcash.Pubkey("recipient"),
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySecret("interim-doesnt-need-real-crypto-here"),
	})
	if err != nil {
		t.Fatalf("transferFromSources: %v", err)
	}
	if len(fake.consolidateCalls) != 1 || len(fake.transferCalls) != 1 {
		t.Fatalf("calls: consolidate=%d transfer=%d, want 1/1", len(fake.consolidateCalls), len(fake.transferCalls))
	}
	if result.ConsolidatedFirst == nil {
		t.Fatal("ConsolidatedFirst must be set — the interim consolidate actually ran")
	}
}

// TestTransferFromSources_ReconnectsToInterimWalletBeforeFinalTransfer is
// the regression test for a real, live-confirmed bug: the final transfer
// must run against a client rebound to the interim consolidate's own
// NewWalletToken — never the original client, which stays bound to
// whatever wallet TransferFromSources was originally dialed against.
// Reusing that stale binding built a CashTransfer proof against the
// wrong wallet pubkey, and the Hub rejected it (NOT_FOUND) every time.
func TestTransferFromSources_ReconnectsToInterimWalletBeforeFinalTransfer(t *testing.T) {
	final := &fakeTransferConsolidater{
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return &nipcash.CashTransferResult{AmountMillis: 8000}, nil
		},
	}
	original := &fakeTransferConsolidater{
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "interim", NewWalletToken: "interim-token"}, nil
		},
		reconnectFunc: func(walletToken string) (transferConsolidaterCloser, error) {
			return final, nil
		},
	}

	_, err := transferFromSources(context.Background(), original, TransferFromSourcesParams{
		Sources: []nipcash.Source{
			{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s1")},
			{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySecret("s2")},
		},
		Amount:            8000,
		To:                nipcash.Pubkey("recipient"),
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySecret("interim"),
	})
	if err != nil {
		t.Fatalf("transferFromSources: %v", err)
	}

	if len(original.reconnectCalls) != 1 || original.reconnectCalls[0] != "interim-token" {
		t.Fatalf("reconnectCalls = %v, want exactly one call with the interim consolidate's own NewWalletToken", original.reconnectCalls)
	}
	if len(original.transferCalls) != 0 {
		t.Fatalf("the ORIGINAL client's CashTransfer was called %d times, want 0 — the final transfer must happen on the reconnected client instead", len(original.transferCalls))
	}
	if len(final.transferCalls) != 1 {
		t.Fatalf("the RECONNECTED client's CashTransfer was called %d times, want 1", len(final.transferCalls))
	}
	if final.closed != 1 {
		t.Fatalf("reconnected client Close() called %d times, want 1 — TransferFromSources must release what it dials", final.closed)
	}
}

// TestTransferFromSources_ReconnectFailure_PartialProgress confirms a
// failure to even reconnect to the interim wallet is still reported as
// *PartialProgressError, not a bare error — the interim consolidate
// already landed for real either way, and the caller must not lose
// track of it just because the very next step (even just dialing)
// failed.
func TestTransferFromSources_ReconnectFailure_PartialProgress(t *testing.T) {
	reconnectErr := errors.New("dial refused")
	fake := &fakeTransferConsolidater{
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "interim", NewWalletToken: "interim-token"}, nil
		},
		reconnectFunc: func(walletToken string) (transferConsolidaterCloser, error) {
			return nil, reconnectErr
		},
	}

	_, err := transferFromSources(context.Background(), fake, TransferFromSourcesParams{
		Sources: []nipcash.Source{
			{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s1")},
			{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySecret("s2")},
		},
		Amount:            8000,
		To:                nipcash.Pubkey("recipient"),
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySecret("interim"),
	})
	var partial *PartialProgressError
	if !errors.As(err, &partial) {
		t.Fatalf("got %v, want *PartialProgressError", err)
	}
	if partial.Consolidated == nil {
		t.Fatal("partial.Consolidated is nil — the interim consolidate's real result must be surfaced even on a reconnect failure")
	}
	if !errors.Is(err, reconnectErr) {
		t.Fatal("the underlying reconnect error must be unwrappable via errors.Is")
	}
}

// TestTransferFromSources_ExactMatchFinalTransfer_SurfacesInterimWalletAsRecipientToken
// covers the exact-amount final transfer: the underlying CashTransfer
// response reports no NewWalletToken and no remainder (an in-place
// reassignment), so the interim wallet must be patched in — otherwise
// RecipientToken would point to an already-consolidated-away source.
func TestTransferFromSources_ExactMatchFinalTransfer_SurfacesInterimWalletAsRecipientToken(t *testing.T) {
	fake := &fakeTransferConsolidater{
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "interim-pub", NewWalletToken: "interim-token"}, nil
		},
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			// The server's real behavior for this exact case: an explicit
			// SplitAmount equal to CurrentAmount still reassigns in place,
			// reporting neither a new wallet nor a remainder.
			return &nipcash.CashTransferResult{AmountMillis: 8000}, nil
		},
	}
	result, err := transferFromSources(context.Background(), fake, TransferFromSourcesParams{
		Sources: []nipcash.Source{
			{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s1")},
			{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySecret("s2")},
		},
		Amount:            8000, // exactly the consolidated total: no remainder
		To:                nipcash.Pubkey("recipient"),
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySecret("interim"),
	})
	if err != nil {
		t.Fatalf("transferFromSources: %v", err)
	}
	if result.Transfer.NewWalletToken != "interim-token" {
		t.Fatalf("Transfer.NewWalletToken = %q, want the interim consolidate's own NewWalletToken (%q) surfaced through", result.Transfer.NewWalletToken, "interim-token")
	}
	if result.Transfer.NewWalletPubkey != "interim-pub" {
		t.Fatalf("Transfer.NewWalletPubkey = %q, want %q", result.Transfer.NewWalletPubkey, "interim-pub")
	}
	if got := result.Transfer.RecipientToken("wallet1-original-token"); got != "interim-token" {
		t.Fatalf("RecipientToken() = %q, want the interim wallet's token, not a consolidated-away source token", got)
	}
}

func TestTransferFromSources_InterimConsolidateLandsButTransferFails_PartialProgress(t *testing.T) {
	transferErr := errors.New("transfer rejected")
	fake := &fakeTransferConsolidater{
		consolidateFunc: func(params nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return &nipcash.CashConsolidateResult{AmountMillis: 8000, NewWalletPubkey: "interim"}, nil
		},
		transferFunc: func(params nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return nil, transferErr
		},
	}
	_, err := transferFromSources(context.Background(), fake, TransferFromSourcesParams{
		Sources: []nipcash.Source{
			{WalletPubkey: "wallet1", Amount: 5000, Credential: nipcash.BySecret("s1")},
			{WalletPubkey: "wallet2", Amount: 3000, Credential: nipcash.BySecret("s2")},
		},
		Amount:            8000,
		To:                nipcash.Pubkey("recipient"),
		InterimIdentity:   nipcash.Pubkey("myPubHex"),
		InterimCredential: nipcash.BySecret("interim"),
	})
	var partial *PartialProgressError
	if !errors.As(err, &partial) {
		t.Fatalf("got %v, want *PartialProgressError", err)
	}
	if partial.Consolidated == nil {
		t.Fatal("partial.Consolidated is nil — the interim consolidate's real result must be surfaced")
	}
	if partial.Transferred != nil {
		t.Fatal("partial.Transferred must be nil — TransferFromSources' interim step is a consolidate, not a transfer")
	}
	if !errors.Is(err, transferErr) {
		t.Fatal("the underlying transfer error must be unwrappable via errors.Is")
	}
}
