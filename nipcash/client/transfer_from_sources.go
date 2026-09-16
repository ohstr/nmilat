package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// TransferFromSourcesParams transfers exactly Amount to To, drawing from
// Sources — a single source transfers (or splits) directly; more than
// one consolidates first into InterimIdentity, then transfers onward
// from there. Sources must already be consolidate-eligible if there's
// more than one (same-minter, non-bearer) — this is an app-level
// curation choice (a caller's own bookkeeping decides "same minter";
// nipcash has no such concept), not a nipcash-enforced rule:
// CashConsolidateParams itself only checks ≥2 sources and rejects bearer
// sources/nil targets, nothing about minters. This function doesn't
// second-guess the caller's own selection either way.
type TransferFromSourcesParams struct {
	Sources []nipcash.Source // ≥1, caller-resolved (live amount + credential)
	Amount  uint64
	To      nipcash.Target
	// InterimIdentity MUST be a pubkey target, required iff
	// len(Sources) > 1. No client-side validation needed here (unlike
	// RekeyBearerSlice's own InterimIdentity): this composite's *first*
	// call is the interim CashConsolidate, and
	// CashConsolidateParams.Request() already rejects a nil To before any
	// network call at all — a bad value is caught for free, before
	// anything moves.
	InterimIdentity   nipcash.Target
	InterimCredential nipcash.Credential // proves control of InterimIdentity afterward
	MintSignature     bool
}

// TransferFromSourcesResult is TransferFromSources' outcome.
// ConsolidatedFirst is nil if Sources had exactly one entry (no
// consolidate call was needed at all).
type TransferFromSourcesResult struct {
	ConsolidatedFirst *nipcash.CashConsolidateResult
	Transfer          *nipcash.CashTransferResult
}

// transferConsolidaterCloser is a transferConsolidater that can also be
// released — the shape reconnect returns, since a client dialed purely
// for TransferFromSources' own final call has no other owner to close it.
type transferConsolidaterCloser interface {
	transferConsolidater
	Close()
}

// transferFromSourcesClient is TransferFromSources' own requirement,
// beyond transferConsolidater's two calls: rebinding to a different
// wallet after the interim consolidate. cash_consolidate always spins
// off a genuinely new wallet (new pubkey), but CashTransfer's own
// proof-building binds to *Client.WalletPubkey() specifically — the
// pubkey the Client was originally dialed against
// (nipcash/client/cash_transfer.go's own CashTransfer method). Acting on
// the newly-consolidated wallet through the *original* client would
// therefore bind the final transfer's proof to the wrong wallet pubkey
// entirely, and the Hub would reject it (confirmed live: NOT_FOUND).
// RekeyBearerSlice never needs this — its own interim step is a
// CashTransfer, which (per NIP-CASH's own rules) is always in-place for
// a bearer source, so its Client binding never goes stale.
type transferFromSourcesClient interface {
	transferConsolidater
	reconnect(ctx context.Context, walletToken string) (transferConsolidaterCloser, error)
}

// reconnect dials a fresh client bound to walletToken.
func (c *Client) reconnect(ctx context.Context, walletToken string) (transferConsolidaterCloser, error) {
	return Connect(ctx, walletToken)
}

// TransferFromSources transfers Amount to To, drawing from Sources. A
// single source transfers (or splits, via CashTransferParams.SplitAmount)
// directly — NIP-CASH's wire format treats an omitted amount_millis and
// one equal to the source's own current amount as equivalent full
// transfers, so Amount == the source's own amount never accidentally
// forces a split. More than one source consolidates first into
// InterimIdentity (always spinning off a genuinely new wallet, with a
// new wallet pubkey), then reconnects to that new wallet specifically
// before transferring the combined total onward to To — see
// transferFromSourcesClient's own doc comment for why the reconnect is
// required, not optional.
//
// If the interim consolidate succeeds but the final transfer then fails
// (including a failure to even reconnect to the new wallet), returns
// *PartialProgressError{Consolidated: <the interim
// CashConsolidateResult>} so the caller can still record what actually
// landed on the wire.
func (c *Client) TransferFromSources(ctx context.Context, p TransferFromSourcesParams) (*TransferFromSourcesResult, error) {
	return transferFromSources(ctx, c, p)
}

// transferFromSources is TransferFromSources' actual call-sequencing
// logic, against transferFromSourcesClient rather than *Client directly
// — see transferConsolidater's own doc comment for why (the same
// no-network-testability reasoning, extended here with a reconnect step
// a fake can assert on independently).
func transferFromSources(ctx context.Context, c transferFromSourcesClient, p TransferFromSourcesParams) (*TransferFromSourcesResult, error) {
	if len(p.Sources) == 1 {
		src := p.Sources[0]
		result, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
			Credential:    src.Credential,
			To:            p.To,
			CurrentAmount: src.Amount,
			SplitAmount:   &p.Amount,
			MintSignature: p.MintSignature,
		})
		if err != nil {
			return nil, err
		}
		return &TransferFromSourcesResult{Transfer: result}, nil
	}

	consolidateResult, err := c.CashConsolidate(ctx, nipcash.CashConsolidateParams{
		Sources:       p.Sources,
		To:            p.InterimIdentity,
		MintSignature: p.MintSignature,
	})
	if err != nil {
		return nil, err
	}

	finalClient, err := c.reconnect(ctx, consolidateResult.NewWalletToken)
	if err != nil {
		return nil, &PartialProgressError{Consolidated: consolidateResult, Cause: err}
	}
	defer finalClient.Close()

	transferResult, err := finalClient.CashTransfer(ctx, nipcash.CashTransferParams{
		Credential:    p.InterimCredential,
		To:            p.To,
		CurrentAmount: consolidateResult.AmountMillis,
		SplitAmount:   &p.Amount,
		MintSignature: p.MintSignature,
	})
	if err != nil {
		return nil, &PartialProgressError{Consolidated: consolidateResult, Cause: err}
	}

	// p.Amount is always sent as an explicit SplitAmount above, even when
	// it equals the consolidated wallet's full amount — NIP-CASH treats
	// that as a plain full transfer, reassigning the SAME wallet in
	// place rather than spinning off a distinct one. transferResult then
	// reports no new wallet and no remainder, even though real money
	// landed on the interim wallet, now reassigned to p.To. Patched in
	// here, or RecipientToken would answer with a source token that's
	// already been consolidated away.
	if transferResult.NewWalletToken == "" && transferResult.RemainderWalletToken == "" {
		transferResult.NewWalletToken = consolidateResult.NewWalletToken
		transferResult.NewWalletPubkey = consolidateResult.NewWalletPubkey
	}

	return &TransferFromSourcesResult{ConsolidatedFirst: consolidateResult, Transfer: transferResult}, nil
}
