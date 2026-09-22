package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcash"
)

// ErrInterimIdentityNotPubkey is returned by RekeyCashSlice when
// ConsolidateWith is non-empty and InterimIdentity isn't a pubkey target
// — checked client-side, before any wire call, since this composite's
// interim step is a CashTransfer (which has no target-type restriction of
// its own): an unvalidated bad InterimIdentity would otherwise succeed
// for real, consuming the original cash secret, before the following
// CashConsolidate then rejected it.
var ErrInterimIdentityNotPubkey = errors.New("nipcash/client: RekeyCashSlice requires InterimIdentity to be a pubkey target")

// RekeyCashSliceParams moves a cash-mode slice out of shared custody:
// CashSlice's own secret is presented once, consumed, and replaced with
// a fresh secret only the caller knows — optionally consolidating the
// slice with other same-issuer sources the caller already controls into
// that same fresh cash note.
//
// Consolidating requires an interim reassignment first: cash_consolidate
// never accepts a cash-mode source (nipcash.ErrCashSource — a
// cash secret has no signature or binding, so a co-recipient of
// whatever connection placed the call could read and race it), so the
// slice must first move onto an identity cash_consolidate does accept.
// InterimIdentity/InterimCredential describe that identity and how to
// prove control of it afterward — both required together, and only, when
// ConsolidateWith is non-empty.
type RekeyCashSliceParams struct {
	// CashSlice.Credential MUST be a nipcash.BySecret(...) value — this
	// is always a cash-mode slice by definition.
	CashSlice nipcash.Source
	// InterimIdentity MUST be a pubkey target (see
	// ErrInterimIdentityNotPubkey), required iff ConsolidateWith is
	// non-empty.
	InterimIdentity   nipcash.Target
	InterimCredential nipcash.Credential
	ConsolidateWith   []nipcash.Source // none may be cash-mode
	MintSignature     bool
}

// RekeyCashSliceResult is RekeyCashSlice's outcome. NewToken == ""
// means the slice was re-keyed in place with nothing consolidated;
// non-empty means a new consolidated wallet was minted — no separate
// bool needed to tell the two apart.
type RekeyCashSliceResult struct {
	NewSecret       string
	NewWalletPubkey string
	NewToken        string
	AmountMillis    uint64
}

// RekeyCashSlice moves CashSlice out of shared cash-mode custody: its
// current secret is presented once, consumed, and replaced with a fresh
// secret only the caller knows (returned as NewSecret — the only copy,
// persist it immediately). With ConsolidateWith empty, this is a single
// in-place CashTransfer (cash-mode source ⇒ single-recipient-by-construction,
// so it's always in-place — NewToken stays ""). With ConsolidateWith
// non-empty, CashSlice first reassigns onto InterimIdentity (also
// always in-place), then consolidates alongside ConsolidateWith into a
// freshly-minted cash-mode wallet (NewToken is then non-empty).
//
// If the interim reassignment succeeds but the following consolidate
// then fails, returns *PartialProgressError{Transferred: <the interim
// CashTransferResult>} — nothing about CashSlice's original secret is
// recoverable at that point (it was genuinely consumed), so the caller
// must record InterimIdentity's real effect rather than treat the whole
// call as a no-op.
func (c *Client) RekeyCashSlice(ctx context.Context, p RekeyCashSliceParams) (*RekeyCashSliceResult, error) {
	return rekeyCashSlice(ctx, c, p)
}

// rekeyCashSlice is RekeyCashSlice's actual call-sequencing logic,
// against the narrow transferConsolidater interface rather than *Client
// directly — see transferConsolidater's own doc comment for why: this is
// what a test calls with a hand-built fake to exercise the branching
// (single vs. consolidated path, partial-failure error) without a
// network.
func rekeyCashSlice(ctx context.Context, c transferConsolidater, p RekeyCashSliceParams) (*RekeyCashSliceResult, error) {
	bt := nipcash.NewCashTarget()

	if len(p.ConsolidateWith) == 0 {
		result, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
			Credential:    p.CashSlice.Credential,
			To:            bt,
			CurrentAmount: p.CashSlice.Amount,
			MintSignature: p.MintSignature,
		})
		if err != nil {
			return nil, err
		}
		return &RekeyCashSliceResult{
			NewSecret:       bt.Secret(),
			NewWalletPubkey: p.CashSlice.WalletPubkey,
			AmountMillis:    result.AmountMillis,
		}, nil
	}

	if !nipcash.IsPubkeyTarget(p.InterimIdentity) {
		return nil, ErrInterimIdentityNotPubkey
	}

	interimResult, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
		Credential:    p.CashSlice.Credential,
		To:            p.InterimIdentity,
		CurrentAmount: p.CashSlice.Amount,
		MintSignature: p.MintSignature,
	})
	if err != nil {
		return nil, err
	}

	thisSource := nipcash.Source{
		WalletPubkey: p.CashSlice.WalletPubkey,
		Amount:       p.CashSlice.Amount,
		Credential:   p.InterimCredential,
	}
	sources := append([]nipcash.Source{thisSource}, p.ConsolidateWith...)
	result, err := c.CashConsolidate(ctx, nipcash.CashConsolidateParams{
		Sources:       sources,
		To:            bt,
		MintSignature: p.MintSignature,
	})
	if err != nil {
		return nil, &PartialProgressError{Transferred: interimResult, Cause: err}
	}

	return &RekeyCashSliceResult{
		NewSecret:       bt.Secret(),
		NewWalletPubkey: result.NewWalletPubkey,
		NewToken:        result.NewWalletToken,
		AmountMillis:    result.AmountMillis,
	}, nil
}
