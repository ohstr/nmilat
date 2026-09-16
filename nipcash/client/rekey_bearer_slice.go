package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcash"
)

// ErrInterimIdentityNotPubkey is returned by RekeyBearerSlice when
// ConsolidateWith is non-empty and InterimIdentity isn't a pubkey target
// — checked client-side, before any wire call, since this composite's
// interim step is a CashTransfer (which has no target-type restriction of
// its own): an unvalidated bad InterimIdentity would otherwise succeed
// for real, consuming the original bearer secret, before the following
// CashConsolidate then rejected it.
var ErrInterimIdentityNotPubkey = errors.New("nipcash/client: RekeyBearerSlice requires InterimIdentity to be a pubkey target")

// RekeyBearerSliceParams moves a bearer-mode slice out of shared custody:
// BearerSlice's own secret is presented once, consumed, and replaced with
// a fresh secret only the caller knows — optionally consolidating the
// slice with other same-issuer sources the caller already controls into
// that same fresh bearer note.
//
// Consolidating requires an interim reassignment first: cash_consolidate
// never accepts a bearer-identified source (nipcash.ErrBearerSource — a
// bearer secret has no signature or binding, so a co-recipient of
// whatever connection placed the call could read and race it), so the
// slice must first move onto an identity cash_consolidate does accept.
// InterimIdentity/InterimCredential describe that identity and how to
// prove control of it afterward — both required together, and only, when
// ConsolidateWith is non-empty.
type RekeyBearerSliceParams struct {
	// BearerSlice.Credential MUST be a nipcash.BySecret(...) value — this
	// is always a bearer slice by definition.
	BearerSlice nipcash.Source
	// InterimIdentity MUST be a pubkey target (see
	// ErrInterimIdentityNotPubkey), required iff ConsolidateWith is
	// non-empty.
	InterimIdentity   nipcash.Target
	InterimCredential nipcash.Credential
	ConsolidateWith   []nipcash.Source // none may be bearer-identified
	MintSignature     bool
}

// RekeyBearerSliceResult is RekeyBearerSlice's outcome. NewToken == ""
// means the slice was re-keyed in place with nothing consolidated;
// non-empty means a new consolidated wallet was minted — no separate
// bool needed to tell the two apart.
type RekeyBearerSliceResult struct {
	NewSecret       string
	NewWalletPubkey string
	NewToken        string
	AmountMillis    uint64
}

// RekeyBearerSlice moves BearerSlice out of shared bearer custody: its
// current secret is presented once, consumed, and replaced with a fresh
// secret only the caller knows (returned as NewSecret — the only copy,
// persist it immediately). With ConsolidateWith empty, this is a single
// in-place CashTransfer (bearer source ⇒ single-recipient-by-construction,
// so it's always in-place — NewToken stays ""). With ConsolidateWith
// non-empty, BearerSlice first reassigns onto InterimIdentity (also
// always in-place), then consolidates alongside ConsolidateWith into a
// freshly-minted bearer wallet (NewToken is then non-empty).
//
// If the interim reassignment succeeds but the following consolidate
// then fails, returns *PartialProgressError{Transferred: <the interim
// CashTransferResult>} — nothing about BearerSlice's original secret is
// recoverable at that point (it was genuinely consumed), so the caller
// must record InterimIdentity's real effect rather than treat the whole
// call as a no-op.
func (c *Client) RekeyBearerSlice(ctx context.Context, p RekeyBearerSliceParams) (*RekeyBearerSliceResult, error) {
	return rekeyBearerSlice(ctx, c, p)
}

// rekeyBearerSlice is RekeyBearerSlice's actual call-sequencing logic,
// against the narrow transferConsolidater interface rather than *Client
// directly — see transferConsolidater's own doc comment for why: this is
// what a test calls with a hand-built fake to exercise the branching
// (single vs. consolidated path, partial-failure error) without a
// network.
func rekeyBearerSlice(ctx context.Context, c transferConsolidater, p RekeyBearerSliceParams) (*RekeyBearerSliceResult, error) {
	bt := nipcash.NewBearerTarget()

	if len(p.ConsolidateWith) == 0 {
		result, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
			Credential:    p.BearerSlice.Credential,
			To:            bt,
			CurrentAmount: p.BearerSlice.Amount,
			MintSignature: p.MintSignature,
		})
		if err != nil {
			return nil, err
		}
		return &RekeyBearerSliceResult{
			NewSecret:       bt.Secret(),
			NewWalletPubkey: p.BearerSlice.WalletPubkey,
			AmountMillis:    result.AmountMillis,
		}, nil
	}

	if !nipcash.IsPubkeyTarget(p.InterimIdentity) {
		return nil, ErrInterimIdentityNotPubkey
	}

	interimResult, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
		Credential:    p.BearerSlice.Credential,
		To:            p.InterimIdentity,
		CurrentAmount: p.BearerSlice.Amount,
		MintSignature: p.MintSignature,
	})
	if err != nil {
		return nil, err
	}

	thisSource := nipcash.Source{
		WalletPubkey: p.BearerSlice.WalletPubkey,
		Amount:       p.BearerSlice.Amount,
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

	return &RekeyBearerSliceResult{
		NewSecret:       bt.Secret(),
		NewWalletPubkey: result.NewWalletPubkey,
		NewToken:        result.NewWalletToken,
		AmountMillis:    result.AmountMillis,
	}, nil
}
