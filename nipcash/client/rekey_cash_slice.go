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

// ErrNewTargetNotCash refuses a re-key with no caller-supplied cash target.
//
// Deliberately an error rather than minting one: the target carries the only copy
// of the replacement secret, and a secret minted inside this call is lost on any
// ambiguous failure — see RekeyCashSliceParams.NewTarget.
var ErrNewTargetNotCash = errors.New("nipcash/client: RekeyCashSlice requires NewTarget to be a cash target the CALLER minted, so the new secret is recorded before the call")

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
	// NewTarget is the cash-mode target this slice is re-keyed ONTO, and the
	// caller supplies it.
	//
	// It used to be minted inside this function by nipcash.NewCashTarget(), which
	// made the replacement secret unrecoverable on any ambiguous failure. Only a
	// COMMITMENT crosses the wire, so the secret existed solely in a local
	// variable: if the CashTransfer returned a timeout, a NotServedError, or an
	// incomplete reply, this returned (nil, err) and the secret died with the
	// stack frame — while the Hub may well have applied the re-key. The slice was
	// then redeemable only with a secret that existed nowhere, and the Hub could
	// not restore it either, because it never had it.
	//
	// That is not conditional on a hostile Hub; one dropped reply is enough.
	//
	// Taking it as a parameter lets a caller write the secret down BEFORE the call
	// and reconcile afterwards, which is the only order that survives an
	// ambiguous answer. cashctl already does exactly this by bypassing
	// RekeyCashSlice entirely and generating the target itself — it wrote down the
	// reason in a comment and the SDK was never changed, so every other consumer
	// of this published API still had the defect.
	//
	// The CONCRETE type, not the Target interface, deliberately: only *CashTarget
	// exposes Secret(), so the compiler now enforces that the caller holds the thing
	// the secret lives in. A nil is refused rather than silently minted, so the
	// requirement cannot be missed by omission.
	NewTarget *nipcash.CashTarget
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
	// Refused, not defaulted. Minting one here is what destroyed the secret on an
	// ambiguous failure, so a caller that forgot to supply one must be told rather
	// than quietly given the old behaviour back.
	if p.NewTarget == nil {
		return nil, ErrNewTargetNotCash
	}
	bt := p.NewTarget

	if len(p.ConsolidateWith) == 0 {
		result, err := c.CashTransfer(ctx, nipcash.CashTransferParams{
			Credential:    p.CashSlice.Credential,
			To:            bt,
			CurrentAmount: p.CashSlice.Amount,
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
	// Authorized by this slice's own interim credential — the same one proving
	// control of the first source below.
	result, err := c.CashConsolidate(ctx, p.InterimCredential, nipcash.CashConsolidateParams{
		Sources: sources,
		To:      bt,
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
