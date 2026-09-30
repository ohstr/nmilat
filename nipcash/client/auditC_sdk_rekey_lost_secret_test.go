package client

// Audit C, SDK-abstraction role, surface 3: does the abstraction make a half-built /
// half-completed state representable?
//
// RekeyCashSlice generates the replacement cash secret ITSELF
// (nipcash/identity.go:122, inside rekeyCashSlice at the top) and returns it only on
// the success path. On the no-consolidate path the whole operation is ONE CashTransfer
// to that fresh target: if that call returns an ambiguous error — a timeout, a
// NotServedError, or ErrIncompleteReply from a hub lying about its chunk total — the
// hub may well have applied the re-key, and the only copy of the new secret dies with
// the local variable. The slice then requires a secret that exists nowhere.
//
// The consolidate path already has the type for this (PartialProgressError). The
// no-consolidate path does not use it, and could not: what it would have to carry is
// the secret, and by then the caller has no way to ask for it.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

// TestAuditC_RekeySlice_AmbiguousErrorDestroysTheOnlySecret
func TestAuditC_RekeySlice_AmbiguousErrorDestroysTheOnlySecret(t *testing.T) {
	// The hub applied the re-key and said so, and the reply was declared incomplete —
	// C-SDK-1's exact output. Any timeout has the same shape.
	ambiguous := ErrIncompleteReply

	fake := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return nil, ambiguous
		},
	}

	res, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
		CashSlice: nipcash.Source{
			WalletPubkey: strings.Repeat("ab", 32),
			Amount:       500_000,
			Credential:   nipcash.BySecret(strings.Repeat("11", 32)),
		},
	})

	if res != nil {
		t.Fatalf("setup: expected a nil result on error, got %+v", res)
	}
	if !errors.Is(err, ambiguous) {
		t.Fatalf("setup: err = %v, want the transport error through", err)
	}

	// A real re-key WAS requested: the wire carried a commitment to a secret this
	// process generated.
	if len(fake.transferCalls) != 1 {
		t.Fatalf("setup: %d transfer calls, want 1", len(fake.transferCalls))
	}
	target, ok := fake.transferCalls[0].To.(*nipcash.CashTarget)
	if !ok {
		t.Fatalf("setup: target type %T, want *nipcash.CashTarget", fake.transferCalls[0].To)
	}
	secret := target.Secret()
	if secret == "" {
		t.Fatal("setup: no secret was generated, so there is nothing to lose")
	}

	// THE BUG: nothing the caller can reach carries that secret. res is nil, and the
	// error is a bare transport error — not the type this package already has for
	// "the first call landed, here is what you must record".
	var partial *PartialProgressError
	if errors.As(err, &partial) {
		t.Errorf("unexpected: a PartialProgressError was returned (%+v) — if this starts "+
			"happening, check whether it carries the new secret", partial)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("unexpected: the secret leaked into the error string; not a fix, but it would "+
			"at least be recoverable")
	}
	t.Logf("BUG PRESENT: the hub may hold a slice re-keyed to %s..., the caller was handed "+
		"(nil, %v), and that secret existed only in rekeyCashSlice's local `bt`. "+
		"NewCashTarget() is called INSIDE the composite, so a caller cannot write it "+
		"ahead of the call the way cashctl's own protectRekeyOnly deliberately does.",
		secret[:8], err)

	// CONTROL, the other half of the asymmetry: the CONSOLIDATE path does report
	// partial progress, so this is a gap in one branch rather than a policy of the
	// package. Same fake, same ambiguous error on the second call.
	interim := &nipcash.CashTransferResult{AmountMillis: 500_000, IdentityType: "pubkey"}
	fake2 := &fakeTransferConsolidater{
		transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
			return interim, nil
		},
		consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
			return nil, ambiguous
		},
	}
	_, err2 := rekeyCashSlice(context.Background(), fake2, RekeyCashSliceParams{
		CashSlice: nipcash.Source{
			WalletPubkey: strings.Repeat("ab", 32), Amount: 500_000,
			Credential: nipcash.BySecret(strings.Repeat("11", 32)),
		},
		InterimIdentity:   nipcash.Pubkey(strings.Repeat("cd", 32)),
		InterimCredential: nipcash.BySigning(strings.Repeat("22", 32)),
		ConsolidateWith: []nipcash.Source{{
			WalletPubkey: strings.Repeat("ef", 32), Amount: 1,
			Credential: nipcash.BySigning(strings.Repeat("33", 32)),
		}},
	})
	if !errors.As(err2, &partial) {
		t.Fatalf("control failed: the consolidate path returned %v, want *PartialProgressError", err2)
	}
	if partial.Transferred != interim {
		t.Error("control failed: PartialProgressError did not carry the landed transfer")
	}
	t.Logf("control: the consolidate path DOES report partial progress (%v), which is why the "+
		"no-consolidate path's silence is a gap and not a house style", err2)
}
