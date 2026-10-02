package client

// Audit C, SDK-abstraction role, surface 3: does the abstraction make a half-built /
// half-completed state representable?
//
// FINDING C-SDK-3 (HIGH, money destroyed) — CONFIRMED AND FIXED.
//
// Pre-fix, RekeyCashSlice generated the replacement cash secret ITSELF
// (nipcash.NewCashTarget(), called at the top of rekeyCashSlice) and returned it only
// on the success path. On the no-consolidate path the whole operation is ONE
// CashTransfer to that fresh target: if that call returned an ambiguous error — a
// timeout, a NotServedError, or ErrIncompleteReply from a hub lying about its chunk
// `total` — the hub may well have applied the re-key, and the ONLY copy of the new
// secret died with the local variable. The slice then required a secret that existed
// nowhere, unrecoverable even by the hub, which never had it.
//
// Not conditional on a hostile hub. One dropped reply was enough.
//
// The fix moves the target to a caller-supplied parameter (RekeyCashSliceParams.NewTarget,
// typed *nipcash.CashTarget so the compiler enforces that the caller holds the thing the
// secret lives in), so the secret can be written down BEFORE the call and reconciled
// after — the only order that survives an ambiguous answer. cashctl had already reached
// this conclusion and bypassed RekeyCashSlice entirely (cmd/receive_secure.go), leaving
// the defect live for every other consumer of the published API.
//
// This file is the ATTACK-PATTERN MATRIX for that fix. The load-bearing assertion in
// every row that reaches the wire is POINTER IDENTITY: the target the hub was asked to
// re-key onto must be the very object the caller passed. That single check is what
// re-introducing an internal NewCashTarget() cannot survive — it would break all six
// wire-reaching rows at once, in both branches, rather than only the one row someone
// remembered to update.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// rekeyMatrixSlice is the slice under re-key, identical in every row so the only
// variable is the failure the transport injects.
func rekeyMatrixSlice() nipcash.Source {
	return nipcash.Source{
		WalletPubkey: strings.Repeat("ab", 32),
		Amount:       500_000,
		Credential:   nipcash.BySecret(strings.Repeat("11", 32)),
	}
}

// TestAuditC_RekeySlice_AmbiguousFailureMatrix_SecretStaysWithCaller sweeps the
// ambiguous outcomes — the ones where the hub MAY have applied the re-key and the
// client cannot tell. Pre-fix every one of these destroyed the replacement secret.
//
// "Ambiguous" is the whole point of the row set: a clean, decided rejection is safe
// under either design, because nothing was applied. These are the cases where the
// caller must be able to go and ask.
func TestAuditC_RekeySlice_AmbiguousFailureMatrix_SecretStaysWithCaller(t *testing.T) {
	type row struct {
		name string
		// what the transport does instead of answering
		injected error
		// why this shape is ambiguous rather than a decided no
		why string
	}
	rows := []row{
		{
			name:     "incomplete_reply_hub_lied_about_total",
			injected: ErrIncompleteReply,
			why:      "hub declared total=2, sent chunk 1, never sent chunk 2; the re-key in chunk 1 may have been applied",
		},
		{
			name:     "context_deadline_exceeded",
			injected: context.DeadlineExceeded,
			why:      "the plain dropped reply; the hub's own processing is unaffected by our timer",
		},
		{
			name:     "context_canceled",
			injected: context.Canceled,
			why:      "caller or parent gave up mid-flight; the request was already on the wire",
		},
		{
			name:     "not_served",
			injected: &NotServedError{Method: "cash_transfer"},
			why:      "NotServedError's own doc says it may or may not have been applied",
		},
		{
			name:     "response_malformed_hostile_relay",
			injected: transport.ErrResponseMalformed,
			why:      "a relay can corrupt the reply to bytes after the hub committed the re-key",
		},
		{
			name:     "opaque_transport_error",
			injected: errors.New("read tcp: connection reset by peer"),
			why:      "the unclassified case, which must default to recoverable and not to lost",
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// The caller mints and, in real use, PERSISTS this before calling. That is
			// the order the fix exists to permit.
			newTarget := nipcash.NewCashTarget()
			recorded := newTarget.Secret()
			if recorded == "" {
				t.Fatal("setup: NewCashTarget produced no secret, nothing to protect")
			}

			fake := &fakeTransferConsolidater{
				transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
					return nil, r.injected
				},
			}

			res, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
				CashSlice: rekeyMatrixSlice(),
				NewTarget: newTarget,
			})

			if res != nil {
				t.Fatalf("result = %+v, want nil on error", res)
			}
			if !errors.Is(err, r.injected) {
				t.Fatalf("err = %v, want %v through (%s)", err, r.injected, r.why)
			}

			// A real re-key WAS requested: a commitment to `recorded` crossed the wire.
			if len(fake.transferCalls) != 1 {
				t.Fatalf("%d transfer calls, want 1", len(fake.transferCalls))
			}
			onWire, ok := fake.transferCalls[0].To.(*nipcash.CashTarget)
			if !ok {
				t.Fatalf("wire target type %T, want *nipcash.CashTarget", fake.transferCalls[0].To)
			}

			// THE FIX, asserted by pointer identity rather than by value: the hub was
			// asked to re-key onto the caller's OWN object. An internally-minted target
			// would be a different pointer carrying a different secret, and the
			// caller's recorded value would be worthless.
			if onWire != newTarget {
				t.Fatalf("the wire carried a DIFFERENT target than the caller supplied — " +
					"a secret was minted inside rekeyCashSlice, which is exactly C-SDK-3")
			}
			if got := newTarget.Secret(); got != recorded {
				t.Fatalf("the caller's target mutated during the call: %q != %q", got, recorded)
			}
			t.Logf("recoverable: hub may hold the slice re-keyed to %s..., caller got %v, "+
				"and the secret is still in the caller's own target", recorded[:8], err)
		})
	}
}

// TestAuditC_RekeySlice_ConsolidatePathMatrix_SecretStaysWithCaller is the same sweep
// on the other branch. This branch already reported partial progress pre-fix — but the
// thing it reported was the interim transfer, never the secret, so the destination
// secret was lost here too whenever the consolidate failed ambiguously.
func TestAuditC_RekeySlice_ConsolidatePathMatrix_SecretStaysWithCaller(t *testing.T) {
	ambiguous := []struct {
		name     string
		injected error
	}{
		{"incomplete_reply_hub_lied_about_total", ErrIncompleteReply},
		{"context_deadline_exceeded", context.DeadlineExceeded},
		{"not_served", &NotServedError{Method: "cash_consolidate"}},
		{"response_malformed_hostile_relay", transport.ErrResponseMalformed},
	}

	for _, c := range ambiguous {
		t.Run(c.name, func(t *testing.T) {
			injected := c.injected
			newTarget := nipcash.NewCashTarget()
			recorded := newTarget.Secret()

			interim := &nipcash.CashTransferResult{AmountMillis: 500_000, IdentityType: "pubkey"}
			fake := &fakeTransferConsolidater{
				transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
					return interim, nil
				},
				consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
					return nil, injected
				},
			}

			_, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
				CashSlice:         rekeyMatrixSlice(),
				InterimIdentity:   nipcash.Pubkey(strings.Repeat("cd", 32)),
				InterimCredential: nipcash.BySigning(strings.Repeat("22", 32)),
				ConsolidateWith: []nipcash.Source{{
					WalletPubkey: strings.Repeat("ef", 32), Amount: 1,
					Credential: nipcash.BySigning(strings.Repeat("33", 32)),
				}},
				NewTarget: newTarget,
			})

			// The interim reassignment genuinely landed, so it must be reported as
			// progress and not as a no-op. This half predates the fix.
			var partial *PartialProgressError
			if !errors.As(err, &partial) {
				t.Fatalf("err = %v, want *PartialProgressError", err)
			}
			if partial.Transferred != interim {
				t.Error("PartialProgressError did not carry the landed interim transfer")
			}
			if !errors.Is(err, injected) {
				t.Errorf("the underlying %v must stay unwrappable", injected)
			}

			// And the destination secret is still the caller's. Pre-fix the caller
			// learned the interim identity held the money but could never learn which
			// secret the hub might have consolidated it onto.
			if len(fake.consolidateCalls) != 1 {
				t.Fatalf("%d consolidate calls, want 1", len(fake.consolidateCalls))
			}
			onWire, ok := fake.consolidateCalls[0].To.(*nipcash.CashTarget)
			if !ok {
				t.Fatalf("wire target type %T, want *nipcash.CashTarget", fake.consolidateCalls[0].To)
			}
			if onWire != newTarget {
				t.Fatal("the consolidate carried a target the caller never supplied — C-SDK-3 in the consolidate branch")
			}
			if newTarget.Secret() != recorded {
				t.Fatal("the caller's target mutated during the call")
			}
		})
	}
}

// TestAuditC_RekeySlice_SuccessMatrix_ReturnsTheCallersOwnSecret covers the direction a
// fix like this can silently get wrong: returning A secret that is not THE secret. If
// NewSecret were ever a different value from the one the caller persisted, the caller's
// pre-call record would be the wrong one and the fix would have moved the loss rather
// than removed it.
func TestAuditC_RekeySlice_SuccessMatrix_ReturnsTheCallersOwnSecret(t *testing.T) {
	t.Run("no_consolidate_in_place", func(t *testing.T) {
		newTarget := nipcash.NewCashTarget()
		recorded := newTarget.Secret()
		fake := &fakeTransferConsolidater{
			transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
				return &nipcash.CashTransferResult{AmountMillis: 500_000}, nil
			},
		}
		res, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
			CashSlice: rekeyMatrixSlice(),
			NewTarget: newTarget,
		})
		if err != nil {
			t.Fatalf("rekeyCashSlice: %v", err)
		}
		if res.NewSecret != recorded {
			t.Fatalf("NewSecret = %q, want the caller's own %q", res.NewSecret, recorded)
		}
		if res.NewToken != "" {
			t.Fatalf("NewToken = %q, want empty on the in-place path", res.NewToken)
		}
	})

	t.Run("consolidated_into_new_wallet", func(t *testing.T) {
		newTarget := nipcash.NewCashTarget()
		recorded := newTarget.Secret()
		fake := &fakeTransferConsolidater{
			transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
				return &nipcash.CashTransferResult{AmountMillis: 500_000, IdentityType: "pubkey"}, nil
			},
			consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
				return &nipcash.CashConsolidateResult{
					AmountMillis: 500_001, NewWalletPubkey: "merged", NewWalletToken: "lokicash1merged",
				}, nil
			},
		}
		res, err := rekeyCashSlice(context.Background(), fake, RekeyCashSliceParams{
			CashSlice:         rekeyMatrixSlice(),
			InterimIdentity:   nipcash.Pubkey(strings.Repeat("cd", 32)),
			InterimCredential: nipcash.BySigning(strings.Repeat("22", 32)),
			ConsolidateWith: []nipcash.Source{{
				WalletPubkey: strings.Repeat("ef", 32), Amount: 1,
				Credential: nipcash.BySigning(strings.Repeat("33", 32)),
			}},
			NewTarget: newTarget,
		})
		if err != nil {
			t.Fatalf("rekeyCashSlice: %v", err)
		}
		if res.NewSecret != recorded {
			t.Fatalf("NewSecret = %q, want the caller's own %q", res.NewSecret, recorded)
		}
		if res.NewToken != "lokicash1merged" {
			t.Fatalf("NewToken = %q, want the merged wallet's token", res.NewToken)
		}
	})
}

// TestAuditC_RekeySlice_OmittedNewTarget_RefusedBeforeAnyWireCall is the other way the
// fix could have been made worthless: defaulting. A caller that forgot the new field
// must be REFUSED, not quietly handed the old behaviour back — and refused before
// anything irreversible happens, since the interim transfer consumes the original
// secret for real.
func TestAuditC_RekeySlice_OmittedNewTarget_RefusedBeforeAnyWireCall(t *testing.T) {
	// Both branches, because the nil check must precede the wire in each.
	both := []struct {
		name string
		p    RekeyCashSliceParams
	}{
		{
			name: "no_consolidate_path",
			p:    RekeyCashSliceParams{CashSlice: rekeyMatrixSlice()},
		},
		{
			name: "consolidate_path",
			p: RekeyCashSliceParams{
				CashSlice:         rekeyMatrixSlice(),
				InterimIdentity:   nipcash.Pubkey(strings.Repeat("cd", 32)),
				InterimCredential: nipcash.BySigning(strings.Repeat("22", 32)),
				ConsolidateWith: []nipcash.Source{{
					WalletPubkey: strings.Repeat("ef", 32), Amount: 1,
					Credential: nipcash.BySigning(strings.Repeat("33", 32)),
				}},
			},
		},
	}

	for _, c := range both {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeTransferConsolidater{
				transferFunc: func(nipcash.CashTransferParams) (*nipcash.CashTransferResult, error) {
					t.Fatal("CashTransfer must not be called with no NewTarget — it consumes the original secret")
					return nil, nil
				},
				consolidateFunc: func(nipcash.CashConsolidateParams) (*nipcash.CashConsolidateResult, error) {
					t.Fatal("CashConsolidate must not be called with no NewTarget")
					return nil, nil
				},
			}
			_, err := rekeyCashSlice(context.Background(), fake, c.p)
			if !errors.Is(err, ErrNewTargetNotCash) {
				t.Fatalf("err = %v, want ErrNewTargetNotCash", err)
			}
			if len(fake.transferCalls) != 0 || len(fake.consolidateCalls) != 0 {
				t.Fatalf("calls: transfer=%d consolidate=%d, want 0/0", len(fake.transferCalls), len(fake.consolidateCalls))
			}
		})
	}
}

// A non-cash NewTarget is not a test case, it is a compile error: the field is typed
// *nipcash.CashTarget, so nipcash.Pubkey(...) cannot be assigned to it. Recorded here
// because a reader looking for that row in the matrix should find out why it is absent
// rather than conclude it was forgotten. The line below is the proof, and it must stay
// commented out:
//
//	RekeyCashSliceParams{NewTarget: nipcash.Pubkey("deadbeef")}
//	  ⇒ cannot use nipcash.Pubkey("deadbeef") (value of type nipcash.Target)
//	    as *nipcash.CashTarget value in struct literal
