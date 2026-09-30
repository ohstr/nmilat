package nipcash

import "testing"

// TestAuditA_Exp_TombstoneRendersAsEmptyRoster is the premise of experience
// finding 1: cashctl's `cash status` (cmd/cash_inspect.go) renders ONLY
// result.Recipients and gates its trailer on len(result.Recipients) > 0. It never
// calls IsSpent(). A tombstone therefore renders as zero lines, exit 0.
func TestAuditA_Exp_TombstoneRendersAsEmptyRoster(t *testing.T) {
	retained := int64(1790000000)
	tomb := CashStatusResult{Error: ErrorSpent, RetainedUntil: &retained}

	if !tomb.IsSpent() {
		t.Fatal("tombstone should be IsSpent")
	}
	// Exactly what cmd/cash_inspect.go iterates and gates on.
	rowsPrinted := len(tomb.Recipients)
	trailerPrinted := len(tomb.Recipients) > 0 && tomb.Recipients[0].ExpiresAt != nil
	t.Logf("cash status text output: %d recipient rows, expiry trailer=%v, exit 0", rowsPrinted, trailerPrinted)
	if rowsPrinted != 0 || trailerPrinted {
		t.Fatalf("expected the tombstone to render as nothing; got rows=%d trailer=%v", rowsPrinted, trailerPrinted)
	}
	t.Log("=> the definitive \"this bill was spent\" answer is invisible in text mode")
}

// TestAuditA_Exp_MatchClaimAutoFalseNegatives is the premise of experience
// finding 2: reconcileAmbiguousSources (cashctl cmd/cash_consolidate.go:817)
// treats nipcash.ErrClaimNotFound from CheckClaim as "confirmed consumed on the
// Hub". CheckClaim produces that sentinel whenever MatchClaimAuto misses — and
// MatchClaimAuto misses on live, unspent rows in two ordinary cases.
func TestAuditA_Exp_MatchClaimAutoFalseNegatives(t *testing.T) {
	cases := []struct {
		name        string
		recipients  []RecipientStatus
		asPubkeyHex string
	}{
		{
			// A connection-key-bound bill, alive and unclaimed. Reachable with
			// `cashctl consolidate --as connection-key:...`, which is the ONLY way
			// resolveCredential will serve such an entry at all.
			name: "live connection_key row never matches",
			recipients: []RecipientStatus{
				{IdentityType: "connection_key", IdentityValue: "twitter:12345", AmountMillis: 50_000},
			},
			asPubkeyHex: "aa" + "00000000000000000000000000000000000000000000000000000000000000",
		},
		{
			// A pubkey-bound bill, alive and unclaimed, but --as overrode the
			// credential while localPubKeyHex(cmd) still returns the LOCAL identity.
			name: "live pubkey row under an --as override",
			recipients: []RecipientStatus{
				{IdentityType: "pubkey", IdentityValue: "bb" + "00000000000000000000000000000000000000000000000000000000000000", AmountMillis: 50_000},
			},
			asPubkeyHex: "cc" + "00000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := MatchClaimAuto(tc.recipients, tc.asPubkeyHex)
			t.Logf("MatchClaimAuto ok=%v -> CheckClaim returns ErrClaimNotFound -> cashctl writes StatusConsolidated and prints \"confirmed consumed on the Hub\"", ok)
			if ok {
				t.Fatalf("expected MatchClaimAuto to miss this live row (that IS the bug's premise)")
			}
			t.Logf("amount wrongly written off: %d millis", tc.recipients[0].AmountMillis)
		})
	}
}
