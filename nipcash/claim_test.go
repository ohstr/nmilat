package nipcash

import "testing"

func TestMatchClaim_CashUnclaimedMatches(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypeCash, AmountMillis: 5000, Claimed: false},
	}
	amount, ok := MatchClaim(recipients, true, NoLocalIdentity)
	if !ok || amount != 5000 {
		t.Fatalf("MatchClaim() = (%d, %v), want (5000, true)", amount, ok)
	}
}

func TestMatchClaim_CashAlreadyClaimedDoesNotMatch(t *testing.T) {
	// The exact regression independent review caught: an already-redeemed
	// cash-mode recipient must not be reported as a live match just because
	// its identity_type still says "cash".
	recipients := []RecipientStatus{
		{IdentityType: identityTypeCash, AmountMillis: 5000, Claimed: true},
	}
	if _, ok := MatchClaim(recipients, true, NoLocalIdentity); ok {
		t.Fatal("MatchClaim() matched an already-claimed cash-mode recipient")
	}
}

func TestMatchClaim_PubkeyExactMatchUnclaimed(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 3000, Claimed: false},
	}
	amount, ok := MatchClaim(recipients, false, "abc123")
	if !ok || amount != 3000 {
		t.Fatalf("MatchClaim() = (%d, %v), want (3000, true)", amount, ok)
	}
}

func TestMatchClaim_PubkeyAlreadyClaimedDoesNotMatch(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 3000, Claimed: true},
	}
	if _, ok := MatchClaim(recipients, false, "abc123"); ok {
		t.Fatal("MatchClaim() matched an already-claimed pubkey recipient")
	}
}

func TestMatchClaim_NoLocalIdentityNeverMatchesPubkey(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 3000, Claimed: false},
	}
	if _, ok := MatchClaim(recipients, false, NoLocalIdentity); ok {
		t.Fatal("MatchClaim() matched a pubkey recipient with no local identity supplied")
	}
}

func TestMatchClaim_WrongPubkeyDoesNotMatch(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 3000, Claimed: false},
	}
	if _, ok := MatchClaim(recipients, false, "someone-else"); ok {
		t.Fatal("MatchClaim() matched a pubkey recipient belonging to a different identity")
	}
}

func TestMatchClaim_NoRecipientsNoMatch(t *testing.T) {
	if _, ok := MatchClaim(nil, true, NoLocalIdentity); ok {
		t.Fatal("MatchClaim() matched against an empty recipient list")
	}
}

func TestMatchClaimAuto_CashWalletMatchesRegardlessOfSuppliedPubkey(t *testing.T) {
	// A pubkey is supplied but the wallet is actually cash-mode —
	// must still find the real cash-mode recipient.
	recipients := []RecipientStatus{
		{IdentityType: identityTypeCash, AmountMillis: 7000, Claimed: false},
	}
	recipient, ok := MatchClaimAuto(recipients, "some-caller-pubkey")
	if !ok || !recipient.IsCash() || recipient.AmountMillis != 7000 {
		t.Fatalf("MatchClaimAuto() = (%+v, %v), want (amount 7000, cash, true)", recipient, ok)
	}
}

func TestMatchClaimAuto_PubkeyWalletMatchesWithoutNeedingACashHint(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 4000, Claimed: false},
	}
	recipient, ok := MatchClaimAuto(recipients, "abc123")
	if !ok || recipient.IsCash() || recipient.AmountMillis != 4000 {
		t.Fatalf("MatchClaimAuto() = (%+v, %v), want (amount 4000, not cash, true)", recipient, ok)
	}
}

func TestMatchClaimAuto_NoLocalIdentitySkipsPubkeyAttemptButStillFindsCash(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypeCash, AmountMillis: 2500, Claimed: false},
	}
	recipient, ok := MatchClaimAuto(recipients, NoLocalIdentity)
	if !ok || !recipient.IsCash() || recipient.AmountMillis != 2500 {
		t.Fatalf("MatchClaimAuto() = (%+v, %v), want (amount 2500, cash, true)", recipient, ok)
	}
}

func TestMatchClaimAuto_WrongPubkeyAndNoCashRecipientNoMatch(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypePubkey, IdentityValue: "abc123", AmountMillis: 4000, Claimed: false},
	}
	if _, ok := MatchClaimAuto(recipients, "someone-else"); ok {
		t.Fatal("MatchClaimAuto() matched a pubkey recipient belonging to a different identity")
	}
}

func TestMatchClaimAuto_AlreadyClaimedRecipientNoMatch(t *testing.T) {
	recipients := []RecipientStatus{
		{IdentityType: identityTypeCash, AmountMillis: 5000, Claimed: true},
	}
	if _, ok := MatchClaimAuto(recipients, NoLocalIdentity); ok {
		t.Fatal("MatchClaimAuto() matched an already-claimed recipient")
	}
}

func TestMatchClaimAuto_NoRecipientsNoMatch(t *testing.T) {
	if _, ok := MatchClaimAuto(nil, "abc123"); ok {
		t.Fatal("MatchClaimAuto() matched against an empty recipient list")
	}
}

// TestMatchClaimAuto_ReturnsFullRowNotJustAmount confirms fee/expiry
// data rides along with the match, not just the amount.
func TestMatchClaimAuto_ReturnsFullRowNotJustAmount(t *testing.T) {
	expiresAt := int64(1234567890)
	recipients := []RecipientStatus{
		{
			IdentityType:        identityTypePubkey,
			IdentityValue:       "abc123",
			AmountMillis:        4000,
			RedeemFeeMillis:     50,
			NetRedeemableMillis: 3950,
			ExpiresAt:           &expiresAt,
		},
	}
	recipient, ok := MatchClaimAuto(recipients, "abc123")
	if !ok {
		t.Fatal("MatchClaimAuto() unexpectedly found no match")
	}
	if recipient.RedeemFeeMillis != 50 || recipient.NetRedeemableMillis != 3950 {
		t.Errorf("MatchClaimAuto() fee fields = (%d, %d), want (50, 3950)", recipient.RedeemFeeMillis, recipient.NetRedeemableMillis)
	}
	if recipient.ExpiresAt == nil || *recipient.ExpiresAt != expiresAt {
		t.Errorf("MatchClaimAuto() ExpiresAt = %v, want %d", recipient.ExpiresAt, expiresAt)
	}
}
