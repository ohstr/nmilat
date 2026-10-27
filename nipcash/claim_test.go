package nipcash

import (
	"errors"
	"strings"
	"testing"
)

// T10-61: OwnRow takes the identity from the credential.
func TestT10_61_OwnRow(t *testing.T) {
	privA, pubA := generateTestKeypair(t)
	_, pubB := generateTestKeypair(t)
	a := RecipientStatus{IdentityType: "pubkey", IdentityValue: pubA, AmountMillis: 1}
	b := RecipientStatus{IdentityType: "pubkey", IdentityValue: pubB, AmountMillis: 2}
	if r, err := OwnRow([]RecipientStatus{a, b}, BySigning(privA), ScopeAll); err != nil || r.IdentityValue != pubA {
		t.Errorf("all: %+v %v", r, err)
	}
	if _, err := OwnRow([]RecipientStatus{b}, BySigning(privA), ScopeAll); !errors.Is(err, ErrClaimNotFound) {
		t.Errorf("all without mine: %v", err)
	}
	for name, rows := range map[string][]RecipientStatus{"two rows": {a, b}, "another's": {b}, "none": nil} {
		if _, err := OwnRow(rows, BySigning(privA), ScopeMine); !errors.Is(err, ErrMineWidened) {
			t.Errorf("mine %s: %v", name, err)
		}
	}
	// connection_key: key and IA both.
	iaPriv, iaPub := generateTestKeypair(t)
	userPriv, userPub := generateTestKeypair(t)
	att := buildTestAttestation(t, iaPriv, userPub, testDiscordKey(t), 1)
	cred := mustConnCred(t, userPriv, att)
	key := string(att.ConnectionKey)
	_, otherIA := generateTestKeypair(t)
	rows := []RecipientStatus{
		{IdentityType: "connection_key", IdentityValue: key, IAPubkey: otherIA},
		{IdentityType: "connection_key", IdentityValue: key, IAPubkey: iaPub, AmountMillis: 7},
	}
	if r, err := OwnRow(rows, cred, ScopeAll); err != nil || r.AmountMillis != 7 {
		t.Errorf("connection_key: %+v %v", r, err)
	}
	// cash: the row the secret commits to.
	ct := mustCashTarget(t)
	cash := RecipientStatus{IdentityType: "cash", IdentityValue: ct.Commitment(), AmountMillis: 9}
	if r, err := OwnRow([]RecipientStatus{cash}, BySecret(ct.Secret()), ScopeMine); err != nil || r.AmountMillis != 9 {
		t.Errorf("cash: %+v %v", r, err)
	}
	if _, err := OwnRow([]RecipientStatus{{IdentityType: "cash", IdentityValue: strings.Repeat("0", 64)}}, BySecret(ct.Secret()), ScopeMine); !errors.Is(err, ErrMineWidened) {
		t.Errorf("another cash row: %v", err)
	}
}

// T10-62.
func TestT10_62_Claimable(t *testing.T) {
	const now = int64(1720000000)
	if ok, _ := Claimable(RecipientStatus{}, now); !ok {
		t.Error("unclaimed live")
	}
	if ok, why := Claimable(RecipientStatus{Claimed: true}, now); ok || why != "claimed" {
		t.Error("claimed")
	}
	if ok, why := Claimable(RecipientStatus{WithdrawRequestID: strings.Repeat("a", 32)}, now); ok || why != "withdrawn" {
		t.Error("withdrawn")
	}
	if ok, _ := Claimable(RecipientStatus{ExpiresAt: Expiry{At: now, Present: true}}, now); !ok {
		t.Error("expires_at = now")
	}
	if ok, why := Claimable(RecipientStatus{ExpiresAt: Expiry{At: now, Present: true}}, now+1); ok || why != "expired" {
		t.Error("expired")
	}
}
