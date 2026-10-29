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

// NIP-CASH §cash_status: scope all lists every slice, claimed history included. OwnRow takes the caller's unclaimed
// row wherever it is listed, before or after its claimed rows; with none, its most recently claimed row.
func TestOwnRow_PrefersTheUnclaimedRowOverClaimedHistory(t *testing.T) {
	priv, pub := generateTestKeypair(t)
	_, other := generateTestKeypair(t)
	at := func(v int64) *int64 { return &v }
	live := RecipientStatus{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: 5}
	old := RecipientStatus{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: 1, Claimed: true, ClaimedAt: at(100)}
	newer := RecipientStatus{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: 2, Claimed: true, ClaimedAt: at(200)}
	stranger := RecipientStatus{IdentityType: "pubkey", IdentityValue: other, AmountMillis: 9}
	cred := BySigning(priv)
	for _, c := range []struct {
		name string
		rows []RecipientStatus
		want uint64
		err  error
	}{
		{"live first, history after", []RecipientStatus{live, old, newer}, 5, nil},
		{"history first, live after", []RecipientStatus{old, newer, live}, 5, nil},
		{"live between history rows", []RecipientStatus{newer, live, old}, 5, nil},
		{"only history: the latest claimed", []RecipientStatus{newer, stranger, old}, 2, nil},
		{"only history, other order", []RecipientStatus{old, newer}, 2, nil},
		{"a stranger's live row is not the caller's", []RecipientStatus{stranger, old}, 1, nil},
		{"two unclaimed rows", []RecipientStatus{live, old, live}, 0, ErrRowAmbiguous},
		{"no row of the caller", []RecipientStatus{stranger}, 0, ErrClaimNotFound},
	} {
		r, err := OwnRow(c.rows, cred, ScopeAll)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%s: %v, want %v", c.name, err, c.err)
			}
			continue
		}
		if err != nil || r.AmountMillis != c.want {
			t.Errorf("%s: %+v %v, want amount %d", c.name, r, err, c.want)
		}
	}
}
