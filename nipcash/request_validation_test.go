package nipcash

import (
	"errors"
	"testing"
	"time"
)

// NIP-CASH §Minting Cash: recipients MUST contain at least one entry.
func TestMintCashParams_Request_NoRecipients(t *testing.T) {
	if _, err := (MintCashParams{}).Request(); !errors.Is(err, ErrRequestIDRequired) {
		t.Fatalf("no request_id: err = %v", err)
	}
	if _, err := (MintCashParams{RequestID: testRID}).Request(); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("err = %v, want ErrNoRecipients", err)
	}
	if _, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{{AmountMillis: 1}}}).Request(); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("nil recipient: err = %v, want ErrNoRecipients", err)
	}
}

// NIP-CASH §Minting Cash: a connection_key entry MUST also carry ia_pubkey; so
// must a connection_key transfer or consolidate target.
func TestRequests_ConnectionKeyNeedsIAPubkey(t *testing.T) {
	noIA := attestedKey(t, "discord", "2002", "")
	if _, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(noIA, 1000)}}).Request(); !errors.Is(err, ErrMissingIAPubkey) {
		t.Errorf("mint_cash: err = %v, want ErrMissingIAPubkey", err)
	}
	priv, _ := generateTestKeypair(t)
	tr := CashTransferParams{RequestID: testRID, To: noIA, Credential: BySigning(priv), CurrentAmount: 1000}
	if _, err := tr.Request(randomKeyHex(t)); !errors.Is(err, ErrMissingIAPubkey) {
		t.Errorf("cash_transfer: err = %v, want ErrMissingIAPubkey", err)
	}
	cons := CashConsolidateParams{RequestID: testRID, To: noIA, Sources: []Source{
		From(randomKeyHex(t), 1, BySigning(priv)), From(randomKeyHex(t), 1, BySigning(priv))}}
	if _, err := cons.Request(); !errors.Is(err, ErrMissingIAPubkey) {
		t.Errorf("cash_consolidate: err = %v, want ErrMissingIAPubkey", err)
	}
	withIA := attestedKey(t, "discord", "2002", randomKeyHex(t))
	if _, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(withIA, 1000)}}).Request(); err != nil {
		t.Errorf("connection_key with ia_pubkey refused: %v", err)
	}
}

// NIP-CASH §Minting Cash: a caller's finite expiry MUST be honored. Truncating a
// sub-second one to zero would ask for the Hub's ceiling, possibly never.
func TestMintCashParams_Request_Expiry(t *testing.T) {
	alloc := []Allocation{Send(Pubkey(randomKeyHex(t)), 1000)}
	for _, d := range []time.Duration{-time.Second, time.Millisecond, 999 * time.Millisecond} {
		if _, err := (MintCashParams{RequestID: testRID, Recipients: alloc, Expiry: d}).Request(); !errors.Is(err, ErrInvalidExpiry) {
			t.Errorf("Expiry %v: err = %v, want ErrInvalidExpiry", d, err)
		}
	}
	for d, want := range map[time.Duration]int64{0: 0, time.Second: 1, 24 * time.Hour: 86400} {
		req, err := (MintCashParams{RequestID: testRID, Recipients: alloc, Expiry: d}).Request()
		if err != nil || req.Expiry != want {
			t.Errorf("Expiry %v: got (%d, %v), want %d", d, req.Expiry, err, want)
		}
	}
}

// NIP-CASH §Transferring and Splitting a Slice: new_identity is REQUIRED. A nil
// target used to panic in an unchecked type assertion.
func TestCashTransferParams_Request_NilTarget(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	_, err := (CashTransferParams{RequestID: testRID, Credential: BySigning(priv), CurrentAmount: 1}).Request(randomKeyHex(t))
	if !errors.Is(err, ErrTransferTargetInvalid) {
		t.Fatalf("err = %v, want ErrTransferTargetInvalid", err)
	}
}

// NIP-CASH §Consolidating Tokens: the same slice MUST NOT appear twice. Two
// identities on one wallet are two slices, and stay legal.
func TestCashConsolidateParams_Request_DuplicateSource(t *testing.T) {
	privA, _ := generateTestKeypair(t)
	privB, _ := generateTestKeypair(t)
	wallet := randomKeyHex(t)
	to := Pubkey(randomKeyHex(t))
	dup := CashConsolidateParams{RequestID: testRID, To: to, Sources: []Source{From(wallet, 1, BySigning(privA)), From(wallet, 1, BySigning(privA))}}
	if _, err := dup.Request(); !errors.Is(err, ErrDuplicateSource) {
		t.Fatalf("err = %v, want ErrDuplicateSource", err)
	}
	twoSlices := CashConsolidateParams{RequestID: testRID, To: to, Sources: []Source{From(wallet, 1, BySigning(privA)), From(wallet, 1, BySigning(privB))}}
	if _, err := twoSlices.Request(); err != nil {
		t.Fatalf("two identities on one wallet refused: %v", err)
	}
}

// NIP-CASH §Minting Cash: a cash entry carries the caller's commitment and no
// ia_pubkey (T10-03).
func TestMintCashParams_Request_CashEntryCarriesTheCommitment(t *testing.T) {
	ct := mustCashTarget(t)
	req, err := (MintCashParams{RequestID: testRID, Recipients: []Allocation{Send(ct, 1000)}}).Request()
	if err != nil {
		t.Fatal(err)
	}
	if r := req.Recipients[0]; r.IdentityType != "cash" || r.IdentityValue != ct.Commitment() || r.IAPubkey != "" {
		t.Fatalf("cash entry = %+v", r)
	}
}
