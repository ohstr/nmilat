package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// T11-56.
// A tombstone is its own answer: *BillGone, never ErrClaimNotFound.
func TestCheckClaim_TombstoneIsGone(t *testing.T) {
	until := int64(1758800000)
	_, err := claimFromStatus(&nipcash.CashStatusResult{Tombstone: &nipcash.Tombstone{Status: nipcash.StatusSpent, RetainedUntil: &until}},
		nil, nipcash.Token{}, nipcash.BySigning(strings.Repeat("11", 32)), 0)
	var gone *nipcash.BillGone
	if !errors.As(err, &gone) || errors.Is(err, nipcash.ErrClaimNotFound) {
		t.Fatalf("err = %v, want *BillGone", err)
	}
}

// signedKATToken is a lokicash bill of wallet 0x22 x 32 and 21000 millis, signed
// under cash-mint:v1 by private key 0x11 x 32 (minter katMinter).
func signedKATToken(t *testing.T) nipcash.Token {
	t.Helper()
	amount := uint64(21000)
	sign, err := nipcash.LocalMintSigner(strings.Repeat("11", 32), "lokicash")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := nipcash.SignToken(nipcash.Token{HRP: "lokicash", WalletPubkey: strings.Repeat("22", 32), Secret: strings.Repeat("33", 32),
		RelayURLs: []string{"wss://r.example"}, AttestedAmountMillis: &amount}, nipcash.SchemeMintV1, nil, katMinter[2:], sign)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

const katMinter = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"

// T11-37, T11-56.
// The row is the credential's; the hint in the token plays no part; the amount
// comes from the live row and a claimed one is not claimable.
func TestCheckClaim_OwnRowFromTheCredential(t *testing.T) {
	priv := strings.Repeat("11", 32)
	me := katMinter[2:] // the x-only key of priv
	stale := false
	tok := nipcash.Token{IdentityRequired: &stale}
	roster := &nipcash.CashStatusResult{Recipients: []nipcash.RecipientStatus{
		{IdentityType: "pubkey", IdentityValue: me, AmountMillis: 500}}}
	got, err := claimFromStatus(roster, nil, tok, nipcash.BySigning(priv), 0)
	if err != nil || got.Row.AmountMillis != 500 || !got.Claimable {
		t.Fatalf("got (%+v, %v)", got, err)
	}
	roster.Recipients[0].Claimed = true
	got, err = claimFromStatus(roster, nil, tok, nipcash.BySigning(priv), 0)
	if err != nil || got.Claimable || got.Reason != "claimed" {
		t.Fatalf("claimed: (%+v, %v)", got, err)
	}
}

// MinterXOnly is set only from a signature that verifies.
func TestCheckClaim_MinterOnlyWhenVerified(t *testing.T) {
	priv := strings.Repeat("11", 32)
	roster := func() *nipcash.CashStatusResult {
		return &nipcash.CashStatusResult{Recipients: []nipcash.RecipientStatus{{IdentityType: "pubkey", IdentityValue: katMinter[2:], AmountMillis: 1}}}
	}
	got, err := claimFromStatus(roster(), nil, signedKATToken(t), nipcash.BySigning(priv), 0)
	if err != nil || got.MinterXOnly != katMinter[2:] {
		t.Fatalf("valid signature: got (%+v, %v)", got, err)
	}
	bad := signedKATToken(t)
	bad.MintSignature = bad.MintSignature[:10]
	got, err = claimFromStatus(roster(), nil, bad, nipcash.BySigning(priv), 0)
	if err != nil || got.MinterXOnly != "" {
		t.Fatalf("malformed signature: got (%+v, %v)", got, err)
	}
}

// Silence is never gone (NIP-CASH §Answering About a Destroyed Bill), and neither
// is NOT_FOUND or an empty roster.
func TestCheckClaim_OnlyATombstoneIsGone(t *testing.T) {
	cred := nipcash.BySigning(strings.Repeat("11", 32))
	for name, tc := range map[string]struct {
		result *nipcash.CashStatusResult
		err    error
		want   error
	}{
		"timeout":      {nil, context.DeadlineExceeded, context.DeadlineExceeded},
		"omission":     {nil, &NotServedError{Method: nipcash.MethodCashStatus}, nil},
		"NOT_FOUND":    {nil, &relayclient.WalletError{Code: "NOT_FOUND"}, nipcash.ErrClaimNotFound},
		"empty roster": {&nipcash.CashStatusResult{}, nil, nipcash.ErrMineWidened},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := claimFromStatus(tc.result, tc.err, nipcash.Token{}, cred, 0)
			var gone *nipcash.BillGone
			if errors.As(err, &gone) || err == nil {
				t.Fatalf("err = %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
