package client

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// A tombstone is its own answer: the bill is gone. Before ErrSpent existed it had
// no roster to match, so it came back as ErrClaimNotFound and a spent bill read
// as one that merely does not name the caller.
func TestCheckClaim_TombstoneIsSpent(t *testing.T) {
	until := int64(1758800000)
	_, err := claimFromStatus(&nipcash.CashStatusResult{Error: nipcash.ErrorSpent, RetainedUntil: &until},
		nil, nipcash.Token{}, nipcash.NoLocalIdentity)
	if !errors.Is(err, nipcash.ErrSpent) {
		t.Fatalf("err = %v, want ErrSpent", err)
	}
	if errors.Is(err, nipcash.ErrClaimNotFound) {
		t.Fatal("a tombstone must not also read as ErrClaimNotFound")
	}
}

// signedKATToken is nipcash's frozen lokicash provenance vector: wallet 0x22 x 32,
// 21000 millis, signed by private key 0x11 x 32 (minter katMinter).
func signedKATToken(t *testing.T) nipcash.Token {
	t.Helper()
	sig, err := hex.DecodeString("20c72cfbb8e8566000d6d90904c0c04fd047ce066dd599ede34c84dfb314f3126709ad9a50800f285c90a9683f8282b268a8bb85f8b7a9599f9b4482cbfd83b508")
	if err != nil {
		t.Fatal(err)
	}
	amount := uint64(21000)
	return nipcash.Token{HRP: "lokicash", WalletPubkey: strings.Repeat("22", 32), Secret: strings.Repeat("33", 32),
		RelayURLs: []string{"wss://r.example"}, MintSignature: sig, AttestedAmountMillis: &amount, Scheme: nipcash.SchemeMintV1}
}

const katMinter = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"

// NIP-CASH §Redemption Metadata: identity_required is a hint, never a substitute
// for the live answer. A stale "false" must not stop a pubkey match.
func TestCheckClaim_IgnoresAStaleIdentityRequiredHint(t *testing.T) {
	me := strings.Repeat("ab", 32)
	stale := false
	tok := nipcash.Token{IdentityRequired: &stale}
	roster := &nipcash.CashStatusResult{Recipients: []nipcash.RecipientStatus{
		{IdentityType: "pubkey", IdentityValue: me, AmountMillis: 500}}}
	got, err := claimFromStatus(roster, nil, tok, me)
	if err != nil || got.AmountMillis != 500 {
		t.Fatalf("got (%+v, %v), want the live pubkey row matched", got, err)
	}
}

// NIP-CASH §Mint Provenance: the mint signature is never a substitute for a call
// succeeding. The amount comes from the live roster, and a call that failed stays
// failed however good the signature.
func TestCheckClaim_SignatureNeverSubstitutesForTheCall(t *testing.T) {
	tok := signedKATToken(t)
	roster := &nipcash.CashStatusResult{Recipients: []nipcash.RecipientStatus{{IdentityType: "cash", AmountMillis: 4242}}}
	got, err := claimFromStatus(roster, nil, tok, nipcash.NoLocalIdentity)
	if err != nil || got.AmountMillis != 4242 {
		t.Fatalf("got (%+v, %v), want the roster's 4242, not the attested 21000", got, err)
	}

	// No connection secret, so cash_status cannot be sent at all.
	res, err := (&Client{walletPubkey: tok.WalletPubkey}).CheckClaim(context.Background(),
		nipcash.BySecret(tok.Secret), tok, nipcash.NoLocalIdentity)
	if err == nil || res != nil {
		t.Fatalf("CheckClaim without a cash_status answer = (%+v, %v), want an error", res, err)
	}
}

// MinterPubkey is set only from a signature that verifies.
func TestCheckClaim_MinterPubkeyOnlyWhenVerified(t *testing.T) {
	roster := &nipcash.CashStatusResult{Recipients: []nipcash.RecipientStatus{{IdentityType: "cash", AmountMillis: 1}}}

	got, err := claimFromStatus(roster, nil, signedKATToken(t), nipcash.NoLocalIdentity)
	if err != nil || got.MinterPubkey == nil || *got.MinterPubkey != katMinter {
		t.Fatalf("valid signature: got (%+v, %v), want MinterPubkey %s", got, err, katMinter)
	}

	bad := signedKATToken(t)
	bad.MintSignature = bad.MintSignature[:10]
	got, err = claimFromStatus(roster, nil, bad, nipcash.NoLocalIdentity)
	if err != nil || got.MinterPubkey != nil {
		t.Fatalf("malformed signature: got (%+v, %v), want no MinterPubkey", got, err)
	}
}

// Silence is never spent (NIP-CASH §Answering About a Destroyed Bill), and
// neither is NOT_FOUND or an empty roster.
func TestCheckClaim_OnlyATombstoneIsSpent(t *testing.T) {
	for name, tc := range map[string]struct {
		result *nipcash.CashStatusResult
		err    error
		want   error
	}{
		"timeout":      {nil, context.DeadlineExceeded, context.DeadlineExceeded},
		"omission":     {nil, &NotServedError{Method: nipcash.MethodCashStatus}, nil},
		"NOT_FOUND":    {nil, &relayclient.WalletError{Code: "NOT_FOUND"}, nipcash.ErrClaimNotFound},
		"empty roster": {&nipcash.CashStatusResult{}, nil, nipcash.ErrClaimNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := claimFromStatus(tc.result, tc.err, nipcash.Token{}, nipcash.NoLocalIdentity)
			if errors.Is(err, nipcash.ErrSpent) {
				t.Fatalf("err = %v, must not be ErrSpent", err)
			}
			if err == nil {
				t.Fatal("want an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
