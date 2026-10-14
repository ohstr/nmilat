package client

import (
	"context"
	"errors"
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
