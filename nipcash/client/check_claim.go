package client

import (
	"context"
	"errors"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// CheckClaim reads the caller's own row of tok's bill and says whether it can be
// spent. The row is found from cred, never from the caller's word (nipcash.OwnRow):
// a pubkey, a connection_key with its IA, or the cash row the secret commits to.
// A Hub that holds the bill but no slice for the caller answers NOT_FOUND, which
// is nipcash.ErrClaimNotFound; a destroyed bill is *nipcash.BillGone; a spent or
// withdrawn slice is a row that is not claimable, never "not found". MinterXOnly
// is set only from a verified provenance.
func (c *Client) CheckClaim(ctx context.Context, cred nipcash.Credential, tok nipcash.Token) (*nipcash.CheckClaimResult, error) {
	result, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	return claimFromStatus(result, err, tok, cred, time.Now().Unix())
}

// claimFromStatus is CheckClaim's decision, separated from the round trip.
func claimFromStatus(result *nipcash.CashStatusResult, err error, tok nipcash.Token, cred nipcash.Credential, now int64) (*nipcash.CheckClaimResult, error) {
	if err != nil {
		var walletErr *relayclient.WalletError
		if errors.As(err, &walletErr) && walletErr.Code == "NOT_FOUND" {
			return nil, nipcash.ErrClaimNotFound
		}
		return nil, err
	}
	if result == nil {
		return nil, errors.New("nipcash/client: cash_status returned no result")
	}
	if result.Tombstone != nil {
		return nil, &nipcash.BillGone{Method: nipcash.MethodCashStatus, Tombstone: *result.Tombstone}
	}
	row, err := nipcash.OwnRow(result.Recipients, cred, nipcash.ScopeMine)
	if err != nil {
		return nil, err
	}
	ok, reason := nipcash.Claimable(row, now)
	out := &nipcash.CheckClaimResult{Row: row, Claimable: ok, Reason: reason}
	if minter, valid := nipcash.VerifyProvenance(tok); valid {
		out.MinterXOnly, _ = nipcash.MinterXOnly(minter)
	}
	return out, nil
}
