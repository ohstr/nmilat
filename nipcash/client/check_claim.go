package client

import (
	"context"

	"github.com/ohstr/nmilat/nipcash"
)

// CheckClaim confirms a matching, unclaimed recipient actually exists on
// c's own Cash Hub connection for tok — via nipcash.MatchClaimAuto, tried
// live against list_recipients rather than gated on tok's own
// identity_required TLV (a stale-prone hint, not a live guarantee — see
// MatchClaimAuto). asPubkeyHex is the caller's own local pubkey if it
// has one; a bearer match is always attempted regardless. Returns
// nipcash.ErrClaimNotFound, not one of its own, if nothing matches.
//
// For a bearer token, a match only proves *some* unclaimed bearer
// recipient exists — list_recipients carries no identity_value for a
// bearer entry, so this can never confirm the *specific* secret the
// caller holds is the one still valid (only redemption itself proves
// that). Don't read a successful CheckClaim as a stronger guarantee than
// the protocol actually gives for the bearer case.
//
// Deliberately a method, not a self-dialing package function: several
// callers (a transfer/consolidate/redeem already mid-flow) already hold
// a live, connected *Client for the same wallet by the time they need
// this check — a self-dialing version would force a wasteful second
// connection. Connect remains the only place a raw token/pairing string
// is ever consumed.
func (c *Client) CheckClaim(ctx context.Context, tok nipcash.Token, asPubkeyHex string) (*nipcash.CheckClaimResult, error) {
	result, err := c.ListRecipients(ctx)
	if err != nil {
		return nil, err
	}

	recipient, ok := nipcash.MatchClaimAuto(result.Recipients, asPubkeyHex)
	if !ok {
		return nil, nipcash.ErrClaimNotFound
	}

	var minterPubkey *string
	if tok.HasProvenance() {
		if minter, valid := nipcash.VerifyProvenance(tok); valid {
			minterPubkey = &minter
		}
	}

	return &nipcash.CheckClaimResult{
		IsBearer:            recipient.IsBearer(),
		AmountMillis:        recipient.AmountMillis,
		MinterPubkey:        minterPubkey,
		RedeemFeeMillis:     recipient.RedeemFeeMillis,
		NetRedeemableMillis: recipient.NetRedeemableMillis,
		ExpiresAt:           recipient.ExpiresAt,
	}, nil
}
