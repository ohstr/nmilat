package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcash"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// CheckClaim confirms a matching, unclaimed recipient actually exists on
// c's own Cash Hub connection for tok — via nipcash.MatchClaimAuto, tried
// live against cash_status rather than gated on tok's own
// identity_required TLV (a stale-prone hint, not a live guarantee — see
// MatchClaimAuto). asPubkeyHex is the caller's own local pubkey if it
// has one; a cash-mode match is always attempted regardless. Returns
// nipcash.ErrClaimNotFound, not one of its own, if nothing matches.
//
// For a cash-mode token, a match only proves *some* unclaimed cash-mode
// recipient exists — cash_status carries no identity_value for a
// cash-mode entry, so this can never confirm the *specific* secret the
// caller holds is the one still valid (only redemption itself proves
// that). Don't read a successful CheckClaim as a stronger guarantee than
// the protocol actually gives for the cash-mode case.
//
// Deliberately a method, not a self-dialing package function: several
// callers (a transfer/consolidate/redeem already mid-flow) already hold
// a live, connected *Client for the same wallet by the time they need
// this check — a self-dialing version would force a wasteful second
// connection. Connect remains the only place a raw token/pairing string
// is ever consumed.
// cred is required because cash_status is: the private transport authorizes per item.
func (c *Client) CheckClaim(ctx context.Context, cred nipcash.Credential, tok nipcash.Token, asPubkeyHex string) (*nipcash.CheckClaimResult, error) {
	// ScopeMine: this looks up the CALLER's own row, which is exactly what the
	// default scope returns — asking for every co-recipient would be a larger reply
	// carrying strictly more than is needed.
	result, err := c.CashStatus(ctx, cred, nipcash.ScopeMine)
	if err != nil {
		// A hub that holds the bill but has no slice for this caller answers
		// NOT_FOUND. That is the same fact as an empty roster, so it becomes the same
		// sentinel — callers already branch on ErrClaimNotFound to say "this token
		// does not name you", and they should not each have to learn a wire code.
		//
		// Safe to collapse HERE specifically because CheckClaim only ever performs a
		// cash_status, where NOT_FOUND has exactly this one meaning. On the spend
		// methods it does not: there it can also be a wrong cash secret, which is why
		// that path reads the code itself rather than a sentinel.
		//
		// The hub only became able to answer at all once items carried a bill proof;
		// before that this was an information-free omission, indistinguishable from
		// an unreachable hub.
		var walletErr *relayclient.WalletError
		if errors.As(err, &walletErr) && walletErr.Code == "NOT_FOUND" {
			return nil, nipcash.ErrClaimNotFound
		}
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
		IsCash:              recipient.IsCash(),
		AmountMillis:        recipient.AmountMillis,
		MinterPubkey:        minterPubkey,
		RedeemFeeMillis:     recipient.RedeemFeeMillis,
		NetRedeemableMillis: recipient.NetRedeemableMillis,
		ExpiresAt:           recipient.ExpiresAt,
	}, nil
}
