package nipcash

import "time"

// MintCashParams is mint_cash's friendly request — build with Send-paired
// Allocations. Called by the wallet owner over their own Cash Hub
// connection; unlike cash_redeem/cash_transfer/cash_consolidate, mint_cash
// needs no Credential, since the Hub's own connection is the proof.
type MintCashParams struct {
	Recipients []Allocation
	// Expiry is OPTIONAL. Zero means "use the Hub's own expiry ceiling" —
	// which itself may be "never" (NIP-CASH §Data Model) — never a
	// zero-duration, already-expired wallet.
	Expiry time.Duration
	// IdempotencyKey is OPTIONAL, and any caller that retries should set it.
	//
	// mint_cash is the one money method with no replay guard of its own:
	// cash_transfer and cash_consolidate sources carry a signed identity_event the
	// Hub refuses on replay, while these params are plain identity/amount fields
	// with no nonce. So a caller whose retry logic reads a timeout as "it failed"
	// resends the same logical request and the Hub mints and funds a SECOND wallet.
	//
	// A timeout does not mean the mint did not happen — the Hub's commit is durable
	// and complete before any response is built. With this set, a resend is REFUSED
	// and told which wallet it already created, instead of creating another.
	//
	// It is not a way to re-read a lost response: a cash-mode mint's secret exists
	// only in the reply the caller missed, and the Hub keeps a commitment rather
	// than the secret, so it genuinely cannot be reissued. What this prevents is
	// minting twice.
	IdempotencyKey string
}

// RecipientParam is one entry of mint_cash's wire "recipients" array
// (NIP-CASH.md §Minting Cash → Request).
type RecipientParam struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
}

// MintCashRequest is mint_cash's wire request shape.
type MintCashRequest struct {
	Recipients []RecipientParam `json:"recipients"`
	Expiry     int              `json:"expiry,omitempty"`
	// IdempotencyKey is omitted when unset, so a Hub that does not implement it sees
	// exactly the request it saw before and nothing changes for callers that do not
	// retry — see MintCashParams.IdempotencyKey.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// Request builds mint_cash's wire request from p. Exported for
// nipcash/client's use; a caller using nipcash/client's MintCash method
// never calls this directly.
func (p MintCashParams) Request() (MintCashRequest, error) {
	hasCash := false
	recipients := make([]RecipientParam, len(p.Recipients))
	for i, a := range p.Recipients {
		f := a.Recipient.(targetFields)
		if f.identityType() == identityTypeCash {
			hasCash = true
		}
		recipients[i] = RecipientParam{
			IdentityType:  f.identityType(),
			IdentityValue: f.identityValue(),
			IAPubkey:      f.iaPubkey(),
			AmountMillis:  a.AmountMillis,
		}
	}
	if hasCash && len(recipients) > 1 {
		return MintCashRequest{}, ErrMixedCashAllocation
	}
	return MintCashRequest{
		Recipients:     recipients,
		Expiry:         int(p.Expiry / time.Second),
		IdempotencyKey: p.IdempotencyKey,
	}, nil
}

// RecipientResult is one entry of mint_cash's wire "recipients" response
// array — the same shape as RecipientParam plus CashSecret, present only
// for a cash-mode recipient's response entry.
type RecipientResult struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
	// CashSecret appears in this response and nowhere else, ever
	// (NIP-CASH §Cash-Mode Slices) — the only place a cash-mode recipient's
	// secret is returned.
	CashSecret string `json:"cash_secret,omitempty"`
}

// MintCashResult is mint_cash's response.
type MintCashResult struct {
	WalletPubkey string            `json:"wallet_pubkey"`
	PairingURI   string            `json:"pairing_uri"`
	CashToken    string            `json:"cash_token"`
	ExpiresAt    int64             `json:"expires_at,omitempty"`
	Recipients   []RecipientResult `json:"recipients"`
}
