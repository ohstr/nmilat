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
	// MintSignature opts the issued token into mint provenance (NIP-CASH
	// §Mint Provenance) — best-effort: a signing failure server-side is
	// never a reason to fail the mint, it just produces a token without the
	// signature.
	MintSignature bool
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
	Recipients    []RecipientParam `json:"recipients"`
	Expiry        int              `json:"expiry,omitempty"`
	MintSignature bool             `json:"mint_signature,omitempty"`
}

// Request builds mint_cash's wire request from p. Exported for
// nipcash/client's use; a caller using nipcash/client's MintCash method
// never calls this directly.
func (p MintCashParams) Request() (MintCashRequest, error) {
	hasBearer := false
	recipients := make([]RecipientParam, len(p.Recipients))
	for i, a := range p.Recipients {
		f := a.Recipient.(targetFields)
		if f.identityType() == identityTypeBearer {
			hasBearer = true
		}
		recipients[i] = RecipientParam{
			IdentityType:  f.identityType(),
			IdentityValue: f.identityValue(),
			IAPubkey:      f.iaPubkey(),
			AmountMillis:  a.AmountMillis,
		}
	}
	if hasBearer && len(recipients) > 1 {
		return MintCashRequest{}, ErrMixedBearerAllocation
	}
	return MintCashRequest{
		Recipients:    recipients,
		Expiry:        int(p.Expiry / time.Second),
		MintSignature: p.MintSignature,
	}, nil
}

// RecipientResult is one entry of mint_cash's wire "recipients" response
// array — the same shape as RecipientParam plus BearerSecret, present only
// for a bearer recipient's response entry.
type RecipientResult struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
	// BearerSecret appears in this response and nowhere else, ever
	// (NIP-CASH §Bearer Slices) — the only place a bearer recipient's
	// secret is returned.
	BearerSecret string `json:"bearer_secret,omitempty"`
}

// MintCashResult is mint_cash's response.
type MintCashResult struct {
	WalletPubkey string            `json:"wallet_pubkey"`
	PairingURI   string            `json:"pairing_uri"`
	CashToken    string            `json:"cash_token"`
	ExpiresAt    int64             `json:"expires_at,omitempty"`
	Recipients   []RecipientResult `json:"recipients"`
}
