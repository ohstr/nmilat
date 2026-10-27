package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Cash-status scopes (NIP-CASH §Scoping the Roster). Absent means mine.
const (
	// ScopeAll returns every recipient's row — the shared roster.
	ScopeAll = "all"
	// ScopeMine returns only the calling recipient's own row.
	ScopeMine = "mine"
)

// CashStatusParams is cash_status' request. A cash-mode bill's item carries no
// proof and no cash_secret (a Hub refuses one that does); its bill proof alone
// names the row.
type CashStatusParams struct {
	Scope string `json:"scope,omitempty"`
}

// CashStatusRequest is cash_status' wire request.
type CashStatusRequest struct {
	Scope string `json:"scope,omitempty"`
}

// IsValidCashStatusScope reports a scope a Hub honours: "", mine or all.
func IsValidCashStatusScope(s string) bool {
	return s == "" || s == ScopeAll || s == ScopeMine
}

// ErrStatusMalformed is a cash_status answer that does not have the spec's shape.
var ErrStatusMalformed = errors.New("nipcash: malformed cash_status answer")

// RecipientStatus is one row of the roster.
type RecipientStatus struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
	Claimed       bool   `json:"claimed"`
	ClaimedAt     *int64 `json:"claimed_at,omitempty"`
	// RedeemFeeMillis/NetRedeemableMillis are the slice's own worst-case redeem
	// quote (NIP-CASH §The Redeem Fee); a same-node redeem pays the full amount.
	RedeemFeeMillis     uint64 `json:"redeem_fee_millis"`
	NetRedeemableMillis uint64 `json:"net_redeemable_millis"`
	// MinTransferMillis is the slice's own split floor, fixed at creation.
	MinTransferMillis uint64 `json:"min_transfer_millis"`
	// ExpiresAt is the wallet's deadline, the same on every row; never when absent.
	ExpiresAt Expiry `json:"expires_at"`
	// WithdrawRequestID names the cash_withdraw that ended this slice, shown to
	// that call's authorizer only; a row carrying it is terminal.
	WithdrawRequestID string `json:"withdraw_request_id,omitempty"`
}

// IsCash reports a cash-mode row.
func (r RecipientStatus) IsCash() bool { return r.IdentityType == identityTypeCash }

// CashStatusResult is cash_status' answer: the roster, or the tombstone of a
// destroyed bill. Withdraw is the Hub's withdrawal terms, when it offers them.
type CashStatusResult struct {
	Recipients []RecipientStatus `json:"recipients,omitempty"`
	Withdraw   *WithdrawTerms    `json:"withdraw,omitempty"`
	Tombstone  *Tombstone        `json:"-"`
}

// ParseCashStatusResult reads a cash_status answer: a tombstone, or a roster
// whose rows each have a known identity_type and lowercase hex values (a row of
// any other type, such as bearer, is malformed).
func ParseCashStatusResult(data []byte) (*CashStatusResult, error) {
	if t, ok := ParseTombstone(data); ok {
		return &CashStatusResult{Tombstone: t}, nil
	}
	var r CashStatusResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatusMalformed, err)
	}
	for i, row := range r.Recipients {
		switch row.IdentityType {
		case identityTypePubkey, identityTypeCash, identityTypeConnectionKey:
		default:
			return nil, fmt.Errorf("%w: row %d has identity_type %q", ErrStatusMalformed, i, row.IdentityType)
		}
		if !isLowerHex64(row.IdentityValue) {
			return nil, fmt.Errorf("%w: row %d identity_value is not 64 lowercase hex", ErrStatusMalformed, i)
		}
		if row.IdentityType == identityTypeConnectionKey && !isLowerHex64(row.IAPubkey) {
			return nil, fmt.Errorf("%w: row %d connection_key without ia_pubkey", ErrStatusMalformed, i)
		}
	}
	if r.Withdraw != nil {
		if err := r.Withdraw.Validate(); err != nil {
			return nil, fmt.Errorf("%w: withdraw: %v", ErrStatusMalformed, err)
		}
	}
	return &r, nil
}
