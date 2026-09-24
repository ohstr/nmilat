package nipcash

// RecipientStatus is one entry of list_recipients' response roster —
// includes every recipient this wallet was ever created or split into,
// claimed or not (NIP-CASH §Listing Recipients).
type RecipientStatus struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
	Claimed       bool   `json:"claimed"`
	ClaimedAt     *int64 `json:"claimed_at,omitempty"`
	// RedeemFeeMillis/NetRedeemableMillis are this slice's own worst-case
	// redeem-fee quote — a same-node cash_redeem pays out more (up to the
	// full AmountMillis, fee-free); it will never pay out less. See
	// NIP-CASH §The Redeem Fee.
	RedeemFeeMillis     uint64 `json:"redeem_fee_millis"`
	NetRedeemableMillis uint64 `json:"net_redeemable_millis"`
	// MinTransferMillis is this slice's own split floor (NIP-CASH §Splitting
	// a Slice), fixed at creation — check this before attempting a
	// CashTransfer split rather than discovering it from a rejected call.
	MinTransferMillis uint64 `json:"min_transfer_millis"`
	// ExpiresAt is the wallet's own shared redemption deadline — identical
	// on every row, omitted entirely for a wallet that never expires.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// CashStatusResult is cash_status' response, and carries one of two mutually
// exclusive answers.
//
// Recipients is the roster — every slice this bill was created or split into.
// It is deliberately NOT scoped to the caller's own slice, despite the method's
// name: every holder of the connection sees every row (NIP-CASH §Cash Status).
//
// Error/RetainedUntil is the tombstone for a bill that has been spent and
// destroyed. It exists because silence cannot be told apart from a Hub that is
// merely slow or unreachable, which forces every client to choose a wrong
// answer: treat the timeout as retryable and a genuinely spent bill retries
// forever, or treat it as gone and a reachable-Hub outage tells someone their
// funds are lost. Three outcomes replace two:
//
//	roster returned              -> available
//	Error "spent" + RetainedUntil -> definitive, and when the answer stops
//	no answer at all              -> indeterminate; retry, never report spent
//
// Past RetainedUntil the Hub falls back to silence, so the tombstone is never
// wrong — only absent for old bills.
type CashStatusResult struct {
	Recipients []RecipientStatus `json:"recipients,omitempty"`
	// Error is ErrorSpent, or empty on a roster response.
	Error string `json:"error,omitempty"`
	// RetainedUntil is the unix second past which this Hub stops answering
	// for this bill and returns to silence. Set whenever Error is.
	RetainedUntil *int64 `json:"retained_until,omitempty"`
}

// ErrorSpent is CashStatusResult.Error's only current value: this bill existed,
// was spent, and has been destroyed.
const ErrorSpent = "spent"

// IsSpent reports whether r is a tombstone rather than a roster.
func (r CashStatusResult) IsSpent() bool { return r.Error == ErrorSpent }

// ListRecipientsResult is the former name of CashStatusResult.
//
// Deprecated: use CashStatusResult.
type ListRecipientsResult = CashStatusResult

// IsCash reports whether r is a cash-mode recipient row — the one
// place identityTypeCash's own comparison lives, so a caller outside
// this package (nipcash/client's CheckClaim, say) never needs the
// unexported wire constant itself just to ask this question.
func (r RecipientStatus) IsCash() bool { return r.IdentityType == identityTypeCash }
