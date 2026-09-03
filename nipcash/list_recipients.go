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

// ListRecipientsResult is list_recipients' response.
type ListRecipientsResult struct {
	Recipients []RecipientStatus `json:"recipients"`
}
