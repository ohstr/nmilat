package nipcash

import "encoding/json"

// CashTransferParams is cash_transfer's friendly request — reassigns an
// unredeemed slice's identity, in place or via a split, depending on To's
// type and history (NIP-CASH §Transferring and Splitting a Slice); the
// outcome is a server-side fact this package can't predict ahead of the
// call — see CashTransferResult's own doc comment for how to tell them
// apart.
type CashTransferParams struct {
	// Credential proves control of the slice's current registered identity.
	Credential Credential
	// To is who the slice (or the split-off piece) goes to: a
	// pubkey/connection_key Target (Pubkey/ConnectionKey) or a
	// *BearerTarget.
	To Target
	// CurrentAmount is the slice's exact current committed amount, in
	// millis — REQUIRED even for a full transfer: NIP-CASH's proof must
	// bind to a concrete amount in every case, including an omitted
	// request amount_millis, which still resolves to this exact value
	// server-side (§Transferring and Splitting a Slice). Get this from a
	// prior mint_cash/cash_transfer response or ListRecipients.
	CurrentAmount uint64
	// SplitAmount, if set, carves exactly that much off for To, leaving the
	// remainder (CurrentAmount - *SplitAmount) behind under the caller's
	// own unchanged identity. nil transfers the slice's entire
	// CurrentAmount.
	SplitAmount *uint64
	// MintSignature opts a spun-off wallet's token into mint provenance —
	// only meaningful when this call actually spins one off (a split, or a
	// full transfer to bearer on a multi-recipient-history wallet);
	// harmless no-op on an in-place reassignment.
	MintSignature bool
}

// cashTransferNewIdentityParam is the wire shape of cash_transfer's
// "new_identity" request field.
type cashTransferNewIdentityParam struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
}

// CashTransferRequest is cash_transfer's wire request shape.
type CashTransferRequest struct {
	IdentityType     string                       `json:"identity_type,omitempty"`
	IdentityValue    string                       `json:"identity_value,omitempty"`
	IdentityEvent    string                       `json:"identity_event,omitempty"`
	AttestationEvent string                       `json:"attestation_event,omitempty"`
	BearerSecret     string                       `json:"bearer_secret,omitempty"`
	NewIdentity      cashTransferNewIdentityParam `json:"new_identity"`
	AmountMillis     *uint64                      `json:"amount_millis,omitempty"`
	MintSignature    bool                         `json:"mint_signature,omitempty"`
}

// Request builds cash_transfer's wire request from p, bound to
// walletPubkey. Exported for nipcash/client's use; a caller using
// nipcash/client's CashTransfer method never calls this directly.
func (p CashTransferParams) Request(walletPubkey string) (CashTransferRequest, error) {
	f := p.To.(targetFields)
	amountBound := p.CurrentAmount
	if p.SplitAmount != nil {
		amountBound = *p.SplitAmount
	}
	binding := proofBinding{
		WalletPubkey:    walletPubkey,
		NewIdentityHash: newIdentityHash(p.To),
		AmountMillis:    &amountBound,
	}
	identityType, identityValue, identityEvent, attestationEvent, bearerSecret, err := p.Credential.buildProof(binding)
	if err != nil {
		return CashTransferRequest{}, err
	}
	req := CashTransferRequest{
		IdentityType:  identityType,
		IdentityValue: identityValue,
		BearerSecret:  bearerSecret,
		NewIdentity: cashTransferNewIdentityParam{
			IdentityType:  f.identityType(),
			IdentityValue: f.identityValue(),
			IAPubkey:      f.iaPubkey(),
		},
		AmountMillis:  p.SplitAmount,
		MintSignature: p.MintSignature,
	}
	if identityEvent != nil {
		req.IdentityEvent = string(identityEvent)
	}
	if attestationEvent != nil {
		req.AttestationEvent = string(attestationEvent)
	}
	return req, nil
}

// cashTransferResponseWire is cash_transfer's raw wire response — its
// *_wallet_token fields are still NIP-44 nested-encrypted at this point;
// ParseResult decrypts them into CashTransferResult.
type cashTransferResponseWire struct {
	AmountMillis          uint64  `json:"amount_millis"`
	IdentityType          string  `json:"identity_type"`
	IdentityValue         string  `json:"identity_value,omitempty"`
	RemainingAmountMillis *uint64 `json:"remaining_amount_millis,omitempty"`
	NewWalletPubkey       string  `json:"new_wallet_pubkey,omitempty"`
	NewWalletToken        string  `json:"new_wallet_token,omitempty"`
	RemainderWalletPubkey string  `json:"remainder_wallet_pubkey,omitempty"`
	RemainderWalletToken  string  `json:"remainder_wallet_token,omitempty"`
}

// CashTransferResult is cash_transfer's response, with any *_wallet_token
// already decrypted into a plain cash token string.
//
// Telling the outcome apart: NewWalletToken == "" means the slice was
// reassigned in place — the recipient already has everything they need via
// the SAME cash token the caller originally held, now registered to the new
// identity. NewWalletToken != "" and RemainderWalletToken == "" means a
// full transfer spun off one new wallet (a bearer target on a
// multi-recipient-history wallet) — hand NewWalletToken (and, for a bearer
// target, the BearerTarget's own Secret()) to the recipient. Both set means
// a partial split: RemainderWalletToken is the caller's own new token (the
// old one is now dead), NewWalletToken is the carved-off piece for the
// recipient.
type CashTransferResult struct {
	AmountMillis          uint64
	IdentityType          string
	IdentityValue         string
	RemainingAmountMillis *uint64
	NewWalletPubkey       string
	NewWalletToken        string
	RemainderWalletPubkey string
	RemainderWalletToken  string
}

// ParseResult parses cash_transfer's wire response, decrypting any
// *_wallet_token field with p.Credential's own privkey (see Credential's
// decryptDelivery doc comment for why a bearer credential's tokens instead
// pass through unchanged). Exported for nipcash/client's use; a caller
// using nipcash/client's CashTransfer method never calls this directly.
func (p CashTransferParams) ParseResult(data []byte) (*CashTransferResult, error) {
	var wire cashTransferResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	result := &CashTransferResult{
		AmountMillis:          wire.AmountMillis,
		IdentityType:          wire.IdentityType,
		IdentityValue:         wire.IdentityValue,
		RemainingAmountMillis: wire.RemainingAmountMillis,
		NewWalletPubkey:       wire.NewWalletPubkey,
		RemainderWalletPubkey: wire.RemainderWalletPubkey,
	}
	if wire.NewWalletToken != "" {
		token, err := p.Credential.decryptDelivery(wire.NewWalletPubkey, wire.NewWalletToken)
		if err != nil {
			return nil, err
		}
		result.NewWalletToken = token
	}
	if wire.RemainderWalletToken != "" {
		token, err := p.Credential.decryptDelivery(wire.RemainderWalletPubkey, wire.RemainderWalletToken)
		if err != nil {
			return nil, err
		}
		result.RemainderWalletToken = token
	}
	return result, nil
}
