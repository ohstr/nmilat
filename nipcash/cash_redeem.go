package nipcash

import (
	"fmt"

	"github.com/ohstr/nmilat/nip57"
)

// CashRedeemParams is cash_redeem's friendly request.
type CashRedeemParams struct {
	// Invoice is a fresh Lightning invoice the caller generated, for
	// exactly the slice's committed amount minus its own redeem_fee_ppm
	// cut, or the full amount if the redemption resolves to a same-node
	// payment — see NIP-CASH §Redeeming a Slice's own invoice-amount
	// guidance; this package cannot resolve that ambiguity on the caller's
	// behalf.
	Invoice string
	// Credential proves control of the slice being redeemed. BySecret for
	// a bearer slice; BySigning/BySigningConnectionKey for an
	// identity-bound one.
	Credential Credential
	// Amount OPTIONALLY overrides an amountless invoice's amount, mirroring
	// pay_invoice. nil uses the invoice's own encoded amount.
	Amount *uint64
}

// CashRedeemRequest is cash_redeem's wire request shape.
type CashRedeemRequest struct {
	Invoice          string  `json:"invoice"`
	Amount           *uint64 `json:"amount,omitempty"`
	IdentityType     string  `json:"identity_type,omitempty"`
	IdentityValue    string  `json:"identity_value,omitempty"`
	IdentityEvent    string  `json:"identity_event,omitempty"`
	AttestationEvent string  `json:"attestation_event,omitempty"`
	BearerSecret     string  `json:"bearer_secret,omitempty"`
}

// Request builds cash_redeem's wire request from p, bound to walletPubkey
// (the Cash Wallet connection's own pubkey — cashclient supplies this).
// Exported for nipcash/client's use; a caller using nipcash/client's
// CashRedeem method never calls this directly.
func (p CashRedeemParams) Request(walletPubkey string) (CashRedeemRequest, error) {
	invoice, err := nip57.DecodeBolt11(p.Invoice)
	if err != nil {
		return CashRedeemRequest{}, fmt.Errorf("nipcash: decode invoice: %w", err)
	}
	binding := proofBinding{WalletPubkey: walletPubkey, Bolt11Hash: invoice.PaymentHash}
	identityType, identityValue, identityEvent, attestationEvent, bearerSecret, err := p.Credential.buildProof(binding)
	if err != nil {
		return CashRedeemRequest{}, err
	}
	req := CashRedeemRequest{
		Invoice:       p.Invoice,
		Amount:        p.Amount,
		IdentityType:  identityType,
		IdentityValue: identityValue,
		BearerSecret:  bearerSecret,
	}
	if identityEvent != nil {
		req.IdentityEvent = string(identityEvent)
	}
	if attestationEvent != nil {
		req.AttestationEvent = string(attestationEvent)
	}
	return req, nil
}

// CashRedeemResult is cash_redeem's response.
type CashRedeemResult struct {
	Preimage string `json:"preimage"`
	// FeesPaid is the recipient's own borne redeem fee (zero for a
	// same-node redemption) — never the real Lightning routing cost, which
	// is never charged to the recipient (NIP-CASH §The Redeem Fee).
	FeesPaid uint64 `json:"fees_paid"`
}
