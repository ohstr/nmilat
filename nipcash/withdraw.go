package nipcash

import (
	"encoding/json"
	"errors"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// CashWithdrawParams is cash_withdraw's friendly request: the quote the caller
// verified (VerifyQuoteAnswer) and its user confirmed, the slice's credential,
// the call's request_id and notify, and for a cash-mode slice (a BySecret
// credential) the fresh cash target the payout is re-minted to if it is
// cancelled.
type CashWithdrawParams struct {
	Quote      *WithdrawQuote
	Credential Credential
	RequestID  string
	// Notify is 64 lowercase hex, fresh per call, kept when re-placed.
	Notify string
	// Remint is required for a BySecret credential and refused for any other.
	Remint *CashTarget
}

// CashWithdrawRequest is cash_withdraw's wire request.
type CashWithdrawRequest struct {
	Quote            string `json:"quote"`
	RequestID        string `json:"request_id"`
	Notify           string `json:"notify"`
	RemintCommitment string `json:"remint_commitment,omitempty"`
	IdentityType     string `json:"identity_type,omitempty"`
	IdentityValue    string `json:"identity_value,omitempty"`
	IdentityEvent    string `json:"identity_event,omitempty"`
	AttestationEvent string `json:"attestation_event,omitempty"`
	CashSecret       string `json:"cash_secret,omitempty"`
}

var (
	// ErrRemintRequired is a cash-mode withdrawal without its re-mint target.
	ErrRemintRequired = errors.New("nipcash: a cash-mode withdrawal needs a fresh re-mint target")
	// ErrRemintForbidden is a re-mint target on a slice that is not cash-mode,
	// or one equal to the slice's own commitment.
	ErrRemintForbidden = errors.New("nipcash: a re-mint target is only for a cash-mode slice, and never its own commitment")
)

// Request builds cash_withdraw's wire request for the bill walletPubkey: the
// quote as a JSON string, request_id, notify, remint_commitment for a cash-mode
// slice, and the proof fields as cash_redeem's, the claim proof carrying m =
// cash_withdraw and q = the quote's id.
func (p CashWithdrawParams) Request(walletPubkey string) (CashWithdrawRequest, error) {
	if p.Quote == nil || p.Quote.Event == nil {
		return CashWithdrawRequest{}, errors.New("nipcash: cash_withdraw needs a quote")
	}
	if p.Quote.Wallet != walletPubkey {
		return CashWithdrawRequest{}, errors.New("nipcash: the quote is for another bill")
	}
	if !ValidRequestID(p.RequestID) {
		return CashWithdrawRequest{}, errors.New("nipcash: cash_withdraw needs a request_id")
	}
	if !isLowerHex64(p.Notify) {
		return CashWithdrawRequest{}, errors.New("nipcash: notify is 64 lowercase hex")
	}
	raw, err := p.Quote.Raw()
	if err != nil {
		return CashWithdrawRequest{}, err
	}
	req := CashWithdrawRequest{Quote: raw, RequestID: p.RequestID, Notify: p.Notify}
	if s, ok := p.Credential.(secretCredential); ok {
		if p.Remint == nil {
			return CashWithdrawRequest{}, ErrRemintRequired
		}
		own, err := CashCommitment(s.secret)
		if err != nil {
			return CashWithdrawRequest{}, err
		}
		if CommitmentsEqual(own, p.Remint.Commitment()) {
			return CashWithdrawRequest{}, ErrRemintForbidden
		}
		req.RemintCommitment = p.Remint.Commitment()
	} else if p.Remint != nil {
		return CashWithdrawRequest{}, ErrRemintForbidden
	}
	if p.Credential == nil {
		return CashWithdrawRequest{}, errors.New("nipcash: cash_withdraw needs the slice's credential")
	}
	binding := ClaimBinding{Method: MethodCashWithdraw, Wallet: walletPubkey, QuoteID: p.Quote.ID}
	identityType, identityValue, identityEvent, attestationEvent, cashSecret, err := p.Credential.buildProof(binding)
	if err != nil {
		return CashWithdrawRequest{}, err
	}
	req.IdentityType, req.IdentityValue, req.CashSecret = identityType, identityValue, cashSecret
	if identityEvent != nil {
		req.IdentityEvent = string(identityEvent)
	}
	if attestationEvent != nil {
		req.AttestationEvent = string(attestationEvent)
	}
	return req, nil
}

// Item builds the cash_withdraw item against the bill target: the item proof
// by the claim key (a bearer item for BySecret), the bill proof by connSecret.
func (p CashWithdrawParams) Item(id, target, connSecret string, b ItemBinding) (transport.Item, error) {
	req, err := p.Request(target)
	if err != nil {
		return transport.Item{}, err
	}
	return buildItem(id, target, connSecret, MethodCashWithdraw, req, p.Credential, b)
}

// Pending is the call to write ahead for this withdrawal of the bill target:
// the quote, its address, amount and holds_until, notify, the re-mint secret
// (role "remint"), the bearer secret authorizing it, and the wire request as
// Params (no secret).
func (p CashWithdrawParams) Pending(target string) (PendingCall, error) {
	req, err := p.Request(target)
	if err != nil {
		return PendingCall{}, err
	}
	raw, err := withoutSecrets(req)
	if err != nil {
		return PendingCall{}, err
	}
	return PendingCall{
		RequestID: p.RequestID, Method: MethodCashWithdraw, Target: target,
		Secrets: targetSecrets(p.Remint, SecretRoleRemint), SourceSecret: bearerSecret(p.Credential),
		Amount: p.Quote.AmountMillis, Notify: p.Notify, Address: p.Quote.Address, Quote: req.Quote,
		HoldsUntil: p.Quote.HoldsUntil, Params: raw,
	}, nil
}

// SecretRoleRemint is the role of a cancelled withdrawal's re-mint secret.
const SecretRoleRemint = "remint"

// WithdrawSlice is what a Hub's own records say of the slice a cash_withdraw
// names: whether it is cash-mode, and its commitment when it is.
type WithdrawSlice struct {
	CashMode   bool
	Commitment string
}

// ParseCashWithdrawRequest is the Hub's check before step 1 (NIP-CASH
// §Request): a *WithdrawError with code BAD_REQUEST for a malformed request_id
// (I6's, first), a missing or malformed quote or notify, a remint_commitment
// missing on a cash-mode slice, present on another, malformed or equal to the
// slice's own, and any of invoice, amount or idempotency_key. Other keys are
// ignored.
func ParseCashWithdrawRequest(raw json.RawMessage, s WithdrawSlice) (*CashWithdrawRequest, error) {
	bad := func(reason string) error { return withdrawErr(ErrCodeBadRequest, "", 0, reason) }
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, bad("params are not an object")
	}
	str := func(k string) (string, bool, error) {
		v, ok := fields[k]
		if !ok {
			return "", false, nil
		}
		var out string
		if err := json.Unmarshal(v, &out); err != nil {
			return "", true, bad(k + " is not a string")
		}
		return out, true, nil
	}
	rid, _, err := str("request_id")
	if err != nil {
		return nil, err
	}
	if !ValidRequestID(rid) {
		return nil, bad("malformed request_id")
	}
	for _, k := range []string{"invoice", "amount", "idempotency_key"} {
		if _, ok := fields[k]; ok {
			return nil, bad(k + " is not allowed")
		}
	}
	req := &CashWithdrawRequest{RequestID: rid}
	var ok bool
	if req.Quote, ok, err = str("quote"); err != nil {
		return nil, err
	} else if !ok {
		return nil, bad("missing quote")
	}
	if _, err := ParseWithdrawQuote(req.Quote); err != nil {
		return nil, bad("malformed quote")
	}
	if req.Notify, _, err = str("notify"); err != nil {
		return nil, err
	} else if !isLowerHex64(req.Notify) {
		return nil, bad("malformed notify")
	}
	rc, has, err := str("remint_commitment")
	if err != nil {
		return nil, err
	}
	switch {
	case s.CashMode && !has:
		return nil, bad("missing remint_commitment")
	case !s.CashMode && has:
		return nil, bad("remint_commitment on a slice that is not cash-mode")
	case has && !ValidCommitment(rc):
		return nil, bad("malformed remint_commitment")
	case has && CommitmentsEqual(rc, s.Commitment):
		return nil, bad("remint_commitment is the slice's own")
	}
	req.RemintCommitment = rc
	for _, f := range []struct {
		k   string
		dst *string
	}{{"identity_type", &req.IdentityType}, {"identity_value", &req.IdentityValue}, {"identity_event", &req.IdentityEvent},
		{"attestation_event", &req.AttestationEvent}, {"cash_secret", &req.CashSecret}} {
		if *f.dst, _, err = str(f.k); err != nil {
			return nil, err
		}
	}
	return req, nil
}
