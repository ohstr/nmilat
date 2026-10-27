package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrZapCashSource       = errors.New("nipcash: a zap transfer's source is bound to a pubkey, never cash")
	ErrZapCKSource         = errors.New("nipcash: a zap transfer's source is bound to a pubkey, never a connection_key")
	ErrZapTargetIdentity   = errors.New("nipcash: a zap transfer's new_identity is a pubkey")
	ErrRemainderCommitment = errors.New("nipcash: remainder_commitment is required for, and only for, a partial split of a cash source, and differs from the source's")
	ErrSplitAmount         = errors.New("nipcash: a split amount is positive and at most the slice's amount")
)

// CashTransferParams is cash_transfer's request (NIP-CASH §Transferring and
// Splitting a Slice). RequestID is REQUIRED.
type CashTransferParams struct {
	// Credential proves control of the slice's current registered identity.
	Credential Credential
	// To is new_identity: a pubkey or connection_key Target, or a *CashTarget.
	To Target
	// CurrentAmount is the slice's committed amount; the claim proof binds it
	// for a full transfer.
	CurrentAmount uint64
	// SplitAmount, when set below CurrentAmount, carves that much off for To.
	SplitAmount *uint64
	// ZapTarget, when set, makes this a zap transfer (NIP-CZ): a pubkey source
	// and a pubkey To only.
	ZapTarget string
	// RemainderTarget is the fresh cash target the remainder takes on a partial
	// split of a cash source; required then and refused otherwise. The SDK's
	// send paths generate one when it is nil (WithRemainder).
	RemainderTarget *CashTarget
	RequestID       string
}

// SecretRoleRemainder is the role of a split's remainder secret in a written-
// ahead call.
const SecretRoleRemainder = "remainder"

// NeedsRemainder reports a partial split of a cash source: SplitAmount below
// CurrentAmount, authorized by a cash secret. Such a call carries a
// remainder_commitment (NIP-CASH §Transferring and Splitting a Slice).
func (p CashTransferParams) NeedsRemainder() bool {
	_, isCash := p.Credential.(secretCredential)
	return isCash && p.SplitAmount != nil && *p.SplitAmount < p.CurrentAmount
}

// WithRemainder returns p with a fresh RemainderTarget when it NeedsRemainder
// and has none; otherwise p unchanged (a caller-supplied target is kept, and
// Request checks it).
func (p CashTransferParams) WithRemainder() (CashTransferParams, error) {
	if !p.NeedsRemainder() || p.RemainderTarget != nil {
		return p, nil
	}
	t, err := NewCashTarget()
	if err != nil {
		return p, err
	}
	p.RemainderTarget = t
	return p, nil
}

// cashTransferNewIdentityParam is the wire shape of new_identity.
type cashTransferNewIdentityParam struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
}

// CashTransferRequest is cash_transfer's wire request, the type a Hub decodes.
// ZapTarget is nil when absent; a present empty one a Hub refuses BAD_REQUEST.
type CashTransferRequest struct {
	IdentityType        string                       `json:"identity_type,omitempty"`
	IdentityValue       string                       `json:"identity_value,omitempty"`
	IdentityEvent       string                       `json:"identity_event,omitempty"`
	AttestationEvent    string                       `json:"attestation_event,omitempty"`
	CashSecret          string                       `json:"cash_secret,omitempty"`
	NewIdentity         cashTransferNewIdentityParam `json:"new_identity"`
	AmountMillis        *uint64                      `json:"amount_millis,omitempty"`
	ZapTarget           *string                      `json:"zap_target,omitempty"`
	RemainderCommitment string                       `json:"remainder_commitment,omitempty"`
	RequestID           string                       `json:"request_id"`
}

// Request builds the wire request bound to walletPubkey.
func (p CashTransferParams) Request(walletPubkey string) (CashTransferRequest, error) {
	if !ValidRequestID(p.RequestID) {
		return CashTransferRequest{}, ErrRequestIDRequired
	}
	f, ok := p.To.(targetFields)
	if !ok || p.To == nil {
		return CashTransferRequest{}, ErrTransferTargetInvalid
	}
	if err := checkIAPubkey(f); err != nil {
		return CashTransferRequest{}, err
	}
	_, isCash := p.Credential.(secretCredential)
	_, isCK := p.Credential.(connectionKeyCredential)
	if p.SplitAmount != nil && (*p.SplitAmount == 0 || *p.SplitAmount > p.CurrentAmount) {
		return CashTransferRequest{}, ErrSplitAmount
	}
	partial := p.SplitAmount != nil && *p.SplitAmount < p.CurrentAmount
	if p.ZapTarget != "" {
		switch {
		case isCash:
			return CashTransferRequest{}, ErrZapCashSource
		case isCK:
			return CashTransferRequest{}, ErrZapCKSource
		case f.identityType() != identityTypePubkey:
			return CashTransferRequest{}, ErrZapTargetIdentity
		}
	}
	remainder := ""
	switch {
	case partial && isCash:
		if p.RemainderTarget == nil {
			return CashTransferRequest{}, ErrRemainderCommitment
		}
		source, err := CashTargetFromSecret(p.Credential.(secretCredential).secret)
		if err != nil {
			return CashTransferRequest{}, err
		}
		if CommitmentsEqual(source.Commitment(), p.RemainderTarget.Commitment()) {
			return CashTransferRequest{}, ErrRemainderCommitment
		}
		remainder = p.RemainderTarget.Commitment()
	case p.RemainderTarget != nil:
		return CashTransferRequest{}, ErrRemainderCommitment
	}

	amountBound := p.CurrentAmount
	if p.SplitAmount != nil {
		amountBound = *p.SplitAmount
	}
	binding := ClaimBinding{Method: MethodCashTransfer, Wallet: walletPubkey, NewIdentityHash: newIdentityHash(p.To), AmountMillis: &amountBound}
	identityType, identityValue, identityEvent, attestationEvent, cashSecret, err := p.Credential.buildProof(binding)
	if err != nil {
		return CashTransferRequest{}, err
	}
	req := CashTransferRequest{
		IdentityType: identityType, IdentityValue: identityValue, CashSecret: cashSecret,
		NewIdentity:         cashTransferNewIdentityParam{IdentityType: f.identityType(), IdentityValue: f.identityValue(), IAPubkey: f.iaPubkey()},
		AmountMillis:        p.SplitAmount,
		RemainderCommitment: remainder,
		RequestID:           p.RequestID,
	}
	if p.ZapTarget != "" {
		z := p.ZapTarget
		req.ZapTarget = &z
	}
	if identityEvent != nil {
		req.IdentityEvent = string(identityEvent)
	}
	if attestationEvent != nil {
		req.AttestationEvent = string(attestationEvent)
	}
	return req, nil
}

// cashTransferResponseWire is the raw response; tokens are still nested-encrypted.
type cashTransferResponseWire struct {
	AmountMillis          uint64           `json:"amount_millis"`
	IdentityType          string           `json:"identity_type"`
	IdentityValue         string           `json:"identity_value,omitempty"`
	RemainingAmountMillis *uint64          `json:"remaining_amount_millis,omitempty"`
	NewWalletPubkey       string           `json:"new_wallet_pubkey,omitempty"`
	NewWalletToken        TokenOrTombstone `json:"new_wallet_token"`
	RemainderWalletPubkey string           `json:"remainder_wallet_pubkey,omitempty"`
	RemainderWalletToken  TokenOrTombstone `json:"remainder_wallet_token"`
	IssuedAt              *uint64          `json:"issued_at,omitempty"`
	ExpiresAt             *uint64          `json:"expires_at,omitempty"`
}

// CashTransferResult is cash_transfer's response with every token decrypted.
//
// NewWalletToken "" means the slice was reassigned in place; NewWalletToken set
// and RemainderWalletToken "" a one-wallet spin-off; both set a partial split.
// IssuedAt and ExpiresAt are a zap bill's signed values (ExpiresAt 0 = never).
// The tombstone fields are set only by ParseLookupResult, for a created bill
// already destroyed.
type CashTransferResult struct {
	AmountMillis             uint64
	IdentityType             string
	IdentityValue            string
	RemainingAmountMillis    *uint64
	NewWalletPubkey          string
	NewWalletToken           string
	RemainderWalletPubkey    string
	RemainderWalletToken     string
	IssuedAt                 *uint64
	ExpiresAt                *uint64
	NewWalletTombstone       *Tombstone
	RemainderWalletTombstone *Tombstone
}

// ZapSigned reports a zap transfer's reply carrying the signed issued_at and
// expires_at a Cash Zap needs. A reply missing them still keeps its tokens.
func (r *CashTransferResult) ZapSigned() bool { return r.IssuedAt != nil && r.ExpiresAt != nil }

// RecipientToken is the token the recipient needs: the new wallet's for a
// spin-off, else (in place) the original token. A spin-off always carries its
// token (NIP-CASH §cash_transfer), so one without it is an error: a *BillGone
// when a lookup answered the new bill's tombstone, a malformed reply otherwise.
func (r *CashTransferResult) RecipientToken(originalToken string) (string, error) {
	switch {
	case r.NewWalletToken != "":
		return r.NewWalletToken, nil
	case r.NewWalletTombstone != nil:
		return "", &BillGone{Method: MethodCashTransfer, Tombstone: *r.NewWalletTombstone}
	case r.NewWalletPubkey != "":
		return "", fmt.Errorf("nipcash: the spin-off %s carries no token", r.NewWalletPubkey)
	default:
		return originalToken, nil
	}
}

// ParseResult reads a direct cash_transfer reply: a tombstone is *BillGone; a
// cash_secret or secret key is refused; a tombstone in a token field is
// ErrTombstoneInReply.
func (p CashTransferParams) ParseResult(data []byte) (*CashTransferResult, error) {
	r, err := p.parse(data)
	if err == nil && (r.NewWalletTombstone != nil || r.RemainderWalletTombstone != nil) {
		return r, ErrTombstoneInReply
	}
	return r, err
}

// ParseLookupResult reads a lookup's done result for a transfer.
func (p CashTransferParams) ParseLookupResult(data []byte) (*CashTransferResult, error) {
	return p.parse(data)
}

func (p CashTransferParams) parse(data []byte) (*CashTransferResult, error) {
	if err := goneIf(MethodCashTransfer, data); err != nil {
		return nil, err
	}
	if hasKey(data, "cash_secret") || hasKey(data, "secret") {
		return nil, ErrHubReturnedSecret
	}
	var w cashTransferResponseWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	r := &CashTransferResult{AmountMillis: w.AmountMillis, IdentityType: w.IdentityType, IdentityValue: w.IdentityValue,
		RemainingAmountMillis: w.RemainingAmountMillis, NewWalletPubkey: w.NewWalletPubkey, RemainderWalletPubkey: w.RemainderWalletPubkey,
		IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt,
		NewWalletTombstone: w.NewWalletToken.Tombstone, RemainderWalletTombstone: w.RemainderWalletToken.Tombstone}
	if w.NewWalletToken.Token != "" {
		token, err := p.Credential.decryptDelivery(w.NewWalletPubkey, w.NewWalletToken.Token)
		if err != nil {
			return nil, err
		}
		r.NewWalletToken = token
	}
	if w.RemainderWalletToken.Token != "" {
		token, err := p.Credential.decryptDelivery(w.RemainderWalletPubkey, w.RemainderWalletToken.Token)
		if err != nil {
			return nil, err
		}
		r.RemainderWalletToken = token
	}
	return r, nil
}
