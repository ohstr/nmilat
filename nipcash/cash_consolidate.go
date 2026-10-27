package nipcash

import (
	"encoding/json"
	"fmt"
)

// CashConsolidateParams is cash_consolidate's friendly request — combines
// several same-hub slices this node custodies into one new cash token
// (NIP-CASH §Consolidating Tokens).
type CashConsolidateParams struct {
	// Sources MUST contain at least two distinct sources (ErrTooFewSources),
	// none cash-mode (ErrCashSource — cash-mode sources remain
	// rejected: a cash secret has no signature and no binding to the
	// request carrying it, unlike a connection_key source's signed
	// identity_event + attestation_event, which this revision does accept).
	Sources []Source
	// To is who the merged wallet belongs to — any Target (pubkey,
	// connection_key, or a *CashTarget) is accepted; ErrConsolidateTargetInvalid
	// only if left nil.
	To Target
	// RequestID is REQUIRED.
	RequestID string
}

// consolidateSourceParam is the wire shape of one entry in cash_consolidate's
// "sources" request array.
type consolidateSourceParam struct {
	WalletPubkey     string `json:"wallet_pubkey"`
	IdentityType     string `json:"identity_type,omitempty"`
	IdentityValue    string `json:"identity_value,omitempty"`
	IdentityEvent    string `json:"identity_event,omitempty"`
	AttestationEvent string `json:"attestation_event,omitempty"`
	CashSecret       string `json:"cash_secret,omitempty"`
}

// CashConsolidateRequest is cash_consolidate's wire request shape.
type CashConsolidateRequest struct {
	Sources     []consolidateSourceParam     `json:"sources"`
	NewIdentity cashTransferNewIdentityParam `json:"new_identity"`
	RequestID   string                       `json:"request_id"`
}

// Request builds cash_consolidate's wire request from p. Exported for
// nipcash/client's use; a caller using nipcash/client's CashConsolidate
// method never calls this directly.
func (p CashConsolidateParams) Request() (CashConsolidateRequest, error) {
	if !ValidRequestID(p.RequestID) {
		return CashConsolidateRequest{}, ErrRequestIDRequired
	}
	if len(p.Sources) < 2 {
		return CashConsolidateRequest{}, ErrTooFewSources
	}
	targetFieldsVal, ok := p.To.(targetFields)
	if !ok {
		return CashConsolidateRequest{}, ErrConsolidateTargetInvalid
	}
	if err := checkIAPubkey(targetFieldsVal); err != nil {
		return CashConsolidateRequest{}, err
	}

	// A slice is a wallet plus an identity on it, so two sources from one wallet
	// under different identities are distinct and stay legal.
	seen := make(map[string]struct{}, len(p.Sources))
	sources := make([]consolidateSourceParam, len(p.Sources))
	wallets := make([]string, len(p.Sources))
	for i, src := range p.Sources {
		wallets[i] = src.WalletPubkey
	}
	sourcesHash, err := SourcesHash(wallets)
	if err != nil {
		return CashConsolidateRequest{}, err
	}
	for i, src := range p.Sources {
		amount := src.Amount
		binding := ClaimBinding{
			Method:          MethodCashConsolidate,
			Wallet:          src.WalletPubkey,
			NewIdentityHash: newIdentityHash(p.To),
			AmountMillis:    &amount,
			SourcesHash:     sourcesHash,
		}
		identityType, identityValue, identityEvent, attestationEvent, cashSecret, err := src.Credential.buildProof(binding)
		if err != nil {
			return CashConsolidateRequest{}, err
		}
		if identityType == identityTypeCash || cashSecret != "" {
			return CashConsolidateRequest{}, ErrCashSource
		}
		key := src.WalletPubkey + "\x00" + identityType + "\x00" + identityValue
		if _, dup := seen[key]; dup {
			return CashConsolidateRequest{}, ErrDuplicateSource
		}
		seen[key] = struct{}{}
		sources[i] = consolidateSourceParam{
			WalletPubkey:  src.WalletPubkey,
			IdentityType:  identityType,
			IdentityValue: identityValue,
		}
		if identityEvent != nil {
			sources[i].IdentityEvent = string(identityEvent)
		}
		if attestationEvent != nil {
			sources[i].AttestationEvent = string(attestationEvent)
		}
	}

	return CashConsolidateRequest{
		RequestID: p.RequestID,
		Sources:   sources,
		NewIdentity: cashTransferNewIdentityParam{
			IdentityType:  targetFieldsVal.identityType(),
			IdentityValue: targetFieldsVal.identityValue(),
			IAPubkey:      targetFieldsVal.iaPubkey(),
		},
	}, nil
}

// cashConsolidateResponseWire is cash_consolidate's raw wire response —
// NewWalletToken is still NIP-44 nested-encrypted at this point;
// ParseResult decrypts it into CashConsolidateResult.
type cashConsolidateResponseWire struct {
	AmountMillis    uint64           `json:"amount_millis"`
	NewWalletPubkey string           `json:"new_wallet_pubkey"`
	NewWalletToken  TokenOrTombstone `json:"new_wallet_token"`
	ExpiresAt       Expiry           `json:"expires_at,omitzero"`
}

// CashConsolidateResult is cash_consolidate's response with the token decrypted.
// ExpiresAt is the earliest source expiry, or never. NewWalletTombstone is set
// only by ParseLookupResult, for a merged bill already destroyed.
type CashConsolidateResult struct {
	AmountMillis       uint64
	NewWalletPubkey    string
	NewWalletToken     string
	ExpiresAt          Expiry
	NewWalletTombstone *Tombstone
}

// ParseResult reads a direct cash_consolidate reply: a tombstone is *BillGone; a
// secret key is refused; a pubkey target's token is decrypted with Sources[0]'s
// credential (the caller's proof key), a connection_key or cash target's comes in
// the clear.
func (p CashConsolidateParams) ParseResult(data []byte) (*CashConsolidateResult, error) {
	r, err := p.parse(data)
	if err == nil && r.NewWalletTombstone != nil {
		return r, ErrTombstoneInReply
	}
	return r, err
}

// ParseLookupResult reads a lookup's done result for a consolidate.
func (p CashConsolidateParams) ParseLookupResult(data []byte) (*CashConsolidateResult, error) {
	return p.parse(data)
}

func (p CashConsolidateParams) parse(data []byte) (*CashConsolidateResult, error) {
	if err := goneIf(MethodCashConsolidate, data); err != nil {
		return nil, err
	}
	if hasKey(data, "cash_secret") || hasKey(data, "secret") {
		return nil, ErrHubReturnedSecret
	}
	var w cashConsolidateResponseWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	r := &CashConsolidateResult{AmountMillis: w.AmountMillis, NewWalletPubkey: w.NewWalletPubkey,
		NewWalletToken: w.NewWalletToken.Token, ExpiresAt: w.ExpiresAt, NewWalletTombstone: w.NewWalletToken.Tombstone}
	if r.NewWalletToken == "" || len(p.Sources) == 0 || !IsPubkeyTarget(p.To) {
		return r, nil
	}
	token, err := p.Sources[0].Credential.decryptDelivery(w.NewWalletPubkey, r.NewWalletToken)
	if err != nil {
		return nil, fmt.Errorf("nipcash: decrypt the consolidated wallet's token for %s: %w", w.NewWalletPubkey, err)
	}
	r.NewWalletToken = token
	return r, nil
}
