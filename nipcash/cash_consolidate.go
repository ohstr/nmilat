package nipcash

import "encoding/json"

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
	// MintSignature opts the merged wallet's token into mint provenance —
	// independent of whether any source wallet had one.
	MintSignature bool
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
	Sources       []consolidateSourceParam     `json:"sources"`
	NewIdentity   cashTransferNewIdentityParam `json:"new_identity"`
	MintSignature bool                         `json:"mint_signature,omitempty"`
}

// Request builds cash_consolidate's wire request from p. Exported for
// nipcash/client's use; a caller using nipcash/client's CashConsolidate
// method never calls this directly.
func (p CashConsolidateParams) Request() (CashConsolidateRequest, error) {
	if len(p.Sources) < 2 {
		return CashConsolidateRequest{}, ErrTooFewSources
	}
	targetFieldsVal, ok := p.To.(targetFields)
	if !ok {
		return CashConsolidateRequest{}, ErrConsolidateTargetInvalid
	}

	sources := make([]consolidateSourceParam, len(p.Sources))
	for i, src := range p.Sources {
		amount := src.Amount
		binding := proofBinding{
			WalletPubkey:    src.WalletPubkey,
			NewIdentityHash: newIdentityHash(p.To),
			AmountMillis:    &amount,
		}
		identityType, identityValue, identityEvent, attestationEvent, cashSecret, err := src.Credential.buildProof(binding)
		if err != nil {
			return CashConsolidateRequest{}, err
		}
		if identityType == identityTypeCash || cashSecret != "" {
			return CashConsolidateRequest{}, ErrCashSource
		}
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
		Sources: sources,
		NewIdentity: cashTransferNewIdentityParam{
			IdentityType:  targetFieldsVal.identityType(),
			IdentityValue: targetFieldsVal.identityValue(),
			IAPubkey:      targetFieldsVal.iaPubkey(),
		},
		MintSignature: p.MintSignature,
	}, nil
}

// cashConsolidateResponseWire is cash_consolidate's raw wire response —
// NewWalletToken is still NIP-44 nested-encrypted at this point;
// ParseResult decrypts it into CashConsolidateResult.
type cashConsolidateResponseWire struct {
	AmountMillis    uint64 `json:"amount_millis"`
	NewWalletPubkey string `json:"new_wallet_pubkey"`
	NewWalletToken  string `json:"new_wallet_token"`
	ExpiresAt       *int64 `json:"expires_at,omitempty"`
}

// CashConsolidateResult is cash_consolidate's response, with NewWalletToken
// already decrypted into a plain cash token string.
type CashConsolidateResult struct {
	AmountMillis    uint64
	NewWalletPubkey string
	NewWalletToken  string
	ExpiresAt       *int64
}

// ParseResult parses cash_consolidate's wire response, decrypting
// NewWalletToken with the first source's own Credential when the target is
// a pubkey — the Hub encrypts it to the caller, same as cash_transfer's own
// delivery. A cash/connection_key target has no real pubkey yet, so the
// Hub sends the token in the clear instead; ParseResult passes it through
// unchanged rather than attempting decryption. If decryption ever fails
// (e.g. an older Hub still keying pubkey-target delivery some other way),
// the raw value is preserved as-is instead of erroring — the merge itself
// already succeeded.
//
// Exported for nipcash/client's use; a caller using nipcash/client's
// CashConsolidate method never calls this directly.
func (p CashConsolidateParams) ParseResult(data []byte) (*CashConsolidateResult, error) {
	var wire cashConsolidateResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	result := &CashConsolidateResult{
		AmountMillis:    wire.AmountMillis,
		NewWalletPubkey: wire.NewWalletPubkey,
		ExpiresAt:       wire.ExpiresAt,
	}
	result.NewWalletToken = wire.NewWalletToken
	if wire.NewWalletToken == "" || len(p.Sources) == 0 || !IsPubkeyTarget(p.To) {
		return result, nil
	}
	if token, err := p.Sources[0].Credential.decryptDelivery(wire.NewWalletPubkey, wire.NewWalletToken); err == nil {
		result.NewWalletToken = token
	}
	return result, nil
}
