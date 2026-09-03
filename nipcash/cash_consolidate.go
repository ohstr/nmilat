package nipcash

import "encoding/json"

// CashConsolidateParams is cash_consolidate's friendly request — combines
// several same-hub slices this node custodies into one new cash token
// (NIP-CASH §Consolidating Tokens).
type CashConsolidateParams struct {
	// Sources MUST contain at least two distinct sources (ErrTooFewSources),
	// none bearer-identified (ErrBearerSource — this revision of
	// cash_consolidate accepts only pubkey-identified sources).
	Sources []Source
	// To is who the merged wallet belongs to — MUST be a pubkey (namedIdentity
	// built via Pubkey); ErrConsolidateTargetNotPubkey otherwise. A
	// *BearerTarget or connection_key Target is this revision's deferred
	// scope, rejected client-side rather than left to fail server-side.
	To Target
	// MintSignature opts the merged wallet's token into mint provenance —
	// independent of whether any source wallet had one.
	MintSignature bool
}

// consolidateSourceParam is the wire shape of one entry in cash_consolidate's
// "sources" request array.
type consolidateSourceParam struct {
	WalletPubkey  string `json:"wallet_pubkey"`
	IdentityType  string `json:"identity_type,omitempty"`
	IdentityValue string `json:"identity_value,omitempty"`
	IdentityEvent string `json:"identity_event,omitempty"`
	BearerSecret  string `json:"bearer_secret,omitempty"`
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
	if !ok || targetFieldsVal.identityType() != identityTypePubkey {
		return CashConsolidateRequest{}, ErrConsolidateTargetNotPubkey
	}

	sources := make([]consolidateSourceParam, len(p.Sources))
	for i, src := range p.Sources {
		amount := src.Amount
		binding := proofBinding{
			WalletPubkey:    src.WalletPubkey,
			NewIdentityHash: newIdentityHash(p.To),
			AmountMillis:    &amount,
		}
		identityType, identityValue, identityEvent, _, bearerSecret, err := src.Credential.buildProof(binding)
		if err != nil {
			return CashConsolidateRequest{}, err
		}
		if identityType == identityTypeBearer || bearerSecret != "" {
			return CashConsolidateRequest{}, ErrBearerSource
		}
		sources[i] = consolidateSourceParam{
			WalletPubkey:  src.WalletPubkey,
			IdentityType:  identityType,
			IdentityValue: identityValue,
		}
		if identityEvent != nil {
			sources[i].IdentityEvent = string(identityEvent)
		}
	}

	return CashConsolidateRequest{
		Sources: sources,
		NewIdentity: cashTransferNewIdentityParam{
			IdentityType:  targetFieldsVal.identityType(),
			IdentityValue: targetFieldsVal.identityValue(),
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
// NewWalletToken with the first source's own Credential — any source's
// decryptDelivery derives the identical key, since the inner delivery layer
// is keyed to the caller's own real identity privkey and the new wallet's
// pubkey, not to any one specific source. Exported for nipcash/client's
// use; a caller using nipcash/client's CashConsolidate method never calls
// this directly.
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
	if wire.NewWalletToken != "" && len(p.Sources) > 0 {
		token, err := p.Sources[0].Credential.decryptDelivery(wire.NewWalletPubkey, wire.NewWalletToken)
		if err != nil {
			return nil, err
		}
		result.NewWalletToken = token
	}
	return result, nil
}
