package nipcash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"time"
)

var (
	ErrZeroAmount         = errors.New("nipcash: an amount must be positive")
	ErrAmountOverflow     = errors.New("nipcash: the amounts overflow")
	ErrDuplicateRecipient = errors.New("nipcash: the same recipient appears twice")
	ErrEmptyToken         = errors.New("nipcash: the Hub returned an empty token")
	ErrCommitmentEcho     = errors.New("nipcash: the Hub's recipients do not echo the request")
	ErrHubReturnedSecret  = errors.New("nipcash: the Hub's reply carries a cash secret")
	ErrTombstoneInReply   = errors.New("nipcash: a direct reply carries a tombstone where a token belongs")
	ErrRequestIDRequired  = errors.New("nipcash: the call needs a request_id")
	ErrTokenScheme        = errors.New("nipcash: the minted token is not signed under cash-mint:v1")
)

// MintCashParams is mint_cash's request. RequestID is REQUIRED (NIP-CASH
// §request_id); the caller writes it ahead with the call.
type MintCashParams struct {
	Recipients []Allocation
	// Expiry is OPTIONAL; zero asks for the Hub's own ceiling (possibly never).
	Expiry    time.Duration
	RequestID string
}

// RecipientParam is one entry of mint_cash's recipients.
type RecipientParam struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
}

// MintCashRequest is mint_cash's wire request.
type MintCashRequest struct {
	Recipients []RecipientParam `json:"recipients"`
	Expiry     int64            `json:"expiry,omitempty"`
	RequestID  string           `json:"request_id"`
}

// Request builds the wire request: a valid RequestID; at least one recipient;
// positive amounts with an overflow-checked sum; pubkey, connection_key (with
// ia_pubkey) or cash (a commitment, the only entry); no duplicate (type, value,
// ia).
func (p MintCashParams) Request() (MintCashRequest, error) {
	if !ValidRequestID(p.RequestID) {
		return MintCashRequest{}, ErrRequestIDRequired
	}
	if len(p.Recipients) == 0 {
		return MintCashRequest{}, ErrNoRecipients
	}
	expiry, err := expirySeconds(p.Expiry)
	if err != nil {
		return MintCashRequest{}, err
	}
	var sum uint64
	hasCash := false
	seen := map[string]bool{}
	recipients := make([]RecipientParam, len(p.Recipients))
	for i, a := range p.Recipients {
		f, ok := a.Recipient.(targetFields)
		if !ok || a.Recipient == nil {
			return MintCashRequest{}, ErrNoRecipients
		}
		if err := checkIAPubkey(f); err != nil {
			return MintCashRequest{}, err
		}
		if a.AmountMillis == 0 {
			return MintCashRequest{}, ErrZeroAmount
		}
		var carry uint64
		sum, carry = bits.Add64(sum, a.AmountMillis, 0)
		if carry != 0 || sum > 1<<63-1 {
			return MintCashRequest{}, ErrAmountOverflow
		}
		if f.identityType() == identityTypeCash {
			hasCash = true
		}
		key := f.identityType() + "\x00" + f.identityValue() + "\x00" + f.iaPubkey()
		if seen[key] {
			return MintCashRequest{}, ErrDuplicateRecipient
		}
		seen[key] = true
		recipients[i] = RecipientParam{IdentityType: f.identityType(), IdentityValue: f.identityValue(),
			IAPubkey: f.iaPubkey(), AmountMillis: a.AmountMillis}
	}
	if hasCash && len(recipients) > 1 {
		return MintCashRequest{}, ErrMixedCashAllocation
	}
	return MintCashRequest{Recipients: recipients, Expiry: expiry, RequestID: p.RequestID}, nil
}

// expirySeconds converts a caller's Expiry to whole seconds; zero stays zero.
func expirySeconds(d time.Duration) (int64, error) {
	if d < 0 || (d > 0 && d < time.Second) {
		return 0, ErrInvalidExpiry
	}
	return int64(d / time.Second), nil
}

// checkIAPubkey refuses a connection_key identity with no Identity Authority.
func checkIAPubkey(f targetFields) error {
	if f.identityType() == identityTypeConnectionKey && f.iaPubkey() == "" {
		return ErrMissingIAPubkey
	}
	return nil
}

// RecipientResult is one entry of mint_cash's response recipients.
type RecipientResult struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value"`
	IAPubkey      string `json:"ia_pubkey,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
}

// MintCashResult is mint_cash's response. cash_token alone is the new bill's
// credential. TokenTombstone is set only by ParseLookupResult, for a bill
// already destroyed.
type MintCashResult struct {
	WalletPubkey   string            `json:"wallet_pubkey"`
	CashToken      string            `json:"-"`
	ExpiresAt      Expiry            `json:"expires_at"`
	Recipients     []RecipientResult `json:"recipients"`
	TokenTombstone *Tombstone        `json:"-"`
}

type mintCashWire struct {
	WalletPubkey string            `json:"wallet_pubkey"`
	CashToken    TokenOrTombstone  `json:"cash_token"`
	ExpiresAt    Expiry            `json:"expires_at"`
	Recipients   []RecipientResult `json:"recipients"`
}

// ParseResult reads a direct mint_cash reply. Funds may already be committed,
// so it returns the parsed result together with any error: a cash_secret
// anywhere (ErrHubReturnedSecret), an empty token (ErrEmptyToken), a tombstone
// in place of the token (ErrTombstoneInReply), a token not signed under
// cash-mint:v1 (ErrTokenScheme), recipients that do not echo the request
// (ErrCommitmentEcho). A pairing_uri key is ignored. Checking the token's
// provenance against the Hub identity is the caller's (it knows the identity).
func (p MintCashParams) ParseResult(data []byte) (*MintCashResult, error) {
	r, err := p.parse(data)
	if err == nil && r.TokenTombstone != nil {
		err = ErrTombstoneInReply
	}
	return r, err
}

// ParseLookupResult reads a lookup's done result for a mint: as ParseResult, but
// a destroyed bill's token is its tombstone (TokenTombstone), not an error.
func (p MintCashParams) ParseLookupResult(data []byte) (*MintCashResult, error) {
	return p.parse(data)
}

func (p MintCashParams) parse(data []byte) (*MintCashResult, error) {
	if hasKey(data, "cash_secret") {
		return nil, ErrHubReturnedSecret
	}
	var w mintCashWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("nipcash: mint_cash result: %w", err)
	}
	r := &MintCashResult{WalletPubkey: w.WalletPubkey, CashToken: w.CashToken.Token, ExpiresAt: w.ExpiresAt,
		Recipients: w.Recipients, TokenTombstone: w.CashToken.Tombstone}
	if r.TokenTombstone == nil {
		if r.CashToken == "" {
			return r, ErrEmptyToken
		}
		tok, err := Decode(r.CashToken)
		if err != nil {
			return r, fmt.Errorf("nipcash: minted token: %w", err)
		}
		if tok.Scheme != SchemeMintV1 {
			return r, ErrTokenScheme
		}
	}
	if err := p.echoes(r.Recipients); err != nil {
		return r, err
	}
	return r, nil
}

// echoes checks the response recipients against the request, entry by entry.
func (p MintCashParams) echoes(got []RecipientResult) error {
	if len(got) != len(p.Recipients) {
		return fmt.Errorf("%w: %d recipients, sent %d", ErrCommitmentEcho, len(got), len(p.Recipients))
	}
	for i, a := range p.Recipients {
		f, ok := a.Recipient.(targetFields)
		if !ok {
			return ErrCommitmentEcho
		}
		g := got[i]
		valueOK := g.IdentityValue == f.identityValue()
		if f.identityType() == identityTypeCash {
			valueOK = CommitmentsEqual(g.IdentityValue, f.identityValue())
		}
		if g.IdentityType != f.identityType() || !valueOK || g.IAPubkey != f.iaPubkey() || g.AmountMillis != a.AmountMillis {
			return fmt.Errorf("%w: entry %d", ErrCommitmentEcho, i)
		}
	}
	return nil
}

// hasKey reports a JSON object key name anywhere in data.
func hasKey(data []byte, name string) bool {
	type frame struct{ obj, expectKey bool }
	var stack []frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expectKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, frame{obj: true, expectKey: true})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].expectKey {
			if k, _ := tok.(string); k == name {
				return true
			}
			stack[n-1].expectKey = false
			continue
		}
		valueDone()
	}
}
