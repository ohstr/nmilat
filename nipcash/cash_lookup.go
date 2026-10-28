package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipcash/transport"
)

var (
	// ErrLookupKey is a lookup naming both request_id and connection_pubkey, or
	// neither, or carrying a cash_secret beside connection_pubkey.
	ErrLookupKey = errors.New("nipcash: a lookup names exactly one of request_id and connection_pubkey")
	// ErrLookupMalformed is a lookup answer that does not have the spec's shape.
	// It is never read as unknown.
	ErrLookupMalformed = errors.New("nipcash: malformed cash_lookup answer")
	// ErrLookupUndecodable is a done whose result does not parse: the call stays
	// pending and is shown to the user, never read as unknown.
	ErrLookupUndecodable = errors.New("nipcash: cash_lookup done result does not parse")
)

// CashLookupRequest is cash_lookup's params.
type CashLookupRequest struct {
	RequestID        string `json:"request_id,omitempty"`
	ConnectionPubkey string `json:"connection_pubkey,omitempty"`
	Deadline         int64  `json:"deadline"`
	CashSecret       string `json:"cash_secret,omitempty"`
}

// Validate checks exactly one of request_id and connection_pubkey (each well
// formed), a positive deadline, and no cash_secret on a join lookup.
func (r CashLookupRequest) Validate() error {
	switch {
	case (r.RequestID == "") == (r.ConnectionPubkey == ""):
		return ErrLookupKey
	case r.RequestID != "" && !ValidRequestID(r.RequestID):
		return fmt.Errorf("%w: request_id", ErrLookupKey)
	case r.ConnectionPubkey != "" && !isLowerHex64(r.ConnectionPubkey):
		return fmt.Errorf("%w: connection_pubkey", ErrLookupKey)
	case r.ConnectionPubkey != "" && r.CashSecret != "":
		return fmt.Errorf("%w: a join lookup carries no cash_secret", ErrLookupKey)
	case r.Deadline <= 0:
		return fmt.Errorf("nipcash: a lookup needs the call's deadline")
	case r.CashSecret != "" && !ValidCashSecret(r.CashSecret):
		return fmt.Errorf("nipcash: cash_secret is 64 lowercase hex")
	}
	return nil
}

// CashLookupResult is cash_lookup's answer.
type CashLookupResult struct {
	Status     LookupStatus    `json:"status"`
	Result     json.RawMessage `json:"result,omitempty"`
	RetryAfter int64           `json:"retry_after,omitempty"`
}

// ParseCashLookupResult reads a lookup answer strictly: done carries a result,
// pending a retry_after, unknown and expired neither; any other status is
// ErrLookupMalformed, never unknown.
func ParseCashLookupResult(data []byte) (*CashLookupResult, error) {
	var r CashLookupResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLookupMalformed, err)
	}
	hasResult := len(r.Result) > 0 && string(r.Result) != "null"
	switch r.Status {
	case LookupDone:
		if !hasResult {
			return nil, fmt.Errorf("%w: done without a result", ErrLookupMalformed)
		}
	case LookupPending:
		if r.RetryAfter <= 0 || hasResult {
			return nil, fmt.Errorf("%w: pending needs retry_after and no result", ErrLookupMalformed)
		}
	case LookupUnknown, LookupExpired:
		if hasResult || r.RetryAfter != 0 {
			return nil, fmt.Errorf("%w: %s carries nothing", ErrLookupMalformed, r.Status)
		}
	default:
		return nil, fmt.Errorf("%w: status %q", ErrLookupMalformed, r.Status)
	}
	return &r, nil
}

// CashLookupParams is a lookup item: the credential that placed the call (or, for
// a cash-authorized call, BySecret), and the request.
type CashLookupParams struct {
	Credential Credential
	Request    CashLookupRequest
}

// Item builds the cash_lookup item against the call's target. A BySecret
// credential makes a bearer item; Request.CashSecret is sent only when set (look
// up first without it, and add it only after an UNAUTHORIZED).
func (p CashLookupParams) Item(id, target, connSecret string, b ItemBinding) (transport.Item, error) {
	if err := p.Request.Validate(); err != nil {
		return transport.Item{}, err
	}
	// A BySecret credential carries no item proof (a bearer item); the secret
	// reaches params only through Request.CashSecret.
	return buildItem(id, target, connSecret, MethodCashLookup, p.Request, p.Credential, b)
}
