package nipcash

import "fmt"

// Detail refines a withdrawal refusal (NIP-CASH §Errors). "" is no detail.
type Detail string

// The eight details NIP-CASH §Redeeming On-chain gives a refusal.
const (
	DetailNetwork      Detail = "network"
	DetailScriptType   Detail = "script_type"
	DetailBelowMin     Detail = "below_min"
	DetailTooSlow      Detail = "too_slow"
	DetailQuoteInvalid Detail = "quote_invalid"
	DetailQuoteExpired Detail = "quote_expired"
	DetailUnfinal      Detail = "unfinal"
	DetailOwnAddress   Detail = "own_address"
)

// ParseDetail reads an error's detail: one of the eight values, else "" (a
// client reads any other value, or none, as no detail).
func ParseDetail(s string) Detail {
	switch d := Detail(s); d {
	case DetailNetwork, DetailScriptType, DetailBelowMin, DetailTooSlow,
		DetailQuoteInvalid, DetailQuoteExpired, DetailUnfinal, DetailOwnAddress:
		return d
	}
	return ""
}

// WithdrawError is a Hub decision refusing a withdrawal step: the NIP-47 code,
// its detail ("" for none) and Row, the 1-based row of the spec's table that
// refused (0 when the refusal is not a table row).
type WithdrawError struct {
	Code   string
	Detail Detail
	Row    int
	// Reason is for people and logs; it never carries an address, a quote or a
	// secret.
	Reason string
}

func (e *WithdrawError) Error() string {
	s := "nipcash: withdrawal refused " + e.Code
	if e.Detail != "" {
		s += "/" + string(e.Detail)
	}
	if e.Row > 0 {
		s += fmt.Sprintf(" (row %d)", e.Row)
	}
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	return s
}

func withdrawErr(code string, detail Detail, row int, reason string) *WithdrawError {
	return &WithdrawError{Code: code, Detail: detail, Row: row, Reason: reason}
}
