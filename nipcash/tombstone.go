package nipcash

import (
	"encoding/json"
	"errors"
	"fmt"
)

// StatusSpent is a tombstone's status.
const StatusSpent = "spent"

// The five reasons a Hub sends (NIP-CASH §Answering About a Destroyed Bill).
const (
	ReasonRedeemed     = "redeemed"
	ReasonTransferred  = "transferred"
	ReasonConsolidated = "consolidated"
	ReasonExpired      = "expired"
	ReasonReclaimed    = "reclaimed"
)

// Tombstone is a destroyed bill's answer: spent, why, and until when the Hub
// keeps answering. A client reads any reason other than the five, or none, as
// spent with no reason.
type Tombstone struct {
	Status            string `json:"status"`
	Reason            string `json:"reason,omitempty"`
	RetainedUntil     *int64 `json:"retained_until,omitempty"`
	WithdrawRequestID string `json:"withdraw_request_id,omitempty"`
}

// ParseTombstone reads raw as a tombstone: an object whose status is spent. An
// unknown reason is dropped (spent, no reason).
func ParseTombstone(raw json.RawMessage) (*Tombstone, bool) {
	var t Tombstone
	if err := json.Unmarshal(raw, &t); err != nil || t.Status != StatusSpent {
		return nil, false
	}
	switch t.Reason {
	case ReasonRedeemed, ReasonTransferred, ReasonConsolidated, ReasonExpired, ReasonReclaimed:
	default:
		t.Reason = ""
	}
	return &t, true
}

// TombstoneReason is the reason a Hub writes for a slice's terminal state: the
// five states name themselves; written-off (and anything else) has none, so the
// tombstone omits reason.
func TombstoneReason(terminalState string) string {
	switch terminalState {
	case ReasonRedeemed, ReasonTransferred, ReasonConsolidated, ReasonExpired, ReasonReclaimed:
		return terminalState
	}
	return ""
}

// BillGone is a value method answered with the bill's tombstone: the bill is
// destroyed and nothing moved. Never read as a success.
type BillGone struct {
	Method    string
	Tombstone Tombstone
}

func (e *BillGone) Error() string {
	return fmt.Sprintf("nipcash: %s answered for a destroyed bill (spent, %s)", e.Method, e.reason())
}

func (e *BillGone) reason() string {
	if e.Tombstone.Reason == "" {
		return "no reason"
	}
	return e.Tombstone.Reason
}

// goneIf returns *BillGone when result is a tombstone.
func goneIf(method string, result []byte) error {
	if t, ok := ParseTombstone(result); ok {
		return &BillGone{Method: method, Tombstone: *t}
	}
	return nil
}

// TokenOrTombstone is a created bill's token as a lookup rebuilds it: the token,
// or the tombstone of a bill already destroyed.
type TokenOrTombstone struct {
	Token     string
	Tombstone *Tombstone
}

// UnmarshalJSON reads a token string or a tombstone object.
func (t *TokenOrTombstone) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*t = TokenOrTombstone{Token: s}
		return nil
	}
	if tomb, ok := ParseTombstone(b); ok {
		*t = TokenOrTombstone{Tombstone: tomb}
		return nil
	}
	return errors.New("nipcash: a token field is neither a token nor a tombstone")
}

// MarshalJSON writes the token string, or the tombstone object.
func (t TokenOrTombstone) MarshalJSON() ([]byte, error) {
	if t.Tombstone != nil {
		return json.Marshal(t.Tombstone)
	}
	return json.Marshal(t.Token)
}
