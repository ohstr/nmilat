package client

import (
	"errors"

	"github.com/ohstr/nmilat/nipcash"
)

// Local reasons: the stable names a caller shows or logs for a refusal the SDK
// made itself, with nothing decided by a Hub.
const (
	// ReasonStatusWidened is a cash_status scope-mine answer that is not
	// exactly the caller's row (nipcash.ErrMineWidened): a non-conforming
	// Hub. Nothing is decided about the claim; the read may be tried again.
	ReasonStatusWidened = "status_widened"
	// ReasonHubUnusable is ErrHubUnusable: nothing was written or sent.
	ReasonHubUnusable = "hub_unusable"
	// ReasonNotSent is ErrNotSent (ErrDeadlineTooClose, ErrPowTooHard and a
	// failed write-ahead included): nothing was published.
	ReasonNotSent = "not_sent"
	// ReasonMixedOrdered is ErrMixedOrdered: nothing was written or sent.
	ReasonMixedOrdered = "mixed_ordered"
	// ReasonConnectionMismatch is a failed online check
	// (nipcash.ErrHubIdentityMismatch, nipcash.ErrChainMismatch): the
	// connection was not used.
	ReasonConnectionMismatch = "connection_mismatch"
)

// LocalReason names the SDK's own refusal err carries, "" when err is not one
// of them (a Hub's answer, a transport failure, nil).
func LocalReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, nipcash.ErrMineWidened):
		return ReasonStatusWidened
	case errors.Is(err, ErrHubUnusable):
		return ReasonHubUnusable
	case errors.Is(err, ErrNotSent):
		return ReasonNotSent
	case errors.Is(err, ErrMixedOrdered):
		return ReasonMixedOrdered
	case errors.Is(err, nipcash.ErrHubIdentityMismatch), errors.Is(err, nipcash.ErrChainMismatch):
		return ReasonConnectionMismatch
	}
	return ""
}

// LocalRetryable reports whether a local refusal may simply be tried again
// later: a widened status read may (a later read can conform); the others need
// something to change first.
func LocalRetryable(err error) bool { return LocalReason(err) == ReasonStatusWidened }
