package client

import (
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// SafeToResend says yes only where resending cannot double-spend and the spec
// allows it: BAD_REQUEST, or a definitive code on a call without a request_id.
func TestSafeToResend_FollowsTheErrorRules(t *testing.T) {
	code := func(c string) *transport.ResultError { return &transport.ResultError{Code: c} }
	for name, tc := range map[string]struct {
		o    ItemOutcome
		want bool
	}{
		"no id, PAYMENT_FAILED":  {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodePaymentFailed)}, true},
		"no id, RATE_LIMITED":    {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeRateLimited)}, true},
		"no id, INTERNAL":        {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal)}, false},
		"id, BAD_REQUEST":        {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeBadRequest), RequestID: "r"}, true},
		"id, RATE_LIMITED":       {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeRateLimited), RequestID: "r"}, false},
		"id, INTERNAL":           {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal), RequestID: "r"}, false},
		"id, REQUEST_REUSED":     {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeRequestReused), RequestID: "r"}, false},
		"no id, REQUEST_REUSED":  {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeRequestReused)}, false},
		"undecodable":            {ItemOutcome{State: OutcomeError, Error: code(nipcash.ErrCodeInternal), Undecodable: true}, false},
		"omitted":                {ItemOutcome{State: OutcomeNotServed}, false},
		"result":                 {ItemOutcome{State: OutcomeResult}, false},
		"error without an Error": {ItemOutcome{State: OutcomeError}, true},
		"id, no Error":           {ItemOutcome{State: OutcomeError, RequestID: "r"}, false},
	} {
		if got := tc.o.SafeToResend(); got != tc.want {
			t.Errorf("%s: SafeToResend = %v, want %v", name, got, tc.want)
		}
	}
}
