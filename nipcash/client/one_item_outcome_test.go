package client

import (
	"errors"
	"testing"
)

// oneItemOutcome's sendErr branch: with nothing decided for the item, the transport
// error is the answer; with a decided result, the result wins and the error goes.
func TestOneItemOutcome_SendErrBranch(t *testing.T) {
	sendErr := errors.New("relay closed")
	if err := oneItemOutcome(OutcomeNotServed, nil, sendErr, "cash_redeem"); !errors.Is(err, sendErr) {
		t.Errorf("not served + sendErr: err = %v, want the send error", err)
	}
	if err := oneItemOutcome(OutcomeResult, nil, sendErr, "cash_redeem"); err != nil {
		t.Errorf("decided result + sendErr: err = %v, want nil", err)
	}
	var ns *NotServedError
	if err := oneItemOutcome(OutcomeNotServed, nil, nil, "cash_redeem"); !errors.As(err, &ns) || ns.Method != "cash_redeem" {
		t.Errorf("not served, no sendErr: err = %v, want NotServedError for cash_redeem", err)
	}
}
