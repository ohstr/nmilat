package client

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// TestJoinOutcomes_OmissionIsItsOwnState is why ItemOutcome has three states.
//
// A hub omits an item whose target it does not hold, whose proof did not verify, or
// whose method it does not serve — and those are indistinguishable by design, because
// distinguishing them would make batching an oracle for which bills a hub holds.
//
// So a caller MUST be able to tell "the hub said nothing" from "the hub refused".
// Collapsing them into one error type is the mistake this type exists to prevent: it
// would report a bill the hub simply does not hold as a failure of that bill, and it
// would make an explicit refusal — which IS safe to retry — look identical to silence,
// which is not.
func TestJoinOutcomes_OmissionIsItsOwnState(t *testing.T) {
	requested := []string{"a", "b", "c"}
	resp := &transport.ResponseEnvelope{
		Results: []transport.Result{
			{ID: "a", Result: json.RawMessage(`{"ok":true}`)},
			{ID: "c", Error: &transport.ResultError{Code: "NOT_FOUND", Message: "gone"}},
			// "b" is absent — omitted.
		},
	}

	got := joinOutcomes(requested, resp, 0)
	if len(got) != 3 {
		t.Fatalf("got %d outcomes for 3 requested items", len(got))
	}

	if got[0].State != OutcomeResult || !got[0].Succeeded() {
		t.Errorf("a: state = %v, want result", got[0].State)
	}
	if got[1].State != OutcomeNotServed {
		t.Errorf("b: state = %v, want not served — the hub omitted it", got[1].State)
	}
	if got[1].Error != nil {
		t.Error("b: an omission must not be reported as an error; the hub said nothing")
	}
	if got[2].State != OutcomeError || got[2].Error == nil {
		t.Errorf("c: state = %v, want error", got[2].State)
	}
}

// TestJoinOutcomes_EveryRequestedItemGetsExactlyOneOutcome: the join is driven by what
// was SENT, not by what came back. Iterating the response could only ever produce
// outcomes for items the hub chose to answer, which would make omission unrepresentable
// — the caller would silently receive a shorter slice than they asked about.
func TestJoinOutcomes_EveryRequestedItemGetsExactlyOneOutcome(t *testing.T) {
	requested := []string{"a", "b", "c", "d"}

	// A hub that answers nothing at all.
	got := joinOutcomes(requested, &transport.ResponseEnvelope{}, 0)
	if len(got) != len(requested) {
		t.Fatalf("got %d outcomes, want %d", len(got), len(requested))
	}
	for i, o := range got {
		if o.ID != requested[i] {
			t.Errorf("outcome %d has id %q, want %q — order must follow the request", i, o.ID, requested[i])
		}
		if o.State != OutcomeNotServed {
			t.Errorf("%s: state = %v, want not served", o.ID, o.State)
		}
	}

	// A nil response — no reply arrived — must behave the same way, not panic.
	if got := joinOutcomes(requested, nil, 0); len(got) != len(requested) {
		t.Errorf("nil response produced %d outcomes, want %d", len(got), len(requested))
	}
}

// TestJoinOutcomes_IgnoresResultsForUnrequestedIDs: a hostile or buggy hub must not be
// able to inject an outcome for an id the caller never sent, which they might demux
// into the wrong bill.
func TestJoinOutcomes_IgnoresResultsForUnrequestedIDs(t *testing.T) {
	resp := &transport.ResponseEnvelope{
		Results: []transport.Result{
			{ID: "a", Result: json.RawMessage(`{"ok":true}`)},
			{ID: "never-sent", Result: json.RawMessage(`{"ok":true}`)},
		},
	}

	got := joinOutcomes([]string{"a"}, resp, 0)
	if len(got) != 1 {
		t.Fatalf("got %d outcomes, want 1 — only requested ids may appear", len(got))
	}
	if got[0].ID != "a" {
		t.Errorf("outcome id = %q, want \"a\"", got[0].ID)
	}
}

// TestOutcome_SafeToResend_OnlyForExplicitErrors is the money-safety property.
//
// The SDK never retries a money path itself: cash_redeem has no idempotency key and a
// double redemption is unrecoverable. This is what a caller consults instead — and the
// answer for an omission must be NO, because silence is indistinguishable from an item
// that executed and whose response was lost.
func TestOutcome_SafeToResend_OnlyForExplicitErrors(t *testing.T) {
	cases := []struct {
		state ItemOutcome
		want  bool
	}{
		{ItemOutcome{State: OutcomeError, Error: &transport.ResultError{Code: "RATE_LIMITED"}}, true},
		{ItemOutcome{State: OutcomeNotServed}, false},
		{ItemOutcome{State: OutcomeResult, Result: json.RawMessage(`{}`)}, false},
	}
	for _, tc := range cases {
		if got := tc.state.SafeToResend(); got != tc.want {
			t.Errorf("%v: SafeToResend() = %v, want %v", tc.state.State, got, tc.want)
		}
	}
}

// TestOutcome_ZeroValueIsNotServed mirrors BillState's own reasoning: a caller who
// forgets to check reads "I don't know", never a false success or a false failure.
func TestOutcome_ZeroValueIsNotServed(t *testing.T) {
	var zero ItemOutcome
	if zero.State != OutcomeNotServed {
		t.Errorf("zero state = %v, want not served", zero.State)
	}
	if zero.Succeeded() {
		t.Error("a zero outcome must not report success")
	}
	if zero.SafeToResend() {
		t.Error("a zero outcome must not report safe-to-resend")
	}
}

// TestNotServedOutcomes_MarksAWholeEnvelope: when an envelope never got an answer,
// every item in it is unserved for one shared reason. The Envelope field is what lets a
// caller notice that correlation instead of reading N independent omissions.
func TestNotServedOutcomes_MarksAWholeEnvelope(t *testing.T) {
	got := notServedOutcomes([]string{"a", "b"}, 2)
	for _, o := range got {
		if o.State != OutcomeNotServed {
			t.Errorf("%s: state = %v, want not served", o.ID, o.State)
		}
		if o.Envelope != 2 {
			t.Errorf("%s: envelope = %d, want 2", o.ID, o.Envelope)
		}
	}
}
