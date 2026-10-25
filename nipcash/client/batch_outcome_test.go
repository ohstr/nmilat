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
			{ID: "a", ResultType: "cash_status", Result: json.RawMessage(`{"ok":true}`)},
			{ID: "c", Error: &transport.ResultError{Code: "NOT_FOUND", Message: "gone"}},
			// "b" is absent — omitted.
		},
	}

	got := joinOutcomes(t, requested, resp)
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

	// A hub that answers nothing at all, in a complete reply.
	got := joinOutcomes(t, requested, &transport.ResponseEnvelope{Results: []transport.Result{}})
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

	// No reply at all: one outcome each, unanswered rather than omitted.
	for _, o := range unansweredOutcomes(requested, 0) {
		if o.State != OutcomeUnanswered {
			t.Errorf("%s: state = %v, want unanswered", o.ID, o.State)
		}
	}
}

// TestJoinOutcomes_IgnoresResultsForUnrequestedIDs: a hostile or buggy hub must not be
// able to inject an outcome for an id the caller never sent, which they might demux
// into the wrong bill.
func TestJoinOutcomes_IgnoresResultsForUnrequestedIDs(t *testing.T) {
	resp := &transport.ResponseEnvelope{
		Results: []transport.Result{
			{ID: "a", ResultType: "cash_status", Result: json.RawMessage(`{"ok":true}`)},
			{ID: "never-sent", ResultType: "cash_status", Result: json.RawMessage(`{"ok":true}`)},
		},
	}

	got := joinOutcomes(t, []string{"a"}, resp)
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
		{ItemOutcome{State: OutcomeUnanswered}, false},
		{ItemOutcome{State: OutcomeConflict}, false},
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

// TestUnansweredOutcomes_MarksAWholeEnvelope: when an envelope never got an answer,
// every item in it is unanswered for one shared reason. The Envelope field is what lets a
// caller notice that correlation instead of reading N independent failures.
func TestUnansweredOutcomes_MarksAWholeEnvelope(t *testing.T) {
	got := unansweredOutcomes([]string{"a", "b"}, 2)
	for _, o := range got {
		if o.State != OutcomeUnanswered {
			t.Errorf("%s: state = %v, want unanswered", o.ID, o.State)
		}
		if o.Envelope != 2 {
			t.Errorf("%s: envelope = %d, want 2", o.ID, o.Envelope)
		}
	}
}

// joinOutcomes runs one single-chunk reply through replyState, every item sent as
// cash_status.
func joinOutcomes(t *testing.T, ids []string, resp *transport.ResponseEnvelope) []ItemOutcome {
	t.Helper()
	resp.Seq, resp.Total = 1, 1
	st := newReplyState(statusPacked("", 0, ids...))
	alien := []string{}
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	kept := resp.Results
	if kept != nil {
		kept = []transport.Result{}
		for _, r := range resp.Results {
			if !known[r.ID] {
				alien = append(alien, r.ID)
				continue
			}
			kept = append(kept, r)
		}
	}
	resp.Results = kept
	st.add("e1", &transport.DecodedChunk{ResponseEnvelope: resp, AlienIDs: alien})
	out, _ := st.outcomes(0)
	return out
}

// statusPacked is a packed envelope of cash_status items, for driving collectReply
// and replyState without building real items.
func statusPacked(nonce string, notAfter int64, ids ...string) packedEnvelope {
	return methodPacked(nonce, notAfter, "cash_status", ids...)
}

func methodPacked(nonce string, notAfter int64, method string, ids ...string) packedEnvelope {
	items := make([]transport.Item, 0, len(ids))
	for _, id := range ids {
		items = append(items, transport.Item{ID: id, Method: method})
	}
	return packedEnvelope{
		Envelope: transport.Envelope{Version: transport.EnvelopeVersion, Nonce: nonce, NotAfter: notAfter, Items: items},
		ItemIDs:  ids,
	}
}
