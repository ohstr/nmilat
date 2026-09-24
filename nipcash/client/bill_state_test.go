package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

func TestBillState_String(t *testing.T) {
	for _, tc := range []struct {
		state BillState
		want  string
	}{
		{BillAvailable, "available"},
		{BillSpent, "spent"},
		{BillIndeterminate, "indeterminate"},
		{BillState(42), "indeterminate"},
	} {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("BillState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// The zero value must be indeterminate. A caller that ignores the error and
// reads the state gets "I don't know", never "spent".
func TestBillState_ZeroValueIsIndeterminate(t *testing.T) {
	var zero BillState
	if zero != BillIndeterminate {
		t.Fatalf("zero value = %v, want BillIndeterminate", zero)
	}
}

// A roster answer means the bill is there.
func TestClassify_Roster(t *testing.T) {
	result := &nipcash.CashStatusResult{
		Recipients: []nipcash.RecipientStatus{{IdentityType: "pubkey", AmountMillis: 1000}},
	}

	state, got, err := classify(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state != BillAvailable {
		t.Fatalf("state = %v, want BillAvailable", state)
	}
	if got != result {
		t.Fatal("the result must be passed through so a caller can read the roster")
	}
}

// A tombstone is definitive, and carries the deadline through.
func TestClassify_Tombstone(t *testing.T) {
	until := int64(1758800000)
	result := &nipcash.CashStatusResult{Error: nipcash.ErrorSpent, RetainedUntil: &until}

	state, got, err := classify(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state != BillSpent {
		t.Fatalf("state = %v, want BillSpent", state)
	}
	if got == nil || got.RetainedUntil == nil || *got.RetainedUntil != until {
		t.Fatal("retained_until must survive so a caller can show when the Hub will stop answering")
	}
}

// The property this whole helper exists for: silence is never "spent".
//
// A timeout, an unreachable relay, a dropped request and a Hub that is simply
// down all arrive here as an error, and every one of them must read as
// indeterminate. Reporting "spent" on any of them tells someone their money is
// gone during an ordinary outage.
func TestClassify_SilenceIsNeverSpent(t *testing.T) {
	for name, err := range map[string]error{
		"deadline exceeded": context.DeadlineExceeded,
		"canceled":          context.Canceled,
		"transport failure": errors.New("dial relay: connection refused"),
	} {
		t.Run(name, func(t *testing.T) {
			state, result, gotErr := classify(nil, err)
			if state != BillIndeterminate {
				t.Fatalf("state = %v, want BillIndeterminate — silence must never read as spent", state)
			}
			if result != nil {
				t.Fatal("no result may be invented for a call that never answered")
			}
			if !errors.Is(gotErr, err) {
				t.Fatalf("err = %v, want it to wrap %v so a caller can retry on it", gotErr, err)
			}
		})
	}
}

// An error takes precedence even if a partial result came back with it, for
// the same reason: a half-answer is not a statement that the bill is gone.
func TestClassify_ErrorWinsOverResult(t *testing.T) {
	until := int64(1758800000)
	result := &nipcash.CashStatusResult{Error: nipcash.ErrorSpent, RetainedUntil: &until}

	state, got, err := classify(result, context.DeadlineExceeded)
	if state != BillIndeterminate {
		t.Fatalf("state = %v, want BillIndeterminate", state)
	}
	if got != nil {
		t.Fatal("a result accompanying an error must not be handed on as authoritative")
	}
	if err == nil {
		t.Fatal("the error must be reported")
	}
}

// A response with neither a roster nor a tombstone is not spent. It reads as
// available-but-empty rather than gone, which is the safe direction: the
// dangerous mistake is concluding "spent" from an answer that never said so.
func TestClassify_EmptyResultIsNotSpent(t *testing.T) {
	state, _, err := classify(&nipcash.CashStatusResult{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state == BillSpent {
		t.Fatal("an empty result must not read as spent")
	}
}

// A nil result with no error should not be read as anything at all. This is
// defensive — call always returns a non-nil result when it returns no error —
// but the fallback must still be indeterminate rather than a nil dereference.
func TestClassify_NilResultWithoutErrorIsIndeterminate(t *testing.T) {
	state, got, err := classify(nil, nil)
	if state != BillIndeterminate {
		t.Fatalf("state = %v, want BillIndeterminate", state)
	}
	if got != nil {
		t.Fatal("no result to pass on")
	}
	if err == nil {
		t.Fatal("a missing result must surface as an error, not as a silent success")
	}
}
