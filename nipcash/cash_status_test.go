package nipcash

import (
	"encoding/json"
	"testing"
)

// A roster response and a tombstone share one type, so the discriminator has to
// be reliable in both directions.
func TestCashStatusResult_IsSpent(t *testing.T) {
	var roster CashStatusResult
	if err := json.Unmarshal([]byte(`{"recipients":[{"identity_type":"pubkey","amount_millis":1000}]}`), &roster); err != nil {
		t.Fatal(err)
	}
	if roster.IsSpent() {
		t.Fatal("a roster response must not read as spent")
	}
	if len(roster.Recipients) != 1 {
		t.Fatalf("recipients = %d, want 1", len(roster.Recipients))
	}

	var tomb CashStatusResult
	if err := json.Unmarshal([]byte(`{"error":"spent","retained_until":1758800000}`), &tomb); err != nil {
		t.Fatal(err)
	}
	if !tomb.IsSpent() {
		t.Fatal("a tombstone must read as spent")
	}
	if tomb.RetainedUntil == nil || *tomb.RetainedUntil != 1758800000 {
		t.Fatalf("retained_until = %v, want 1758800000", tomb.RetainedUntil)
	}
}

// An empty response is neither a roster nor a tombstone. It must not read as
// spent — reporting a bill gone on an empty answer is the failure this whole
// mechanism exists to prevent.
func TestCashStatusResult_EmptyIsNotSpent(t *testing.T) {
	var empty CashStatusResult
	if err := json.Unmarshal([]byte(`{}`), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.IsSpent() {
		t.Fatal("an empty result must not read as spent")
	}
}

// An unrecognised error value must not read as spent either: a future Hub may
// answer with something this client does not know, and guessing "gone" is the
// dangerous direction to guess in.
func TestCashStatusResult_UnknownErrorIsNotSpent(t *testing.T) {
	var other CashStatusResult
	if err := json.Unmarshal([]byte(`{"error":"something_new"}`), &other); err != nil {
		t.Fatal(err)
	}
	if other.IsSpent() {
		t.Fatal("only the documented \"spent\" value may read as spent")
	}
}

// The zero value must be indeterminate, so a caller that ignores an error and
// reads the state still never concludes the bill is gone.
func TestBillStateZeroValueIsIndeterminate(t *testing.T) {
	// BillState lives in the client package; this asserts the contract it
	// depends on from here: a zero CashStatusResult is not spent.
	var zero CashStatusResult
	if zero.IsSpent() {
		t.Fatal("the zero value must not read as spent")
	}
}
