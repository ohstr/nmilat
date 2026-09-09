package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// TestFindEventBytesSurvivesLaterWrites guards a use-after-transaction-
// scope bug in EventStore.FindEventBytes: it used to return bbolt's Get()
// result to the caller after its own read transaction had already closed.
// Per bbolt's contract, that []byte is only valid for the transaction's
// lifetime -- a later write can recycle the page it points into. Fixed by
// copying the bytes out inside the transaction closure.
//
// Not theoretical: this caused
// TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection to
// fail with corrupted (NUL-byte) event JSON 3/3 times, pre-fix, under
// exactly the "large backlog held for a while before delivery" shape the
// stall report describes (relay/handlers.go fetches bytes at delivery
// time, which can sit queued for a while before actually being
// marshaled). -race stayed silent throughout, consistent with an
// mmap-level hazard below Go's memory-model visibility.
//
// This test does *not* reliably reproduce that corruption standalone --
// several attempts (many separate write transactions, a concurrent
// writer/reader pair) didn't trigger it even once, unlike the real
// session-level test above. Kept as cheap defensive coverage of the
// invariant, not as primary evidence.
//
// FindEventBytes was the only unsafe Get() call site in this package --
// every other one (store_membership.go) already json.Unmarshals its
// result inside the transaction closure.
func TestFindEventBytesSurvivesLaterWrites(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	ev := CreateEvent(t, 1)
	InsertTestEvents(t, store, []*nip01.Event{ev})

	// The only event in a fresh store gets evsid 1 (insertEvent's
	// NextSequence starts there).
	raw, err := store.FindEventBytes(1)
	if err != nil {
		t.Fatalf("FindEventBytes: %v", err)
	}
	want := append([]byte(nil), raw...) // defensive copy for comparison

	var sanity nip01.Event
	if err := json.Unmarshal(raw, &sanity); err != nil || sanity.ID != ev.ID {
		t.Fatalf("setup: FindEventBytes didn't return event %s before any later writes (err=%v)", ev.ID, err)
	}

	// A reasonable number of separate, unrelated write transactions --
	// see the doc comment above for why this alone isn't a reliable
	// reproduction of the actual bug, just a cheap best-effort check.
	for i := 0; i < 20; i++ {
		InsertTestEvents(t, store, CreateEvents(t, 100, 2))
	}

	if string(raw) != string(want) {
		t.Fatalf("FindEventBytes's returned slice was mutated by later, unrelated writes -- "+
			"corrupted event bytes now read: %q\nwant (captured immediately after the call): %q", raw, want)
	}

	var got nip01.Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("FindEventBytes's returned slice is no longer valid JSON after later writes: %v (raw=%q)", err, raw)
	}
	if got.ID != ev.ID {
		t.Fatalf("FindEventBytes's returned slice now decodes to a different event after later writes: got ID=%s, want=%s", got.ID, ev.ID)
	}
}
