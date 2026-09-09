package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// TestFindEventBytesSurvivesLaterWrites guards a use-after-transaction-
// scope bug in EventStore.FindEventBytes: it used to return bbolt's Get()
// result after its own read transaction had already closed. Per bbolt's
// contract, that []byte is only valid for the transaction's lifetime --
// a later write can recycle the page it points into. Fixed by copying the
// bytes out inside the transaction closure. FindEventBytes was the only
// unsafe Get() call site in this package.
//
// Not theoretical: this caused
// TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection to
// fail with corrupted (NUL-byte) event JSON 3/3 times, pre-fix, under a
// held-for-a-while delivery backlog. -race stayed silent throughout,
// consistent with an mmap-level hazard below Go's memory-model
// visibility. This test itself doesn't reliably reproduce that
// corruption standalone (several attempts didn't trigger it) -- kept as
// cheap defensive coverage, not primary evidence.
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

	// Separate, unrelated write transactions (best-effort only, see doc
	// comment above).
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
