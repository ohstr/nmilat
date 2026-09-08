package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// TestFindEventBytesSurvivesLaterWrites guards a use-after-transaction-
// scope bug found while building a regression test for the stall reported
// in issues.md. EventStore.FindEventBytes (relay/store.go) used to do
// this:
//
//	var eventBytes []byte
//	_ = s.db.View(func(tx *bolt.Tx) error {
//	    eventBytes = tx.Bucket(indexEvents).Get(itob(evsid))
//	    return nil
//	})
//	return eventBytes, nil
//
// -- returning bbolt's Get result to the *caller*, after the read
// transaction that produced it had already closed. Per bbolt's own
// documented contract, a []byte from Get is a direct reference into the
// mmap'd database file and "is only valid for the life of the transaction
// ... Do not use it outside of the transaction". It's now fixed by copying
// the bytes out inside the transaction closure before returning.
//
// This was not a theoretical concern: it's what caused
// TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection to
// fail with "invalid character '\x00' looking for beginning of value" the
// first few times it was written, pre-fix -- reliably, 3/3 runs including
// under -race (which stayed silent throughout, consistent with this being
// an mmap-level memory hazard below Go's own memory-model visibility, not
// an ordinary data race on a Go variable). That test holds a large backlog
// queued for delivery for a while under a slow/backpressured connection --
// the same shape as the community-reported stall -- which is exactly the
// condition under which a FindEventBytes caller (relay/handlers.go's
// per-subscription consumer, which fetches bytes at delivery time and can
// then sit queued in Session.incoming for a while before actually being
// marshaled) can end up serving corrupted event JSON to a client instead
// of just delivering it late.
//
// What this test does *not* do: reliably reproduce that corruption in
// isolation. Several standalone attempts to force it deterministically --
// many separate write transactions after the read (up to 10,000 events
// across 40 transactions), and a version with a concurrent
// writer/reader goroutine pair -- did not reproduce it even once, despite
// the real session-level test catching it 3/3 times. The exact trigger
// (most likely bbolt's mmap being grown -- unmapped and remapped -- by a
// concurrent writer while this package held a stale pointer into the old
// mapping, though that's inference, not confirmed root cause) needs
// genuine concurrency and/or timing this test doesn't reliably hit. This
// test is kept anyway as a cheap defensive/documentation check of the
// invariant "FindEventBytes's result must survive later writes
// byte-for-byte" -- treat TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection
// as the real regression coverage for this bug, not this one.
//
// Every other Get() call site in this package (store_membership.go) was
// already safe: each json.Unmarshals its result *inside* the transaction
// closure, before the slice can go stale. FindEventBytes was the one
// exception, kept as a raw-bytes fast path specifically to avoid a
// marshal/unmarshal round trip (see EventSubscriptionResponse.MarshalJSON).
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
