package relay

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// TestCollectBatchPopulatesEventBytes guards the PotentialEvent.Bytes
// plumbing added to drop the delivery loop's second per-event read
// transaction (see relay/handlers.go and
// docs/relay-scan-transaction-blocks-under-load.md): collectBatch must set
// Bytes to the event's exact stored JSON, and that slice must be a copy out
// of bbolt's mmap, not a reference into it -- same requirement as
// FindEventBytes (see store_findeventbytes_test.go).
func TestCollectBatchPopulatesEventBytes(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	ev := CreateEvent(t, 1)
	InsertTestEvents(t, store, []*nip01.Event{ev})

	query := CreateQueryWithFilters(t, store, CreateFilter([]int{1}, 10))
	got := readEventsCollecting(t, query, false)

	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	pe := got[0]
	if len(pe.Bytes) == 0 {
		t.Fatalf("PotentialEvent.Bytes is empty, want the event's stored JSON")
	}

	var decoded nip01.Event
	if err := json.Unmarshal(pe.Bytes, &decoded); err != nil {
		t.Fatalf("PotentialEvent.Bytes is not valid JSON: %v (raw=%q)", err, pe.Bytes)
	}
	if decoded.ID != ev.ID {
		t.Fatalf("PotentialEvent.Bytes decodes to event %s, want %s", decoded.ID, ev.ID)
	}

	// Mutate the returned slice in place and confirm the store's own data
	// is unaffected -- if Bytes were a direct reference into bbolt's mmap
	// rather than a copy, this write would corrupt the store's page too.
	before := append([]byte(nil), pe.Bytes...)
	for i := range pe.Bytes {
		pe.Bytes[i] = 'x'
	}

	raw, err := store.FindEventBytes(pe.Evsid)
	if err != nil {
		t.Fatalf("FindEventBytes: %v", err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatalf("mutating PotentialEvent.Bytes affected the store's own data -- "+
			"it must be a copy, not a reference into bbolt's mmap\nstore now reads: %q\nwant (unaffected): %q",
			raw, before)
	}
}

// TestDeliveryUsesScanTimeBytesEvenIfEventIsLaterDeleted documents and
// guards the deliberate semantics change PotentialEvent.Bytes introduces:
// delivery no longer re-reads the store, so an event the scan already
// matched is still delivered once even if it is deleted before a consumer
// gets to it, using the bytes captured at scan time. This is a
// snapshot-consistency model ("deliver what matched at scan time"), not a
// live re-check -- before this change, handlers.go's delivery loop called
// FindEventBytes at delivery time, which would have returned
// ErrEventNotFound here and silently dropped the event instead.
func TestDeliveryUsesScanTimeBytesEvenIfEventIsLaterDeleted(t *testing.T) {
	store := newStore(t)
	defer store.Close()

	ev := CreateEvent(t, 1)
	InsertTestEvents(t, store, []*nip01.Event{ev})

	query := CreateQueryWithFilters(t, store, CreateFilter([]int{1}, 10))
	got := readEventsCollecting(t, query, false)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	pe := got[0]
	if len(pe.Bytes) == 0 {
		t.Fatalf("scan did not capture PotentialEvent.Bytes")
	}

	// Delete the event the scan already matched, simulating a delete
	// landing in the gap between scan and delivery.
	if err := store.DeleteAll([]*PotentialEvent{{Evsid: pe.Evsid}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.FindEventBytes(pe.Evsid); err == nil {
		t.Fatalf("setup: event is still readable from the store after delete")
	}

	// This is exactly what handlers.go's delivery loop does now: use
	// event.Bytes directly, with no second store read.
	var delivered nip01.Event
	if err := json.Unmarshal(pe.Bytes, &delivered); err != nil {
		t.Fatalf("PotentialEvent.Bytes is not valid JSON after the underlying event was deleted: %v", err)
	}
	if delivered.ID != ev.ID {
		t.Fatalf("delivered event ID = %s, want %s", delivered.ID, ev.ID)
	}
}
