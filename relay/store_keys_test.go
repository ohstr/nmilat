package relay

import (
	"context"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip01"
)

// The index write path and the index delete path build their keys
// independently, and delete discards every bolt error, so a layout mismatch
// between them leaves stale entries behind in silence. These tests pin the
// key shape and assert the two paths agree.

// queryIndexes are the buckets a filter scan walks. indexEvents,
// indexExpiration and indexZaps are covered separately where relevant.
var queryIndexes = []struct {
	name   string
	bucket []byte
	// keyLen is the expected key size, given the tag entry length for the
	// tag index (0 for the fixed-width ones).
	keyLen func(tagEntryLen int) int
}{
	// Every query index carries created_at ahead of evsid, so reverse
	// iteration is newest-first. indexCreatedAt already led with the
	// timestamp and is unchanged.
	{"id", indexID, func(int) int { return 32 + 8 + 8 }},
	{"pubkey", indexPubkey, func(int) int { return 32 + 8 + 8 }},
	{"kind", indexKind, func(int) int { return 8 + 8 + 8 }},
	{"kindPubkey", indexKindPubkey, func(int) int { return 8 + 32 + 8 + 8 }},
	{"createdAt", indexCreatedAt, func(int) int { return 8 + 32 + 8 }},
	{"tag", indexTag, func(entry int) int { return entry + 8 + 8 }},
}

func bucketKeys(t testing.TB, store *EventStore, bucket []byte) [][]byte {
	t.Helper()
	var keys [][]byte
	err := store.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			keys = append(keys, append([]byte(nil), k...))
			return nil
		})
	})
	if err != nil {
		t.Fatalf("read bucket: %v", err)
	}
	return keys
}

func countBucket(t testing.TB, store *EventStore, bucket []byte) int {
	t.Helper()
	return len(bucketKeys(t, store, bucket))
}

// evsidOf looks up the store-assigned sequence id for an event.
func evsidOf(t testing.TB, store *EventStore, ev *nip01.Event) uint64 {
	t.Helper()
	var pes []*PotentialEvent
	err := store.db.View(func(tx *bolt.Tx) error {
		var err error
		pes, err = store.findEventEvsidByEventID(context.Background(), tx, []string{ev.ID})
		return err
	})
	if err != nil {
		t.Fatalf("look up evsid: %v", err)
	}
	if len(pes) != 1 {
		t.Fatalf("looking up %s: got %d matches, want 1", ev.ID[:8], len(pes))
	}
	return pes[0].Evsid
}

func deleteEvents(t testing.TB, store *EventStore, events ...*nip01.Event) {
	t.Helper()
	var pes []*PotentialEvent
	for _, ev := range events {
		pes = append(pes, &PotentialEvent{Evsid: evsidOf(t, store, ev)})
	}
	task := NewEventDeleteTask(pes)
	store.Execute(context.Background(), task)
	select {
	case <-task.Completed():
	case err := <-task.Errors():
		t.Fatalf("delete events: %v", err)
	}
}

// TestIndexKeyLayout pins the key size written to every query index, so a
// change to the layout has to be deliberate and shows up here first.
func TestIndexKeyLayout(t *testing.T) {
	store := newStore(t)

	ev := CreateEventWithTimestamp(t, 1, uint64(time.Now().Unix()), []string{"t", "abc"})
	InsertTestEvents(t, store, []*nip01.Event{ev})

	const tagEntryLen = len("t") + len("abc")

	for _, idx := range queryIndexes {
		keys := bucketKeys(t, store, idx.bucket)
		if len(keys) != 1 {
			t.Errorf("%s index: got %d keys, want 1", idx.name, len(keys))
			continue
		}
		if want := idx.keyLen(tagEntryLen); len(keys[0]) != want {
			t.Errorf("%s index: key is %d bytes, want %d", idx.name, len(keys[0]), want)
		}
	}
}

// TestIndexKeyRoundTrip checks that every cursor's parseKey recovers the
// evsid from a key its own index actually holds, across edge-value kinds
// and timestamps.
func TestIndexKeyRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		kind      int
		createdAt uint64
	}{
		{"epoch", 1, 1},
		{"typical", 1, uint64(time.Now().Unix())},
		{"kind zero", 0, uint64(time.Now().Unix())},
		{"large kind", 65535, uint64(time.Now().Unix())},
		{"far future", 1, 1 << 40},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			ev := CreateEventWithTimestamp(t, tc.kind, tc.createdAt, []string{"t", "rt"})
			InsertTestEvents(t, store, []*nip01.Event{ev})

			evsid := evsidOf(t, store, ev)

			shapes := map[string][]*storeCursor{}
			byID, err := createCursorsByID([]string{ev.ID})
			if err != nil {
				t.Fatalf("id cursors: %v", err)
			}
			shapes["id"] = byID
			byAuthor, err := createCursorsByAuthors([]string{ev.PubKey})
			if err != nil {
				t.Fatalf("author cursors: %v", err)
			}
			shapes["pubkey"] = byAuthor
			byKind, err := createCursorsByKinds([]int{tc.kind})
			if err != nil {
				t.Fatalf("kind cursors: %v", err)
			}
			shapes["kind"] = byKind
			byKindAuthor, err := createCursorsByKindsAndAuthors([]int{tc.kind}, []string{ev.PubKey})
			if err != nil {
				t.Fatalf("kind+author cursors: %v", err)
			}
			shapes["kindPubkey"] = byKindAuthor
			byTag, err := createCursorsByTags(map[string][]string{"t": {"rt"}})
			if err != nil {
				t.Fatalf("tag cursors: %v", err)
			}
			shapes["tag"] = byTag
			shapes["createdAt"] = []*storeCursor{defaultCursor()}

			buckets := map[string][]byte{
				"id": indexID, "pubkey": indexPubkey, "kind": indexKind,
				"kindPubkey": indexKindPubkey, "tag": indexTag, "createdAt": indexCreatedAt,
			}

			for name, cursors := range shapes {
				keys := bucketKeys(t, store, buckets[name])
				if len(keys) != 1 {
					t.Errorf("%s: got %d keys, want 1", name, len(keys))
					continue
				}
				if !cursors[0].matchKey(keys[0]) {
					t.Errorf("%s: matchKey rejected a key from its own index", name)
					continue
				}
				_, gotEvsid, err := cursors[0].parseKey(keys[0])
				if err != nil {
					t.Errorf("%s: parseKey: %v", name, err)
					continue
				}
				if gotEvsid != evsid {
					t.Errorf("%s: parsed evsid %d, want %d", name, gotEvsid, evsid)
				}
			}
		})
	}
}

// TestIndexLifecycleLeavesNothingBehind is the guard that the write and
// delete paths agree: after deleting every event, no query index may hold a
// single key.
func TestIndexLifecycleLeavesNothingBehind(t *testing.T) {
	cases := []struct {
		name string
		tags [][]string
	}{
		{"no tags", nil},
		{"one tag", [][]string{{"t", "a"}}},
		{"several tags", [][]string{{"t", "a"}, {"e", "b"}, {"p", "c"}}},
		{"more tags than MaxIndexableTags", [][]string{
			{"t", "a"}, {"e", "b"}, {"p", "c"}, {"d", "e"}, {"g", "f"}, {"h", "g"}, {"i", "h"},
		}},
		{"duplicate tag values", [][]string{{"t", "same"}, {"t", "same"}}},
		{"empty tag value", [][]string{{"t", ""}}},
		{"unicode tag value", [][]string{{"t", "héllo-世界"}}},
		{"long tag value", [][]string{{"t", string(make([]byte, 512))}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)

			ev := CreateEventWithTimestamp(t, 1, uint64(time.Now().Unix()), tc.tags...)
			InsertTestEvents(t, store, []*nip01.Event{ev})

			for _, idx := range queryIndexes {
				if idx.bucket == nil {
					continue
				}
				if countBucket(t, store, idx.bucket) == 0 && idx.name != "tag" {
					t.Errorf("%s index: nothing written for the inserted event", idx.name)
				}
			}
			if countBucket(t, store, indexEvents) != 1 {
				t.Fatalf("events bucket: got %d, want 1", countBucket(t, store, indexEvents))
			}

			deleteEvents(t, store, ev)

			for _, idx := range queryIndexes {
				if n := countBucket(t, store, idx.bucket); n != 0 {
					t.Errorf("%s index: %d stale keys after delete", idx.name, n)
				}
			}
			if n := countBucket(t, store, indexEvents); n != 0 {
				t.Errorf("events bucket: %d stale entries after delete", n)
			}
		})
	}
}

// TestIndexCountsScaleWithEvents pins the per-event key count in each
// fixed-width index, so a double-write or a missed write is caught.
func TestIndexCountsScaleWithEvents(t *testing.T) {
	store := newStore(t)

	const n = 25
	var events []*nip01.Event
	base := uint64(time.Now().Unix())
	for i := 0; i < n; i++ {
		events = append(events, signEventAt(t, probeKeyA, 1, base+uint64(i),
			fmt.Sprintf("count %d", i), []string{"t", fmt.Sprintf("v%d", i)}))
	}
	InsertTestEvents(t, store, events)

	for _, idx := range []struct {
		name   string
		bucket []byte
	}{
		{"id", indexID}, {"pubkey", indexPubkey}, {"kind", indexKind},
		{"kindPubkey", indexKindPubkey}, {"createdAt", indexCreatedAt}, {"tag", indexTag},
	} {
		if got := countBucket(t, store, idx.bucket); got != n {
			t.Errorf("%s index: got %d keys for %d events, want %d", idx.name, got, n, n)
		}
	}

	deleteEvents(t, store, events...)

	for _, idx := range queryIndexes {
		if got := countBucket(t, store, idx.bucket); got != 0 {
			t.Errorf("%s index: %d stale keys after deleting every event", idx.name, got)
		}
	}
}

// A replaceable event supersedes the previous one, and the superseded
// event's index entries must go with it.
func TestReplaceableEventLeavesNoStaleIndexEntries(t *testing.T) {
	store := newStore(t)

	base := uint64(time.Now().Unix())
	older := signEventAt(t, probeKeyA, 0, base, "older profile", []string{"t", "old"})
	InsertTestEvents(t, store, []*nip01.Event{older})

	newer := signEventAt(t, probeKeyA, 0, base+1, "newer profile", []string{"t", "new"})
	InsertTestEvents(t, store, []*nip01.Event{newer})

	if got := countBucket(t, store, indexEvents); got != 1 {
		t.Fatalf("events bucket: got %d entries, want 1 after replacement", got)
	}
	for _, idx := range queryIndexes {
		if got := countBucket(t, store, idx.bucket); got != 1 {
			t.Errorf("%s index: got %d keys, want 1 after replacement", idx.name, got)
		}
	}

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{Kinds: []int{0}}))
	got := readEventsCollecting(t, q, false)
	assertIDsInOrder(t, got, []*nip01.Event{newer})
}

// An ephemeral event with no expiration tag still gets a default retention
// window written to the expiration index on insert. The delete path derived
// the expiration from the tags alone, so that entry outlived the event.
func TestEphemeralEventExpirationEntryIsRemoved(t *testing.T) {
	store := newStore(t)

	ev := CreateEventWithTimestamp(t, 20001, uint64(time.Now().Unix()))
	InsertTestEvents(t, store, []*nip01.Event{ev})

	if got := countBucket(t, store, indexExpiration); got != 1 {
		t.Fatalf("expiration index: got %d entries after inserting an ephemeral event, want 1", got)
	}

	deleteEvents(t, store, ev)

	if got := countBucket(t, store, indexExpiration); got != 0 {
		t.Errorf("expiration index: %d stale entries after deleting the event", got)
	}
}

// An explicit NIP-40 expiration tag must round-trip the same way.
func TestExpirationTagEntryIsRemoved(t *testing.T) {
	store := newStore(t)

	exp := uint64(time.Now().Add(time.Hour).Unix())
	ev := CreateEventWithTimestamp(t, 1, uint64(time.Now().Unix()),
		[]string{"expiration", fmt.Sprintf("%d", exp)})
	InsertTestEvents(t, store, []*nip01.Event{ev})

	if got := countBucket(t, store, indexExpiration); got != 1 {
		t.Fatalf("expiration index: got %d entries, want 1", got)
	}

	deleteEvents(t, store, ev)

	if got := countBucket(t, store, indexExpiration); got != 0 {
		t.Errorf("expiration index: %d stale entries after delete", got)
	}
}
