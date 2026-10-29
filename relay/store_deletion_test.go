package relay

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func (f *socialFixture) note(author testKey, content string) *nip01.Event {
	f.at++
	ev := &nip01.Event{PubKey: author.pub, CreatedAt: f.at, Kind: 1, Content: content}
	require.NoError(f.t, ev.Sign(author.priv))
	return ev
}

func (f *socialFixture) find(filter *nip01.SubscriptionFilter) []string {
	pes, err := f.store.FindEvents(context.Background(), filter)
	require.NoError(f.t, err)
	var ids []string
	for _, pe := range pes {
		ids = append(ids, pe.EventID)
	}
	return ids
}

// NIP-09: a relay applies a deletion request and keeps serving the request itself, by id and by kind and author,
// so clients of other relays learn of the deletion. One naming an event the relay lacks is served too.
func TestDeletionRequest_IsServedAfterItApplies(t *testing.T) {
	f := newSocialFixture(t)
	note := f.note(f.alice, "hello")
	f.insert(note)
	del := f.deletion(f.alice, note.ID)
	unknown := f.deletion(f.alice, strings.Repeat("ab", 32))
	f.insert(del, unknown)

	require.Empty(t, f.find(&nip01.SubscriptionFilter{IDs: []string{note.ID}}), "the note is deleted")
	require.Equal(t, []string{del.ID}, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}))
	require.ElementsMatch(t, []string{del.ID, unknown.ID}, f.find(&nip01.SubscriptionFilter{Kinds: []int{5}, Authors: []string{f.alice.pub}}))
	require.Equal(t, []string{del.ID}, f.find(&nip01.SubscriptionFilter{Kinds: []int{5}, Tags: map[string][]string{"e": {note.ID}}}))

	// The same request again is the same event, stored once.
	f.insert(del)
	require.Len(t, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}), 1)
}

// A deletion request against a deletion request has no effect, and one by another author deletes nothing; both are
// still served.
func TestDeletionRequest_CannotDeleteADeletionOrAnotherAuthorsEvent(t *testing.T) {
	f := newSocialFixture(t)
	note := f.note(f.alice, "hello")
	f.insert(note)
	del := f.deletion(f.alice, note.ID)
	f.insert(del)
	undo := f.deletion(f.alice, del.ID)
	foreign := f.deletion(f.bob, note.ID)
	other := f.note(f.alice, "kept")
	f.insert(undo, other, foreign)
	bobOn := f.deletion(f.bob, other.ID)
	f.insert(bobOn)

	require.Equal(t, []string{del.ID}, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}), "a deletion of a deletion has no effect")
	require.Equal(t, []string{other.ID}, f.find(&nip01.SubscriptionFilter{IDs: []string{other.ID}}), "another author's request deletes nothing")
	require.ElementsMatch(t, []string{undo.ID, foreign.ID, bobOn.ID}, f.find(&nip01.SubscriptionFilter{IDs: []string{undo.ID, foreign.ID, bobOn.ID}}))
}

// deletionStore opens the store at path the way a relay does.
func deletionStore(t *testing.T, path string) *EventStore {
	t.Helper()
	s, err := NewEventStore(path, &nip11.Limitation{MaxLimit: 1000}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	return s
}

// storeTheOldWay writes ev as versions before #209's fix stored a deletion request: the event row and no indexes.
// It also clears the mark the reindex leaves, as such a store never had it.
func storeTheOldWay(t *testing.T, s *EventStore, events ...*nip01.Event) {
	t.Helper()
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		for _, ev := range events {
			if _, err := s.insertEvent(tx, ev); err != nil {
				return err
			}
		}
		return tx.Bucket(storeMeta).Delete(deletionsIndexedKey)
	}))
}

// storedRows counts the event rows of kind in the events bucket, indexed or not.
func storedRows(t *testing.T, s *EventStore, kind int) int {
	t.Helper()
	all, err := s.FetchAll()
	require.NoError(t, err)
	n := 0
	for _, ev := range all {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

// A store holding deletion requests the old way, unindexed and one stored twice, indexes them when the relay opens
// it: each is served by id, by kind and author and by #e, stored once, counted, and a republish is a duplicate.
func TestStoredDeletionRequests_AreIndexedWhenTheStoreOpens(t *testing.T) {
	old := reindexBatch
	reindexBatch = 2 // several batches
	t.Cleanup(func() { reindexBatch = old })

	f := newSocialFixture(t)
	path := filepath.Join(t.TempDir(), "old.db")
	f.store = deletionStore(t, path)
	note := f.note(f.alice, "hello")
	other := f.note(f.bob, "kept")
	f.insert(note, other)
	del := f.deletion(f.alice, note.ID)
	unknown := f.deletion(f.alice, strings.Repeat("ab", 32))
	storeTheOldWay(t, f.store, del, unknown, del)
	require.Empty(t, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}), "seeded the old way: not served")
	f.store.Close()

	f.store = deletionStore(t, path)
	require.Equal(t, []string{del.ID}, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}))
	require.ElementsMatch(t, []string{del.ID, unknown.ID}, f.find(&nip01.SubscriptionFilter{Kinds: []int{5}, Authors: []string{f.alice.pub}}))
	require.Equal(t, []string{del.ID}, f.find(&nip01.SubscriptionFilter{Kinds: []int{5}, Tags: map[string][]string{"e": {note.ID}}}))
	require.Equal(t, 2, storedRows(t, f.store, 5), "the second copy is dropped")
	require.Equal(t, uint64(2), f.store.Counts().Kind(5))
	assertCountsExact(t, f.store)

	f.insert(del)
	require.Len(t, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}), 1, "a republish is a duplicate")
	require.Equal(t, 2, storedRows(t, f.store, 5))
	require.ElementsMatch(t, []string{note.ID, other.ID}, f.find(&nip01.SubscriptionFilter{Kinds: []int{1}}), "other events untouched")
	f.store.Close()

	// Run again, mark cleared: nothing changes.
	f.store = deletionStore(t, path)
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(storeMeta).Delete(deletionsIndexedKey) }))
	f.store.Close()
	f.store = deletionStore(t, path)
	t.Cleanup(f.store.Close)
	require.Len(t, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}), 1)
	require.Equal(t, 2, storedRows(t, f.store, 5))
	assertCountsExact(t, f.store)
}

// A deletion request stored indexed is left as it is; two indexed copies of one (as the index rebuild left them)
// become one; and a store already marked is not scanned again.
func TestStoredDeletionRequests_IndexedOnesAreLeftAlone(t *testing.T) {
	f := newSocialFixture(t)
	path := filepath.Join(t.TempDir(), "new.db")
	f.store = deletionStore(t, path)
	note := f.note(f.alice, "hello")
	f.insert(note)
	del := f.deletion(f.alice, note.ID)
	f.insert(del)
	twice := f.deletion(f.alice, strings.Repeat("cd", 32))
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error {
		for range 2 {
			if err := f.store.insertWithIndexes(tx, twice); err != nil {
				return err
			}
		}
		return tx.Bucket(storeMeta).Delete(deletionsIndexedKey)
	}))
	require.Len(t, f.find(&nip01.SubscriptionFilter{IDs: []string{twice.ID}}), 2)
	before := f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}})
	f.store.Close()

	f.store = deletionStore(t, path)
	require.Equal(t, before, f.find(&nip01.SubscriptionFilter{IDs: []string{del.ID}}))
	require.Len(t, f.find(&nip01.SubscriptionFilter{IDs: []string{twice.ID}}), 1)
	require.Equal(t, 2, storedRows(t, f.store, 5))
	assertCountsExact(t, f.store)

	// Marked: an unindexed row written now stays unindexed, as no scan runs.
	late := f.deletion(f.alice, strings.Repeat("ef", 32))
	require.NoError(t, f.store.db.Update(func(tx *bolt.Tx) error { _, err := f.store.insertEvent(tx, late); return err }))
	f.store.Close()
	f.store = deletionStore(t, path)
	t.Cleanup(f.store.Close)
	require.Empty(t, f.find(&nip01.SubscriptionFilter{IDs: []string{late.ID}}))
}
