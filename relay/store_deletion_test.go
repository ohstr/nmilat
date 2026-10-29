package relay

import (
	"context"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/stretchr/testify/require"
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
