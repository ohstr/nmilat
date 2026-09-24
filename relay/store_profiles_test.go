package relay

import (
	"context"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// FetchProfileEvents parses the kind+pubkey index key by byte offset to
// recover an evsid. A layout change that leaves the key long enough to pass
// its length guard makes it read the wrong bytes, look up an evsid that
// doesn't exist, and return nothing -- with no error anywhere. These tests
// are what turns that into a failure.

func TestFetchProfileEventsReturnsLatestPerPubkey(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	// Two authors, each with a superseded and a current profile.
	oldA := signEventAt(t, probeKeyA, 0, base, `{"name":"a-old"}`)
	InsertTestEvents(t, store, []*nip01.Event{oldA})
	newA := signEventAt(t, probeKeyA, 0, base+10, `{"name":"a-new"}`)
	InsertTestEvents(t, store, []*nip01.Event{newA})

	oldB := signEventAt(t, probeKeyB, 0, base+1, `{"name":"b-old"}`)
	InsertTestEvents(t, store, []*nip01.Event{oldB})
	newB := signEventAt(t, probeKeyB, 0, base+11, `{"name":"b-new"}`)
	InsertTestEvents(t, store, []*nip01.Event{newB})

	got, err := store.FetchProfileEvents(context.Background(), []string{newA.PubKey, newB.PubKey})
	if err != nil {
		t.Fatalf("FetchProfileEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d profiles, want 2", len(got))
	}

	byPubkey := map[string]*nip01.Event{}
	for _, ev := range got {
		byPubkey[ev.PubKey] = ev
	}
	for _, want := range []*nip01.Event{newA, newB} {
		ev, ok := byPubkey[want.PubKey]
		if !ok {
			t.Errorf("no profile returned for %s", want.PubKey[:8])
			continue
		}
		if ev.ID != want.ID {
			t.Errorf("%s: got profile %q, want %q", want.PubKey[:8], ev.Content, want.Content)
		}
	}
}

func TestFetchProfileEventsSkipsUnknownAndMalformed(t *testing.T) {
	store := newStore(t)

	known := signEventAt(t, probeKeyA, 0, uint64(time.Now().Unix()), `{"name":"known"}`)
	InsertTestEvents(t, store, []*nip01.Event{known})

	cases := []struct {
		name    string
		pubkeys []string
		want    int
	}{
		{"empty input", nil, 0},
		{"unknown pubkey", []string{"00000000000000000000000000000000000000000000000000000000000000aa"}, 0},
		{"malformed hex", []string{"not-hex"}, 0},
		{"wrong length", []string{"abcd"}, 0},
		{"known plus unknown", []string{known.PubKey, "00000000000000000000000000000000000000000000000000000000000000aa"}, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.FetchProfileEvents(context.Background(), tc.pubkeys)
			if err != nil {
				t.Fatalf("FetchProfileEvents: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d profiles, want %d", len(got), tc.want)
			}
		})
	}
}

// A pubkey with non-profile events but no kind 0 must return nothing rather
// than some other kind's event.
func TestFetchProfileEventsIgnoresOtherKinds(t *testing.T) {
	store := newStore(t)

	note := signEventAt(t, probeKeyA, 1, uint64(time.Now().Unix()), "just a note")
	InsertTestEvents(t, store, []*nip01.Event{note})

	got, err := store.FetchProfileEvents(context.Background(), []string{note.PubKey})
	if err != nil {
		t.Fatalf("FetchProfileEvents: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d profiles for an author with no kind 0, want 0", len(got))
	}
}
