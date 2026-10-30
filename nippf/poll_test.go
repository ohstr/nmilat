package nippf

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip88"
)

func testPoll(t *testing.T, pollType string, extra ...[]string) *nip88.Poll {
	t.Helper()
	ends := time.Unix(2000, 0)
	ev := nip88.NewPoll(nip88.PollParams{Question: "Where?", PollType: pollType, EndsAt: &ends,
		Options: []nip88.PollOption{{ID: "a", Label: "Library"}, {ID: "b", Label: "Café"}, {ID: "c", Label: "Other"}}})
	ev.Tags = append(ev.Tags, extra...)
	ev.CreatedAt = 1
	if err := ev.Sign(authorPriv); err != nil {
		t.Fatal(err)
	}
	p, err := nip88.ParsePoll(ev)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPollExtras(t *testing.T) {
	x := PollExtras{Rec: []string{"a"}, NoteRequired: []string{"c"}, Why: "It is free.", Expiration: 3000}
	p := testPoll(t, nip88.PollTypeSingle, append(x.Tags(), []string{"rec", "zz"}, []string{"noteRequired", "zz"})...)
	got := ParsePollExtras(p)
	if !slices.Equal(got.Rec, x.Rec) || !slices.Equal(got.NoteRequired, x.NoteRequired) || got.Why != x.Why || got.Expiration != 3000 {
		t.Fatalf("extras: %+v", got)
	}
	// Two why tags: none is read.
	if w := ParsePollExtras(testPoll(t, "", []string{"why", "one"}, []string{"why", "two"})).Why; w != "" {
		t.Fatalf("why: %q", w)
	}
	// A vote nip88 accepts stays accepted with a note; the note is read, not counted.
	vote := nip88.NewPollResponse(nip88.PollResponseParams{PollEventID: p.ID, OptionIDs: []string{"c"}})
	vote.Tags[1] = append(vote.Tags[1], "the park")
	if err := vote.Sign(op1Priv); err != nil {
		t.Fatal(err)
	}
	if err := nip88.ValidatePollResponse(vote, p); err != nil {
		t.Fatalf("nip88 refuses a vote with a note: %v", err)
	}
	if n := VoteNotes(vote); n["c"] != "the park" || len(n) != 1 {
		t.Fatalf("notes: %v", n)
	}
	blank := &nip01.Event{Tags: [][]string{{"response", "a", "  "}}}
	if len(VoteNotes(blank)) != 0 {
		t.Fatal("a blank note is no note")
	}
}

func TestPollResult(t *testing.T) {
	single := testPoll(t, nip88.PollTypeSingle, []string{"expiration", "3000"})
	multi := testPoll(t, nip88.PollTypeMultiple)
	mk := func(p *nip88.Poll, author string, at int64, eid string, more ...[]string) *Result {
		ev := nip01.NewUnsignedEvent(KindResult, author, "", append([][]string{{"e", p.ID}}, more...)...)
		ev.CreatedAt, ev.ID = uint64(at), eid
		r, err := ParseResult(ev)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ok := []struct {
		p    *nip88.Poll
		more [][]string
	}{
		{single, [][]string{{"status", "decided"}, {"response", "a"}}},
		{multi, [][]string{{"status", "decided"}, {"response", "a"}, {"response", "b"}}},
		{single, [][]string{{"status", "cancelled"}}},
	}
	for _, c := range ok {
		if err := CheckPollResult(c.p, mk(c.p, c.p.PubKey, 1, id('1'), c.more...)); err != nil {
			t.Fatalf("%v: %v", c.more, err)
		}
	}
	bad := []struct {
		p    *nip88.Poll
		more [][]string
	}{
		{single, [][]string{{"status", "decided"}, {"response", "a"}, {"response", "b"}}}, // one for singlechoice
		{single, [][]string{{"status", "decided"}, {"response", "z"}}},                    // an existing option
		{multi, [][]string{{"status", "decided"}, {"response", "a"}, {"response", "a"}}},  // once each
		{single, [][]string{{"status", "decided"}}},                                       // names an option
		{single, [][]string{{"status", "decided"}, {"answer", "0", "x"}}},                 // no answer
		{single, [][]string{{"status", "default"}, {"response", "a"}}},                    // decided or cancelled
		{single, [][]string{{"status", "cancelled"}, {"response", "a"}}},                  // none
	}
	for _, c := range bad {
		if err := CheckPollResult(c.p, mk(c.p, c.p.PubKey, 1, id('1'), c.more...)); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("%v: got %v", c.more, err)
		}
	}
	decided := mk(single, single.PubKey, 100, id('2'), []string{"status", "decided"}, []string{"response", "a"})
	cancelled := mk(single, single.PubKey, 100, id('1'), []string{"status", "cancelled"})
	byOther := mk(single, pub(t, op1Priv), 10, id('0'), []string{"status", "cancelled"})
	closing := ClosingPollResult(single, []*Result{decided, cancelled, byOther})
	if closing != cancelled {
		t.Fatalf("the earliest by the author, ties to the lowest id: %+v", closing)
	}
	if PollState(single, nil, 1500) != StateOpen || PollState(single, nil, 2001) != StateEnded ||
		PollState(single, closing, 1500) != StateCancelled || PollState(single, closing, 3001) != StateExpired {
		t.Fatal("poll states")
	}
	ev, err := NewPollResult(single, 5, StatusDecided, "booked", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	if !sameTags(ev.Tags, [][]string{{"e", single.ID}, {"expiration", "3000"}, {"status", "decided"}, {"response", "a"}}) || ev.PubKey != single.PubKey {
		t.Fatalf("poll result: %v", ev.Tags)
	}
	if _, err := NewPollResult(single, 5, StatusDecided, "", []string{"a", "b"}); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("got %v", err)
	}
}
