package nippf

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip88"
)

func TestNewVote(t *testing.T) {
	x := PollExtras{Rec: []string{"a"}, NoteRequired: []string{"c"}, Expiration: 3000}
	p := testPoll(t, nip88.PollTypeSingle, append(x.Tags(), []string{"h", "ops"})...)
	ev, err := NewVote(p, pub(t, op1Priv), 10, []Choice{{Option: "c", Note: "the park"}})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"e", p.ID}, {"expiration", "3000"}, {"h", "ops"}, {"response", "c", "the park"}}
	if !sameTags(ev.Tags, want) || ev.Kind != nip88.KindPollResponse || ev.CreatedAt != 10 {
		t.Fatalf("vote: %+v", ev)
	}
	if err := ev.Sign(op1Priv); err != nil {
		t.Fatal(err)
	}
	if err := nip88.ValidatePollResponse(ev, p); err != nil {
		t.Fatalf("nip88 counts it: %v", err)
	}
	if _, err := NewVote(p, pub(t, op1Priv), 10, []Choice{{Option: "c", Note: " "}}); err == nil {
		t.Fatal("a noteRequired option without a note")
	}
	if _, err := NewVote(p, pub(t, op1Priv), 10, []Choice{{Option: "a"}, {Option: "b"}}); !errors.Is(err, nip88.ErrTooManyResponses) {
		t.Fatalf("two on a singlechoice poll: %v", err)
	}
	if _, err := NewVote(p, pub(t, op1Priv), 10, []Choice{{Option: "z"}}); !errors.Is(err, nip88.ErrUnknownOption) {
		t.Fatalf("an unknown option: %v", err)
	}
	multi := testPoll(t, nip88.PollTypeMultiple)
	if _, err := NewVote(multi, pub(t, op1Priv), 10, []Choice{{Option: "a"}, {Option: "a"}}); !errors.Is(err, nip88.ErrUnknownOption) {
		t.Fatalf("an option twice: %v", err)
	}
	if _, err := NewVote(multi, pub(t, op1Priv), 10, []Choice{{Option: "a"}, {Option: "b"}}); err != nil {
		t.Fatal(err)
	}
	res, err := NewPollResult(p, 20, StatusCancelled, "", nil)
	if err != nil || !sameTags(res.Tags, [][]string{{"e", p.ID}, {"expiration", "3000"}, {"h", "ops"}, {"status", "cancelled"}}) {
		t.Fatalf("poll result in a group: %v %v", err, res)
	}
}
