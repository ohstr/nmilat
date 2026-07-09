package nip88

import (
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"

func signed(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func TestNewPollAndParsePoll(t *testing.T) {
	opts := []PollOption{{ID: "1", Label: "Yes"}, {ID: "2", Label: "No"}}
	endsAt := time.Unix(2000000000, 0)

	ev := NewPoll(PollParams{
		Question: "Do you like polls?",
		Options:  opts,
		PollType: PollTypeSingle,
		Relays:   []string{"wss://relay.example"},
		EndsAt:   &endsAt,
	})
	ev = signed(t, ev)

	poll, err := ParsePoll(ev)
	if err != nil {
		t.Fatalf("ParsePoll() error = %v", err)
	}
	if poll.Question != "Do you like polls?" {
		t.Errorf("Question = %q", poll.Question)
	}
	if len(poll.Options) != 2 {
		t.Fatalf("Options = %v", poll.Options)
	}
	if poll.PollType != PollTypeSingle {
		t.Errorf("PollType = %q", poll.PollType)
	}
	if poll.EndsAt == nil || !poll.EndsAt.Equal(endsAt) {
		t.Errorf("EndsAt = %v, want %v", poll.EndsAt, endsAt)
	}

	if err := ValidatePoll(ev); err != nil {
		t.Errorf("ValidatePoll() error = %v", err)
	}
}

func TestParsePollErrors(t *testing.T) {
	tests := []struct {
		name string
		tags [][]string
	}{
		{name: "no options", tags: nil},
		{name: "one option", tags: [][]string{{"option", "1", "Yes"}}},
		{name: "duplicate option ids", tags: [][]string{{"option", "1", "Yes"}, {"option", "1", "No"}}},
		{name: "bad polltype", tags: [][]string{{"option", "1", "Yes"}, {"option", "2", "No"}, {"polltype", "bogus"}}},
		{name: "bad relay scheme", tags: [][]string{{"option", "1", "Yes"}, {"option", "2", "No"}, {"relay", "https://relay.example"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: KindPoll, Content: "q", Tags: tt.tags}
			if _, err := ParsePoll(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestNewPollResponseAndValidate(t *testing.T) {
	opts := []PollOption{{ID: "1", Label: "Yes"}, {ID: "2", Label: "No"}}
	pollEv := signed(t, NewPoll(PollParams{Question: "q?", Options: opts, PollType: PollTypeSingle}))
	poll, err := ParsePoll(pollEv)
	if err != nil {
		t.Fatalf("ParsePoll() error = %v", err)
	}

	respEv := signed(t, NewPollResponse(PollResponseParams{PollEventID: pollEv.ID, OptionIDs: []string{"1"}}))
	if err := ValidatePollResponse(respEv, poll); err != nil {
		t.Errorf("ValidatePollResponse() error = %v", err)
	}

	// Structural-only validation (no poll available) should still pass.
	if err := ValidatePollResponse(respEv, nil); err != nil {
		t.Errorf("ValidatePollResponse(nil poll) error = %v", err)
	}

	// Invalid option for this poll.
	badResp := signed(t, NewPollResponse(PollResponseParams{PollEventID: pollEv.ID, OptionIDs: []string{"99"}}))
	if err := ValidatePollResponse(badResp, poll); err == nil {
		t.Error("expected error for unknown option id")
	}

	// Multiple response tags on a singlechoice poll.
	multiResp := signed(t, NewPollResponse(PollResponseParams{PollEventID: pollEv.ID, OptionIDs: []string{"1", "2"}}))
	if err := ValidatePollResponse(multiResp, poll); err == nil {
		t.Error("expected error for multiple responses on singlechoice poll")
	}

	// Wrong poll id.
	otherEventID := strings.Repeat("0", 64)
	wrongPoll := signed(t, NewPollResponse(PollResponseParams{PollEventID: otherEventID, OptionIDs: []string{"1"}}))
	if err := ValidatePollResponse(wrongPoll, poll); err == nil {
		t.Error("expected error for mismatched poll id")
	}
}

func TestParsePollResponseErrors(t *testing.T) {
	tests := []struct {
		name string
		tags [][]string
	}{
		{name: "missing e tag", tags: [][]string{{"response", "1"}}},
		{name: "missing response tag", tags: [][]string{{"e", "e7f4bd16c90532504b2a6582531d27926e838dd9652a225eecbf8943644026b"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: KindPollResponse, Tags: tt.tags}
			if _, err := ParsePollResponse(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
