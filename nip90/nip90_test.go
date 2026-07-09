package nip90

import (
	"testing"

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

func TestIsJobRequestResultKind(t *testing.T) {
	if !IsJobRequestKind(5001) || IsJobRequestKind(6001) {
		t.Errorf("IsJobRequestKind wrong for 5001/6001")
	}
	if !IsJobResultKind(6001) || IsJobResultKind(5001) {
		t.Errorf("IsJobResultKind wrong for 6001/5001")
	}
	if JobResultKindFor(5001) != 6001 {
		t.Errorf("JobResultKindFor(5001) = %d, want 6001", JobResultKindFor(5001))
	}
}

func TestNewJobRequestAndParse(t *testing.T) {
	inputs := []JobInput{{Data: "transcribe this", Type: InputTypeText}}
	ev, err := NewJobRequest(JobRequestParams{
		JobKind:  5000,
		Inputs:   inputs,
		Output:   "text/plain",
		BidMloki: 1000,
		Relays:   []string{"wss://relay.example"},
		Params:   map[string]string{"lang": "en"},
	})
	if err != nil {
		t.Fatalf("NewJobRequest() error = %v", err)
	}
	ev = signed(t, ev)

	jr, err := ParseJobRequest(ev)
	if err != nil {
		t.Fatalf("ParseJobRequest() error = %v", err)
	}
	if len(jr.Inputs) != 1 || jr.Inputs[0].Data != "transcribe this" {
		t.Errorf("Inputs = %v", jr.Inputs)
	}
	if jr.Output != "text/plain" {
		t.Errorf("Output = %q", jr.Output)
	}
	if jr.BidMloki != 1000 {
		t.Errorf("BidMloki = %d", jr.BidMloki)
	}
	if len(jr.Relays) != 1 || jr.Relays[0] != "wss://relay.example" {
		t.Errorf("Relays = %v", jr.Relays)
	}
	if got := jr.Params["lang"]; len(got) != 1 || got[0] != "en" {
		t.Errorf("Params[lang] = %v", got)
	}

	if err := ValidateJobRequest(ev); err != nil {
		t.Errorf("ValidateJobRequest() error = %v", err)
	}

	if _, err := NewJobRequest(JobRequestParams{JobKind: 7000, Inputs: inputs}); err == nil {
		t.Error("expected error for out-of-range job kind")
	}
}

func TestParseJobRequestErrors(t *testing.T) {
	tests := []struct {
		name string
		kind int
		tags [][]string
	}{
		{name: "kind out of range", kind: 4000, tags: nil},
		{name: "bad input type", kind: 5000, tags: [][]string{{"i", "data", "bogus"}}},
		{name: "bad bid", kind: 5000, tags: [][]string{{"bid", "not-a-number"}}},
		{name: "bad relay scheme", kind: 5000, tags: [][]string{{"relays", "https://relay.example"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			if _, err := ParseJobRequest(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestNewJobResultAndParse(t *testing.T) {
	reqEv := signed(t, &nip01.Event{Kind: 5000, Content: ""})

	resultEv, err := NewJobResult(JobResultParams{
		ResultKind:   JobResultKindFor(reqEv.Kind),
		RequestEvent: reqEv,
		Content:      "transcribed text",
		AmountMloki:  500,
		Bolt11:       "lnbc...",
	})
	if err != nil {
		t.Fatalf("NewJobResult() error = %v", err)
	}
	resultEv = signed(t, resultEv)

	jr, err := ParseJobResult(resultEv)
	if err != nil {
		t.Fatalf("ParseJobResult() error = %v", err)
	}
	if jr.RequestEventID != reqEv.ID {
		t.Errorf("RequestEventID = %q, want %q", jr.RequestEventID, reqEv.ID)
	}
	if jr.CustomerPubkey != reqEv.PubKey {
		t.Errorf("CustomerPubkey = %q, want %q", jr.CustomerPubkey, reqEv.PubKey)
	}
	if jr.AmountMloki != 500 || jr.Bolt11 != "lnbc..." {
		t.Errorf("AmountMloki/Bolt11 = %d/%q", jr.AmountMloki, jr.Bolt11)
	}

	if err := ValidateJobResult(resultEv); err != nil {
		t.Errorf("ValidateJobResult() error = %v", err)
	}

	if _, err := NewJobResult(JobResultParams{ResultKind: 5001, RequestEvent: reqEv}); err == nil {
		t.Error("expected error for out-of-range result kind")
	}
}

func TestParseJobResultMissingETag(t *testing.T) {
	ev := &nip01.Event{Kind: 6000, Tags: nil}
	if _, err := ParseJobResult(ev); err == nil {
		t.Error("expected error for missing e tag")
	}
}

func TestNewJobFeedbackAndParse(t *testing.T) {
	reqEv := signed(t, &nip01.Event{Kind: 5000})

	feedbackEv := signed(t, NewJobFeedback(JobFeedbackParams{
		RequestEvent: reqEv,
		Status:       StatusProcessing,
		StatusExtra:  "starting up",
	}))

	jf, err := ParseJobFeedback(feedbackEv)
	if err != nil {
		t.Fatalf("ParseJobFeedback() error = %v", err)
	}
	if jf.Status != StatusProcessing || jf.StatusExtra != "starting up" {
		t.Errorf("Status/StatusExtra = %q/%q", jf.Status, jf.StatusExtra)
	}
	if jf.RequestEventID != reqEv.ID {
		t.Errorf("RequestEventID = %q, want %q", jf.RequestEventID, reqEv.ID)
	}

	if err := ValidateJobFeedback(feedbackEv); err != nil {
		t.Errorf("ValidateJobFeedback() error = %v", err)
	}
}

func TestParseJobFeedbackErrors(t *testing.T) {
	tests := []struct {
		name string
		tags [][]string
	}{
		{name: "bad status", tags: [][]string{{"status", "bogus"}, {"e", "abc"}}},
		{name: "missing e tag", tags: [][]string{{"status", StatusSuccess}}},
		{name: "missing status", tags: [][]string{{"e", "abc"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: KindJobFeedback, Tags: tt.tags}
			if _, err := ParseJobFeedback(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
