package nippf

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip88"
	"github.com/ohstr/nmilat/utils"
)

// Keys of the tests: the author, three operators, an observer, a stranger.
const (
	authorPriv   = "0000000000000000000000000000000000000000000000000000000000000001"
	op1Priv      = "0000000000000000000000000000000000000000000000000000000000000002"
	op2Priv      = "0000000000000000000000000000000000000000000000000000000000000003"
	op3Priv      = "0000000000000000000000000000000000000000000000000000000000000004"
	observerPriv = "0000000000000000000000000000000000000000000000000000000000000005"
	strangerPriv = "0000000000000000000000000000000000000000000000000000000000000006"
	alertID      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func pub(t testing.TB, priv string) string {
	t.Helper()
	p, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The spec's examples (NIP-PF.md at 503d428, "Examples"), verbatim but for
// their placeholders (<operator 1>, <form id>, …), which the tests fill.
const (
	specPrivateForm = `{
  "kind": 1069,
  "content": "Restart the payment service?",
  "tags": [
    ["context", "Memory use grew from 2 GB to 7 GB in 6 hours; a restart takes about 40 seconds and drops in-flight requests."],
    ["e", "<alert event id>"],
    ["p", "<operator 1>"], ["p", "<operator 2>"], ["p", "<operator 3>"],
    ["p", "<observer>", "", "observer"],
    ["quorum", "2"],
    ["priority", "high"],
    ["endsAt", "1793430000"],
    ["expiration", "1794034800"],
    ["question", "0", "Restart now?", "singlechoice", "Memory will run out in about an hour at this rate."],
    ["option", "restart", "Restart now", "0"],
    ["option", "wait", "Wait", "0"],
    ["option", "other", "Something else", "0"],
    ["rec", "restart"],
    ["noteRequired", "other"],
    ["default", "0", "wait"],
    ["question", "1", "Restart no later than", "time"],
    ["optional", "1"],
    ["max", "1", "1793430000"]
  ]
}`
	specPrivateResponse = `{
  "kind": 1019,
  "content": "",
  "tags": [
    ["e", "<form id>"],
    ["p", "<author>"],
    ["expiration", "1794034800"],
    ["response", "restart", "Fine, traffic is low now"]
  ]
}`
	specPrivateResult = `{
  "kind": 1070,
  "content": "Restarted at 14:02; memory back to 2 GB.",
  "tags": [
    ["e", "<form id>"],
    ["p", "<operator 1>"], ["p", "<operator 2>"], ["p", "<operator 3>"],
    ["expiration", "1794034800"],
    ["status", "decided"],
    ["response", "restart"]
  ]
}`
	specPublicForm = `{
  "kind": 1069,
  "content": "Planning the next meetup",
  "tags": [
    ["alt", "Form: Planning the next meetup"],
    ["endsAt", "1793430000"],
    ["relay", "wss://relay.example.com"],
    ["question", "0", "Where?", "singlechoice", "The library has a free room with a projector."],
    ["question", "1", "Which days work for you?", "multiplechoice"],
    ["question", "2", "How many people will you bring?", "number"],
    ["question", "3", "Anything we should know?", "text"],
    ["optional", "3"],
    ["min", "2", "0"],
    ["max", "2", "5"],
    ["option", "library", "Library", "0"],
    ["option", "cafe", "Café", "0"],
    ["option", "other", "Other", "0"],
    ["option", "sat", "Saturday", "1"],
    ["option", "sun", "Sunday", "1"],
    ["rec", "library"],
    ["noteRequired", "other"]
  ]
}`
	specPublicResponse = `{
  "kind": 1019,
  "content": "",
  "tags": [
    ["e", "<form id>"],
    ["p", "<author>"],
    ["response", "other", "The park, if it is sunny"],
    ["response", "sat", "Only after 14:00"],
    ["answer", "2", "1"]
  ]
}`
	specPollResult = `{
  "kind": 1070,
  "content": "The library is booked.",
  "tags": [
    ["e", "<poll id>"],
    ["status", "decided"],
    ["response", "a"]
  ]
}`
)

// fill replaces the examples' placeholders.
func fill(t testing.TB, doc string, extra ...string) string {
	t.Helper()
	pairs := []string{
		"<alert event id>", alertID,
		"<operator 1>", pub(t, op1Priv), "<operator 2>", pub(t, op2Priv), "<operator 3>", pub(t, op3Priv),
		"<observer>", pub(t, observerPriv), "<author>", pub(t, authorPriv),
	}
	return strings.NewReplacer(append(pairs, extra...)...).Replace(doc)
}

// event reads an example and signs it as priv at createdAt.
func event(t testing.TB, doc, priv string, createdAt int64) *nip01.Event {
	t.Helper()
	var ev nip01.Event
	if err := json.Unmarshal([]byte(doc), &ev); err != nil {
		t.Fatal(err)
	}
	ev.CreatedAt = uint64(createdAt)
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return &ev
}

// sameTags: the same tags as a multiset (the order of tags is free).
func sameTags(a, b [][]string) bool {
	key := func(ts [][]string) []string {
		var out []string
		for _, t := range ts {
			j, _ := json.Marshal(t)
			out = append(out, string(j))
		}
		sort.Strings(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

func TestSpecPrivateApprovalWithQuorum(t *testing.T) {
	formEv := event(t, fill(t, specPrivateForm), authorPriv, 1793400000)
	f, err := ParseForm(formEv, true)
	if err != nil {
		t.Fatal(err)
	}
	ops := []string{pub(t, op1Priv), pub(t, op2Priv), pub(t, op3Priv)}
	if f.Title != "Restart the payment service?" || f.Quorum != 2 || !f.Priority || f.EndsAt != 1793430000 ||
		f.Expiration != 1794034800 || len(f.Questions) != 2 || f.ReadOnly || !slices.Equal(f.Events, []string{alertID}) {
		t.Fatalf("form: %+v", f)
	}
	if !slices.Equal(f.Responders(), ops) || !slices.Equal(f.Observers(), []string{pub(t, observerPriv)}) {
		t.Fatalf("responders %v observers %v", f.Responders(), f.Observers())
	}
	q0, q1 := f.Questions[0], f.Questions[1]
	restart, _ := q0.Option("restart")
	other, _ := q0.Option("other")
	if q0.Type != TypeSingle || q0.Why == "" || !restart.Rec || !other.NoteRequired || !slices.Equal(q0.Defaults, []string{"wait"}) {
		t.Fatalf("q0: %+v", q0)
	}
	if q1.Type != TypeTime || !q1.Optional || q1.Max != "1793430000" || q1.Min != "" {
		t.Fatalf("q1: %+v", q1)
	}
	// Round trip: the form's tags written back are the example's.
	if !sameTags(f.Tags(), formEv.Tags) {
		t.Fatalf("tags written back:\n%v\nwant\n%v", f.Tags(), formEv.Tags)
	}
	built, err := f.Event(f.Author, 1793400000)
	if err != nil {
		t.Fatal(err)
	}
	if built.Content != formEv.Content || !sameTags(built.Tags, formEv.Tags) {
		t.Fatalf("built: %v", built.Tags)
	}

	// The response, and the same built by NewResponse.
	respEv := event(t, fill(t, specPrivateResponse, "<form id>", f.ID), op1Priv, 1793410000)
	r, err := ParseResponse(respEv)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(r); err != nil {
		t.Fatal(err)
	}
	if r.FormAuthor != f.Author || r.Expiration != 1794034800 ||
		!slices.Equal(r.Choices, []Choice{{Option: "restart", Note: "Fine, traffic is low now"}}) {
		t.Fatalf("response: %+v", r)
	}
	again, err := f.NewResponse(pub(t, op1Priv), 1793410000, r.Choices, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTags(again.Tags, respEv.Tags) || again.Content != "" {
		t.Fatalf("NewResponse: %v", again.Tags)
	}

	// The result, and the same built by NewResult.
	resEv := event(t, fill(t, specPrivateResult, "<form id>", f.ID), authorPriv, 1793420000)
	res, err := ParseResult(resEv)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckResult(res); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Responders, ops) || res.Status != StatusDecided || res.Content != "Restarted at 14:02; memory back to 2 GB." {
		t.Fatalf("result: %+v", res)
	}
	resAgain, err := f.NewResult(1793420000, StatusDecided, res.Content, res.Choices, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameTags(resAgain.Tags, resEv.Tags) {
		t.Fatalf("NewResult: %v", resAgain.Tags)
	}

	// Lifecycle: the result closes the form as decided; the response counts.
	closing := f.Closing([]*Result{res})
	if closing != res || f.State(closing, 1793425000) != StateDecided || f.State(closing, 1794034801) != StateExpired {
		t.Fatalf("closing %v, state %s", closing, f.State(closing, 1793425000))
	}
	sel := f.Select([]*Response{r}, closing)
	tally := f.Tally(sel)
	if len(sel) != 1 || tally.Responses != 1 || tally.QuorumMet || tally.Questions[0].Counts["restart"] != 1 ||
		tally.Questions[0].Notes["restart"][0].Text != "Fine, traffic is low now" {
		t.Fatalf("tally: %+v", tally)
	}
}

func TestSpecPublicForm(t *testing.T) {
	formEv := event(t, specPublicForm, authorPriv, 1793000000)
	f, err := ParseForm(formEv, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.Alt != "Form: Planning the next meetup" || !slices.Equal(f.Relays, []string{"wss://relay.example.com"}) ||
		len(f.Questions) != 4 || len(f.Parties) != 0 {
		t.Fatalf("form: %+v", f)
	}
	if q := f.Questions[2]; q.Type != TypeNumber || q.Min != "0" || q.Max != "5" {
		t.Fatalf("q2: %+v", q)
	}
	if q := f.Questions[3]; q.Type != TypeText || !q.Optional {
		t.Fatalf("q3: %+v", q)
	}
	if !sameTags(f.Tags(), formEv.Tags) {
		t.Fatalf("tags written back: %v", f.Tags())
	}
	built, err := f.Event(f.Author, 1793000000)
	if err != nil || !sameTags(built.Tags, formEv.Tags) {
		t.Fatalf("built: %v %v", err, built)
	}
	// Anyone may respond to a public form without responders.
	respEv := event(t, fill(t, specPublicResponse, "<form id>", f.ID), strangerPriv, 1793100000)
	r, err := ParseResponse(respEv)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(r); err != nil {
		t.Fatal(err)
	}
	if !f.Allowed(r.Author) || len(r.Choices) != 2 || r.Answers[0] != (Answer{Question: 2, Value: "1"}) {
		t.Fatalf("response: %+v", r)
	}
	again, err := f.NewResponse(r.Author, 1793100000, r.Choices, r.Answers)
	if err != nil || !sameTags(again.Tags, respEv.Tags) {
		t.Fatalf("NewResponse: %v %v", err, again)
	}
	tally := f.Tally(f.Select([]*Response{r}, nil))
	if tally.Questions[0].Counts["other"] != 1 || tally.Questions[1].Counts["sat"] != 1 || tally.Questions[1].Counts["sun"] != 0 ||
		tally.Questions[2].Answers[0].Value != "1" || len(tally.Questions[3].Answers) != 0 || !tally.QuorumMet {
		t.Fatalf("tally: %+v", tally)
	}
	if f.State(nil, 1793000001) != StateOpen || f.State(nil, 1793430001) != StateEnded || !f.State(nil, 1793430001).Closed() {
		t.Fatal("states")
	}
}

func TestSpecClosingAPoll(t *testing.T) {
	pollEv := nip88.NewPoll(nip88.PollParams{Question: "Where?", Options: []nip88.PollOption{{ID: "a", Label: "Library"}, {ID: "b", Label: "Café"}}})
	if err := pollEv.Sign(authorPriv); err != nil {
		t.Fatal(err)
	}
	p, err := nip88.ParsePoll(pollEv)
	if err != nil {
		t.Fatal(err)
	}
	resEv := event(t, fill(t, specPollResult, "<poll id>", p.ID), authorPriv, 1793000000)
	res, err := ParseResult(resEv)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPollResult(p, res); err != nil {
		t.Fatal(err)
	}
	if ClosingPollResult(p, []*Result{res}) != res || PollState(p, res, 1793000001) != StateDecided {
		t.Fatal("the result closes the poll")
	}
	again, err := NewPollResult(p, 1793000000, StatusDecided, res.Content, []string{"a"})
	if err != nil || !sameTags(again.Tags, resEv.Tags) {
		t.Fatalf("NewPollResult: %v %v", err, again)
	}
}
