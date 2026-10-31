package nippf

import (
	"fmt"
	"slices"

	"github.com/ohstr/nmilat/nip01"
)

// Statuses of a result.
const (
	StatusDecided   = "decided"
	StatusDefault   = "default"
	StatusCancelled = "cancelled"
)

func invalidResult(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, fmt.Sprintf(f, a...))
}

// Result is a kind-1070 result, read: the outcome its author records for a
// form or a poll.
type Result struct {
	ID        string `json:"id"`
	Author    string `json:"author"`
	CreatedAt int64  `json:"created_at"`
	// Form: its one e tag, the form's or the poll's id.
	Form   string `json:"form"`
	Status string `json:"status"`
	// Choices and Answers: the outcome (their notes optional).
	Choices    []Choice `json:"choices,omitempty"`
	Answers    []Answer `json:"answers,omitempty"`
	Responders []string `json:"responders,omitempty"` // its p tags
	Content    string   `json:"content,omitempty"`    // what the author did
	Expiration int64    `json:"expiration,omitempty"`
	Group      string   `json:"group,omitempty"`
}

// ParseResult reads a kind-1070 event: exactly one e tag and one status from
// the table. Whether its outcome matches its status needs the form
// (Form.CheckResult) or the poll (CheckPollResult).
func ParseResult(ev *nip01.Event) (*Result, error) {
	if ev == nil || ev.Kind != KindResult {
		return nil, ErrWrongKind
	}
	o, err := readOutcome(ev.Tags)
	if err != nil {
		return nil, invalidResult("%v", err)
	}
	if len(o.e) != 1 || !hex64Re.MatchString(o.e[0]) {
		return nil, invalidResult("a result has exactly one e tag naming the form (%d)", len(o.e))
	}
	if len(o.status) != 1 {
		return nil, invalidResult("a result has one status tag (%d)", len(o.status))
	}
	switch o.status[0] {
	case StatusDecided, StatusDefault, StatusCancelled:
	default:
		return nil, invalidResult("status %q (decided, default or cancelled)", o.status[0])
	}
	return &Result{ID: ev.ID, Author: ev.PubKey, CreatedAt: int64(ev.CreatedAt), Form: o.e[0], Status: o.status[0],
		Choices: o.choices, Answers: o.answers, Responders: o.p, Content: ev.Content,
		Expiration: o.expiration, Group: o.group}, nil
}

// DefaultOutcome: the form's defaults as an outcome — every choice question's
// default options, every other question's default answer; questions without a
// default are left unanswered.
func (f *Form) DefaultOutcome() ([]Choice, []Answer) {
	var cs []Choice
	var as []Answer
	for _, q := range f.Questions {
		for _, d := range q.Defaults {
			if q.Choice() {
				if !slices.ContainsFunc(cs, func(c Choice) bool { return c.Option == d }) {
					cs = append(cs, Choice{Option: d})
				}
			} else {
				as = append(as, Answer{Question: q.Index, Value: d})
			}
		}
	}
	return cs, as
}

// CheckResult reports whether r is a valid result of the form: it names the
// form, and its outcome matches its status — decided: valid by the response
// rules (notes optional; quorum is the author's claim, not checked); default:
// exactly the form's defaults, for a form with a default tag; cancelled: none.
// Who wrote it is Closing's concern.
func (f *Form) CheckResult(r *Result) error {
	if f.ID != "" && r.Form != f.ID {
		return invalidResult("it closes %s, not this form %s", r.Form, f.ID)
	}
	switch r.Status {
	case StatusDecided:
		if err := f.checkOutcome(r.Choices, r.Answers, false); err != nil {
			return invalidResult("a decided outcome: %v", err)
		}
	case StatusDefault:
		if !f.HasDefault() {
			return invalidResult("a default result for a form with no default tag")
		}
		cs, as := f.DefaultOutcome()
		if !sameChoices(r.Choices, cs) || !sameAnswers(r.Answers, as) {
			return invalidResult("a default outcome is exactly the form's defaults")
		}
	case StatusCancelled:
		if len(r.Choices) > 0 || len(r.Answers) > 0 {
			return invalidResult("a cancelled result has no outcome")
		}
	default:
		return invalidResult("status %q", r.Status)
	}
	return nil
}

// sameChoices: the same options, each once, in any order (notes aside).
func sameChoices(got, want []Choice) bool {
	if len(got) != len(want) {
		return false
	}
	var seen []string
	for _, c := range got {
		if slices.Contains(seen, c.Option) || !slices.ContainsFunc(want, func(w Choice) bool { return w.Option == c.Option }) {
			return false
		}
		seen = append(seen, c.Option)
	}
	return true
}

// sameAnswers: the same question/value pairs, in any order (notes aside).
func sameAnswers(got, want []Answer) bool {
	if len(got) != len(want) {
		return false
	}
	left := slices.Clone(want)
	for _, a := range got {
		i := slices.IndexFunc(left, func(w Answer) bool { return w.Question == a.Question && w.Value == a.Value })
		if i < 0 {
			return false
		}
		left = slices.Delete(left, i, i+1)
	}
	return true
}

// NewResult builds the author's unsigned result for the form: e, a p tag per
// responder, its expiration and group, the status and the outcome. For
// StatusDefault with no outcome given, the outcome is DefaultOutcome. It is
// read back and checked before it is returned.
func (f *Form) NewResult(createdAt int64, status, content string, choices []Choice, answers []Answer) (*nip01.Event, error) {
	if !hex64Re.MatchString(f.ID) {
		return nil, invalidResult("the form has no id")
	}
	if status == StatusDefault && len(choices) == 0 && len(answers) == 0 {
		choices, answers = f.DefaultOutcome()
	}
	tags := f.replyTags(f.Responders())
	tags = append(tags, []string{"status", status})
	tags = append(tags, outcomeTags(choices, answers, true)...)
	ev := nip01.NewUnsignedEvent(KindResult, f.Author, content, tags...)
	ev.CreatedAt = uint64(createdAt)
	r, err := ParseResult(ev)
	if err != nil {
		return nil, err
	}
	if err := f.CheckResult(r); err != nil {
		return nil, err
	}
	return ev, nil
}

// earliest: the result kept as the closing one among the valid candidates by
// the author: the earliest created_at, ties to the lowest id.
func earliest(rs []*Result, author string, valid func(*Result) bool) *Result {
	var best *Result
	for _, r := range rs {
		if r == nil || r.Author != author || !valid(r) {
			continue
		}
		if best == nil || r.CreatedAt < best.CreatedAt || (r.CreatedAt == best.CreatedAt && r.ID < best.ID) {
			best = r
		}
	}
	return best
}

// Closing: the form's closing result — the earliest valid result by the
// form's author, ties to the lowest id; nil when there is none.
func (f *Form) Closing(results []*Result) *Result {
	return earliest(results, f.Author, func(r *Result) bool { return f.CheckResult(r) == nil })
}
