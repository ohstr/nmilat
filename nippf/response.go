package nippf

import (
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/ohstr/nmilat/nip01"
)

// MaxText: the builders keep each note and answer under this many characters
// (a client SHOULD, says the spec); parsers accept longer ones.
const MaxText = 1000

func invalidResponse(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResponse, fmt.Sprintf(f, a...))
}

// Choice is a response tag: an option chosen, with its note ("" for none).
type Choice struct {
	Option string `json:"option"`
	Note   string `json:"note,omitempty"`
}

// Answer is an answer tag: a question's value, with its note.
type Answer struct {
	Question int    `json:"question"`
	Value    string `json:"value"`
	Note     string `json:"note,omitempty"`
}

// Response is a kind-1019 response, or a withdrawal, read.
type Response struct {
	ID        string `json:"id"`
	Author    string `json:"author"`
	CreatedAt int64  `json:"created_at"`
	// Form: its one e tag; FormAuthor: its p tag (the form's author).
	Form       string   `json:"form"`
	FormAuthor string   `json:"form_author,omitempty"`
	Choices    []Choice `json:"choices,omitempty"`
	Answers    []Answer `json:"answers,omitempty"`
	Expiration int64    `json:"expiration,omitempty"`
	Group      string   `json:"group,omitempty"`
}

// Withdrawal reports whether the response has no response or answer tag:
// its author withdraws an earlier response.
func (r *Response) Withdrawal() bool { return len(r.Choices) == 0 && len(r.Answers) == 0 }

// outcome is what a response's or a result's response and answer tags hold,
// and how many e tags it has.
type outcome struct {
	e          []string
	p          []string
	choices    []Choice
	answers    []Answer
	expiration int64
	group      string
	status     []string
}

// readOutcome reads the tags a response and a result share. A response or
// answer tag that can't be read is an error.
func readOutcome(tags [][]string) (outcome, error) {
	var o outcome
	for _, t := range tags {
		if len(t) == 0 {
			continue
		}
		switch t[0] {
		case "e":
			if len(t) < 2 {
				return o, fmt.Errorf("an e tag with no id")
			}
			o.e = append(o.e, t[1])
		case "p":
			if len(t) >= 2 {
				o.p = append(o.p, t[1])
			}
		case "response":
			if len(t) < 2 {
				return o, fmt.Errorf("a response tag names no option: %q", t)
			}
			o.choices = append(o.choices, Choice{Option: t[1], Note: noteOf(t, 2)})
		case "answer":
			if len(t) < 3 {
				return o, fmt.Errorf("an answer tag has an index and a value: %q", t)
			}
			i, ok := parseIndex(t[1])
			if !ok {
				return o, fmt.Errorf("an answer names no question: %q", t[1])
			}
			o.answers = append(o.answers, Answer{Question: i, Value: t[2], Note: noteOf(t, 3)})
		case "expiration":
			if len(t) >= 2 && o.expiration == 0 {
				o.expiration, _ = parseUnix(t[1])
			}
		case "h":
			if len(t) >= 2 && o.group == "" {
				o.group = t[1]
			}
		case "status":
			if len(t) >= 2 {
				o.status = append(o.status, t[1])
			}
		}
	}
	return o, nil
}

// ParseResponse reads a kind-1019 event: exactly one e tag naming the form;
// a response with no response or answer tag is a withdrawal. The rules that
// need the form are Form.Check's.
func ParseResponse(ev *nip01.Event) (*Response, error) {
	if ev == nil || ev.Kind != KindResponse {
		return nil, ErrWrongKind
	}
	o, err := readOutcome(ev.Tags)
	if err != nil {
		return nil, invalidResponse("%v", err)
	}
	if len(o.e) != 1 || !hex64Re.MatchString(o.e[0]) {
		return nil, invalidResponse("a response has exactly one e tag naming the form (%d)", len(o.e))
	}
	r := &Response{ID: ev.ID, Author: ev.PubKey, CreatedAt: int64(ev.CreatedAt), Form: o.e[0],
		Choices: o.choices, Answers: o.answers, Expiration: o.expiration, Group: o.group}
	if len(o.p) > 0 {
		r.FormAuthor = o.p[0]
	}
	return r, nil
}

// Check applies the response rules of the form to r: it names this form,
// and, unless it is a withdrawal, every option exists and appears once, each
// question has as many responses or answers as it takes, every value is valid
// and within the question's bounds, and every response to a noteRequired
// option has a note. Questions of an unknown type are skipped.
func (f *Form) Check(r *Response) error {
	if f.ID != "" && r.Form != f.ID {
		return invalidResponse("it answers %s, not this form %s", r.Form, f.ID)
	}
	if r.Withdrawal() {
		return nil
	}
	if err := f.checkOutcome(r.Choices, r.Answers, true); err != nil {
		return invalidResponse("%v", err)
	}
	return nil
}

// checkOutcome is the response rules on choices and answers; notes: the
// noteRequired rule applies (a result's notes are optional).
func (f *Form) checkOutcome(choices []Choice, answers []Answer, notes bool) error {
	byQ := map[int]int{}
	var seen []string
	for _, c := range choices {
		o, q, ok := f.Option(c.Option)
		switch {
		case !ok:
			return fmt.Errorf("no option %q in the form", c.Option)
		case slices.Contains(seen, c.Option):
			return fmt.Errorf("option %q twice", c.Option)
		case notes && o.NoteRequired && c.Note == "":
			return fmt.Errorf("option %q requires a note", c.Option)
		}
		seen = append(seen, c.Option)
		byQ[q.Index]++
	}
	ansQ := map[int][]Answer{}
	for _, a := range answers {
		q, ok := f.Question(a.Question)
		if !ok {
			return fmt.Errorf("an answer names no question (%d)", a.Question)
		}
		if KnownType(q.Type) && q.Choice() {
			return fmt.Errorf("an answer names question %d, a %s question", q.Index, q.Type)
		}
		ansQ[q.Index] = append(ansQ[q.Index], a)
	}
	for _, q := range f.Questions {
		n := byQ[q.Index]
		switch q.Type {
		case TypeSingle:
			if n > 1 || (n == 0 && !q.Optional) {
				return fmt.Errorf("question %d takes exactly one response%s, not %d", q.Index, optionalNote(q), n)
			}
		case TypeMulti:
			if n == 0 && !q.Optional {
				return fmt.Errorf("question %d takes at least one response", q.Index)
			}
		case TypeText, TypeNumber, TypeDate, TypeTime:
			as := ansQ[q.Index]
			if len(as) > 1 || (len(as) == 0 && !q.Optional) {
				return fmt.Errorf("question %d takes exactly one answer%s, not %d", q.Index, optionalNote(q), len(as))
			}
			if len(as) == 0 {
				continue
			}
			v := as[0].Value
			if !ValidValue(q.Type, v) {
				return fmt.Errorf("question %d's answer %q isn't a valid %s", q.Index, v, q.Type)
			}
			if q.Min != "" && compareValues(q.Type, v, q.Min) < 0 {
				return fmt.Errorf("question %d's answer %s is below its min %s", q.Index, v, q.Min)
			}
			if q.Max != "" && compareValues(q.Type, v, q.Max) > 0 {
				return fmt.Errorf("question %d's answer %s is above its max %s", q.Index, v, q.Max)
			}
		}
	}
	return nil
}

func optionalNote(q Question) string {
	if q.Optional {
		return " at most (optional)"
	}
	return ""
}

// outcomeTags writes choices and answers as response and answer tags, a note
// only when there is one.
func outcomeTags(choices []Choice, answers []Answer, notes bool) [][]string {
	var tags [][]string
	for _, c := range choices {
		if notes && noteOf([]string{c.Note}, 0) != "" {
			tags = append(tags, []string{"response", c.Option, c.Note})
		} else {
			tags = append(tags, []string{"response", c.Option})
		}
	}
	for _, a := range answers {
		i := strconv.Itoa(a.Question)
		if notes && noteOf([]string{a.Note}, 0) != "" {
			tags = append(tags, []string{"answer", i, a.Value, a.Note})
		} else {
			tags = append(tags, []string{"answer", i, a.Value})
		}
	}
	return tags
}

// replyTags: the e, p, expiration and h tags of a response or result.
func (f *Form) replyTags(ps []string) [][]string {
	tags := [][]string{{"e", f.ID}}
	for _, p := range ps {
		tags = append(tags, []string{"p", p})
	}
	if f.Expiration > 0 {
		tags = append(tags, []string{"expiration", strconv.FormatInt(f.Expiration, 10)})
	}
	if f.Group != "" {
		tags = append(tags, []string{"h", f.Group})
	}
	return tags
}

// NewResponse builds author's unsigned response to the form: e (the form), p
// (its author), its expiration and group, then the choices and answers. It
// refuses a read-only form, an author the form doesn't let respond, and a
// response the form's rules refuse; the event is read back before it is
// returned. A response is never empty: that is NewWithdrawal. Each note and
// answer is kept under MaxText characters (the spec's SHOULD).
func (f *Form) NewResponse(author string, createdAt int64, choices []Choice, answers []Answer) (*nip01.Event, error) {
	if f.ReadOnly {
		return nil, ErrReadOnly
	}
	if !f.Allowed(author) {
		return nil, ErrNotResponder
	}
	if len(choices) == 0 && len(answers) == 0 {
		return nil, invalidResponse("no response or answer (a withdrawal is NewWithdrawal)")
	}
	for _, c := range choices {
		if utf8.RuneCountInString(c.Note) >= MaxText {
			return nil, invalidResponse("option %q's note has %d characters or more", c.Option, MaxText)
		}
	}
	for _, a := range answers {
		if utf8.RuneCountInString(a.Value) >= MaxText || utf8.RuneCountInString(a.Note) >= MaxText {
			return nil, invalidResponse("question %d's answer or note has %d characters or more", a.Question, MaxText)
		}
	}
	if !hex64Re.MatchString(f.ID) {
		return nil, invalidResponse("the form has no id")
	}
	tags := append(f.replyTags([]string{f.Author}), outcomeTags(choices, answers, true)...)
	return f.readBackResponse(nip01.NewUnsignedEvent(KindResponse, author, "", tags...), createdAt)
}

// NewWithdrawal builds author's unsigned withdrawal of its response: the e
// and p tags, no response or answer.
func (f *Form) NewWithdrawal(author string, createdAt int64) (*nip01.Event, error) {
	if !f.Allowed(author) {
		return nil, ErrNotResponder
	}
	if !hex64Re.MatchString(f.ID) {
		return nil, invalidResponse("the form has no id")
	}
	return f.readBackResponse(nip01.NewUnsignedEvent(KindResponse, author, "", f.replyTags([]string{f.Author})...), createdAt)
}

func (f *Form) readBackResponse(ev *nip01.Event, createdAt int64) (*nip01.Event, error) {
	ev.CreatedAt = uint64(createdAt)
	r, err := ParseResponse(ev)
	if err != nil {
		return nil, err
	}
	if err := f.Check(r); err != nil {
		return nil, err
	}
	return ev, nil
}
