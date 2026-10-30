package nippf

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip88"
)

// Kinds of NIP-PF, and NIP-88's poll and vote, which it extends.
const (
	KindForm     = 1069
	KindResponse = 1019
	KindResult   = 1070
	KindPoll     = nip88.KindPoll
	KindVote     = nip88.KindPollResponse
)

// Question types.
const (
	TypeSingle = "singlechoice"
	TypeMulti  = "multiplechoice"
	TypeText   = "text"
	TypeNumber = "number"
	TypeDate   = "date"
	TypeTime   = "time"
)

// Roles of a form's p tags.
const (
	RoleResponder = "responder"
	RoleObserver  = "observer"
)

// Errors, for errors.Is.
var (
	ErrWrongKind       = errors.New("nippf: wrong kind")
	ErrInvalidForm     = errors.New("nippf: invalid form")
	ErrInvalidResponse = errors.New("nippf: invalid response")
	ErrInvalidResult   = errors.New("nippf: invalid result")
	// ErrReadOnly is a form with a question type this package doesn't know:
	// it is shown, never answered.
	ErrReadOnly = errors.New("nippf: read-only form (a question type not supported)")
	// ErrNotResponder is a pubkey the form doesn't let respond.
	ErrNotResponder = errors.New("nippf: not a responder of the form")
)

func invalidForm(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidForm, fmt.Sprintf(f, a...))
}

// KnownType reports whether typ is a question type of the spec.
func KnownType(typ string) bool {
	switch typ {
	case TypeSingle, TypeMulti, TypeText, TypeNumber, TypeDate, TypeTime:
		return true
	}
	return false
}

func choiceType(typ string) bool { return typ == TypeSingle || typ == TypeMulti }

// Option is one option of a choice question.
type Option struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Rec: a rec tag names it (the author recommends it).
	Rec bool `json:"rec,omitempty"`
	// NoteRequired: choosing it requires a note.
	NoteRequired bool `json:"note_required,omitempty"`
}

// Question is one question of a form, with its options in their tags' order.
type Question struct {
	Index    int      `json:"index"`
	Text     string   `json:"text"`
	Type     string   `json:"type"`
	Why      string   `json:"why,omitempty"`
	Options  []Option `json:"options,omitempty"`
	Optional bool     `json:"optional,omitempty"`
	Min      string   `json:"min,omitempty"`
	Max      string   `json:"max,omitempty"`
	// Defaults: the default tags' values, in their order (several only for
	// multiplechoice).
	Defaults []string `json:"defaults,omitempty"`
}

// Choice reports whether the question is answered with response tags.
func (q Question) Choice() bool { return choiceType(q.Type) }

// Option: the question's option with this id.
func (q Question) Option(id string) (Option, bool) {
	for _, o := range q.Options {
		if o.ID == id {
			return o, true
		}
	}
	return Option{}, false
}

// Party is one p tag of a form: a pubkey, its relay hint and its role
// (responder or observer; an unknown role reads as observer).
type Party struct {
	PubKey string `json:"pubkey"`
	Relay  string `json:"relay,omitempty"`
	Role   string `json:"role"`
}

// Form is a kind-1069 form, read and valid.
type Form struct {
	// ID, Author and CreatedAt are the event's (empty for a form being built).
	ID        string `json:"id,omitempty"`
	Author    string `json:"author,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	// Private: received as a rumor in a gift wrap (the event doesn't say).
	Private bool `json:"private,omitempty"`

	Title     string     `json:"title"`
	Questions []Question `json:"questions"` // in index order
	Context   string     `json:"context,omitempty"`
	Events    []string   `json:"events,omitempty"` // e tags: the form's subject
	Addrs     []string   `json:"addrs,omitempty"`  // a tags: the form's subject
	Parties   []Party    `json:"parties,omitempty"`
	Quorum    int        `json:"quorum,omitempty"`
	// Priority: ["priority", "high"].
	Priority bool `json:"priority,omitempty"`
	// EndsAt and Expiration in unix seconds; 0 when absent.
	EndsAt     int64    `json:"ends_at,omitempty"`
	Expiration int64    `json:"expiration,omitempty"`
	Relays     []string `json:"relays,omitempty"`
	// ResultsAll: ["results", "all"] (a private form's responses go to every p).
	ResultsAll bool   `json:"results_all,omitempty"`
	Alt        string `json:"alt,omitempty"`
	// Group: the NIP-29 h tag of a group form.
	Group string `json:"group,omitempty"`
	// ReadOnly: a question's type isn't one of the spec's; the rules that
	// depend on a question's type skip it, and the form is never answered.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Question: the question with this index.
func (f *Form) Question(i int) (Question, bool) {
	if i >= 0 && i < len(f.Questions) && f.Questions[i].Index == i {
		return f.Questions[i], true
	}
	return Question{}, false
}

// Option: the option with this id and its question.
func (f *Form) Option(id string) (Option, Question, bool) {
	for _, q := range f.Questions {
		if o, ok := q.Option(id); ok {
			return o, q, true
		}
	}
	return Option{}, Question{}, false
}

// Responders: the responder pubkeys, once each, in their tags' order (a
// pubkey listed with both roles is a responder).
func (f *Form) Responders() []string {
	var out []string
	for _, p := range f.Parties {
		if p.Role == RoleResponder && !slices.Contains(out, p.PubKey) {
			out = append(out, p.PubKey)
		}
	}
	return out
}

// Observers: the pubkeys listed only as observers, once each.
func (f *Form) Observers() []string {
	rs := f.Responders()
	var out []string
	for _, p := range f.Parties {
		if !slices.Contains(rs, p.PubKey) && !slices.Contains(out, p.PubKey) {
			out = append(out, p.PubKey)
		}
	}
	return out
}

// Recipients: every p pubkey, once each, in their tags' order.
func (f *Form) Recipients() []string {
	var out []string
	for _, p := range f.Parties {
		if !slices.Contains(out, p.PubKey) {
			out = append(out, p.PubKey)
		}
	}
	return out
}

// Allowed reports whether pubkey may respond: with responder pubkeys, only
// they; without, any pubkey but an observer for a public or group form, and
// only the author for a private one.
func (f *Form) Allowed(pubkey string) bool {
	if rs := f.Responders(); len(rs) > 0 {
		return slices.Contains(rs, pubkey)
	}
	if f.Private {
		return pubkey == f.Author
	}
	return !slices.Contains(f.Observers(), pubkey)
}

// HasDefault reports whether the form has a default tag.
func (f *Form) HasDefault() bool {
	for _, q := range f.Questions {
		if len(q.Defaults) > 0 {
			return true
		}
	}
	return false
}

// ParseForm reads a kind-1069 event as a form and applies every validity
// rule. private: the form came as a rumor in a gift wrap.
func ParseForm(ev *nip01.Event, private bool) (*Form, error) {
	if ev == nil || ev.Kind != KindForm {
		return nil, ErrWrongKind
	}
	f, err := ParseFormTags(ev.Content, ev.Tags, private)
	if err != nil {
		return nil, err
	}
	f.ID, f.Author, f.CreatedAt = ev.ID, ev.PubKey, int64(ev.CreatedAt)
	return f, nil
}

type indexValue struct {
	index string
	value string
}

// onceTags appear at most once in a form.
var onceTags = []string{"context", "quorum", "priority", "endsAt", "expiration", "results", "alt"}

// ParseFormTags reads a form's content and tags: one pass collects the tags,
// then each rule is checked against the whole.
func ParseFormTags(content string, tags [][]string, private bool) (*Form, error) {
	f := &Form{Title: content, Private: private}
	qs := map[int]*Question{}
	type opt struct {
		Option
		question int
	}
	var (
		opts                 []opt
		optionals            []string
		mins, maxs, defaults []indexValue
		recs, noteReqs       []string
		quorum               string
		once                 = map[string]int{}
	)
	for _, t := range tags {
		if len(t) == 0 {
			continue
		}
		if slices.Contains(onceTags, t[0]) {
			once[t[0]]++
			if len(t) < 2 {
				return nil, invalidForm("%s has no value", t[0])
			}
		}
		switch t[0] {
		case "question":
			if len(t) < 4 {
				return nil, invalidForm("a question tag has an index, a text and a type: %q", t)
			}
			i, ok := parseIndex(t[1])
			if !ok {
				return nil, invalidForm("a question's index is a decimal string without leading zeros: %q", t[1])
			}
			if qs[i] != nil {
				return nil, invalidForm("question %d twice", i)
			}
			q := &Question{Index: i, Text: t[2], Type: t[3]}
			if len(t) > 4 {
				q.Why = t[4]
			}
			if !KnownType(q.Type) {
				f.ReadOnly = true
			}
			qs[i] = q
		case "option":
			if len(t) < 4 {
				return nil, invalidForm("an option tag has an id, a label and a question index: %q", t)
			}
			if !optionIDRe.MatchString(t[1]) {
				return nil, invalidForm("option id %q (ASCII letters, digits, - and _)", t[1])
			}
			if slices.ContainsFunc(opts, func(o opt) bool { return o.ID == t[1] }) {
				return nil, invalidForm("option %q twice", t[1])
			}
			i, ok := parseIndex(t[3])
			if !ok {
				return nil, invalidForm("option %q names no question: %q", t[1], t[3])
			}
			opts = append(opts, opt{Option{ID: t[1], Label: t[2]}, i})
		case "optional":
			if len(t) < 2 {
				return nil, invalidForm("an optional tag names a question")
			}
			optionals = append(optionals, t[1])
		case "min", "max", "default":
			if len(t) < 3 {
				return nil, invalidForm("a %s tag has an index and a value: %q", t[0], t)
			}
			iv := indexValue{t[1], t[2]}
			switch t[0] {
			case "min":
				mins = append(mins, iv)
			case "max":
				maxs = append(maxs, iv)
			default:
				defaults = append(defaults, iv)
			}
		case "rec", "noteRequired":
			if len(t) < 2 {
				continue
			}
			if t[0] == "rec" {
				recs = append(recs, t[1])
			} else {
				noteReqs = append(noteReqs, t[1])
			}
		case "context":
			f.Context = t[1]
		case "alt":
			f.Alt = t[1]
		case "quorum":
			quorum = t[1]
		case "priority":
			f.Priority = t[1] == "high"
		case "results":
			f.ResultsAll = t[1] == "all"
		case "endsAt", "expiration":
			v, ok := parseUnix(t[1])
			if !ok {
				return nil, invalidForm("%s is unix seconds: %q", t[0], t[1])
			}
			if t[0] == "endsAt" {
				f.EndsAt = v
			} else {
				f.Expiration = v
			}
		case "e", "a", "relay":
			if len(t) < 2 || t[1] == "" {
				continue
			}
			switch t[0] {
			case "e":
				f.Events = append(f.Events, t[1])
			case "a":
				f.Addrs = append(f.Addrs, t[1])
			default:
				f.Relays = append(f.Relays, t[1])
			}
		case "p":
			if len(t) < 2 || !hex64Re.MatchString(t[1]) {
				return nil, invalidForm("a p tag names a pubkey (64 lower-case hex): %q", t)
			}
			p := Party{PubKey: t[1], Role: RoleResponder}
			if len(t) > 2 {
				p.Relay = t[2]
			}
			if len(t) > 3 && t[3] != "" && t[3] != RoleResponder {
				p.Role = RoleObserver
			}
			f.Parties = append(f.Parties, p)
		case "h":
			if len(t) >= 2 && f.Group == "" {
				f.Group = t[1]
			}
		}
	}
	for _, name := range onceTags {
		if once[name] > 1 {
			return nil, invalidForm("%s appears %d times (at most once)", name, once[name])
		}
	}

	// Questions: at least one, indexes 0..n-1.
	if len(qs) == 0 {
		return nil, invalidForm("no question")
	}
	for i := 0; i < len(qs); i++ {
		if qs[i] == nil {
			return nil, invalidForm("question indexes have a gap at %d", i)
		}
	}
	// Options: each names an existing choice question; each choice question has one.
	for _, o := range opts {
		q := qs[o.question]
		if q == nil {
			return nil, invalidForm("option %q names no question (%d)", o.ID, o.question)
		}
		if KnownType(q.Type) && !choiceType(q.Type) {
			return nil, invalidForm("option %q names question %d, a %s question", o.ID, q.Index, q.Type)
		}
		q.Options = append(q.Options, o.Option)
	}
	for i := 0; i < len(qs); i++ {
		if q := qs[i]; choiceType(q.Type) && len(q.Options) == 0 {
			return nil, invalidForm("choice question %d has no option", i)
		}
	}
	question := func(tag, s string) (*Question, error) {
		i, ok := parseIndex(s)
		if !ok || qs[i] == nil {
			return nil, invalidForm("%s names no question: %q", tag, s)
		}
		return qs[i], nil
	}
	for _, s := range optionals {
		q, err := question("optional", s)
		if err != nil {
			return nil, err
		}
		q.Optional = true
	}
	for _, b := range []struct {
		tag string
		ivs []indexValue
	}{{"min", mins}, {"max", maxs}} {
		for _, iv := range b.ivs {
			q, err := question(b.tag, iv.index)
			if err != nil {
				return nil, err
			}
			if !KnownType(q.Type) {
				if b.tag == "min" {
					q.Min = iv.value
				} else {
					q.Max = iv.value
				}
				continue
			}
			if !bounded(q.Type) || !ValidValue(q.Type, iv.value) {
				return nil, invalidForm("%s %q doesn't match question %d (%s)", b.tag, iv.value, q.Index, q.Type)
			}
			bound := &q.Min
			if b.tag == "max" {
				bound = &q.Max
			}
			if *bound != "" {
				return nil, invalidForm("question %d has two %s tags", q.Index, b.tag)
			}
			*bound = iv.value
		}
	}
	for i := 0; i < len(qs); i++ {
		q := qs[i]
		if KnownType(q.Type) && q.Min != "" && q.Max != "" && compareValues(q.Type, q.Min, q.Max) > 0 {
			return nil, invalidForm("question %d's min %s is above its max %s", i, q.Min, q.Max)
		}
	}
	for _, iv := range defaults {
		q, err := question("default", iv.index)
		if err != nil {
			return nil, err
		}
		if KnownType(q.Type) {
			if choiceType(q.Type) {
				if _, ok := q.Option(iv.value); !ok {
					return nil, invalidForm("default %q is no option of question %d", iv.value, q.Index)
				}
			} else if !ValidValue(q.Type, iv.value) {
				return nil, invalidForm("default %q doesn't match question %d (%s)", iv.value, q.Index, q.Type)
			}
			if q.Type != TypeMulti && len(q.Defaults) > 0 {
				return nil, invalidForm("question %d (%s) has more than one default", q.Index, q.Type)
			}
		}
		q.Defaults = append(q.Defaults, iv.value)
	}
	for i := 0; i < len(qs); i++ {
		f.Questions = append(f.Questions, *qs[i])
	}
	// rec and noteRequired naming no option are ignored.
	for qi := range f.Questions {
		for oi := range f.Questions[qi].Options {
			o := &f.Questions[qi].Options[oi]
			o.Rec = slices.Contains(recs, o.ID)
			o.NoteRequired = slices.Contains(noteReqs, o.ID)
		}
	}
	if once["quorum"] > 0 {
		if !positiveRe.MatchString(quorum) || len(quorum) > 9 {
			return nil, invalidForm("quorum is a positive integer: %q", quorum)
		}
		f.Quorum, _ = strconv.Atoi(quorum)
		if n := len(f.Responders()); n > 0 && f.Quorum > n {
			return nil, invalidForm("quorum %d is above the %d responders", f.Quorum, n)
		}
	}
	if f.EndsAt > 0 && f.Expiration > 0 && f.Expiration < f.EndsAt {
		return nil, invalidForm("expiration %d is earlier than endsAt %d", f.Expiration, f.EndsAt)
	}
	if private && len(f.Parties) == 0 {
		return nil, invalidForm("a private form has no p tag")
	}
	return f, nil
}

// Tags: the form's tags, in a fixed order (Check them with ParseFormTags,
// which Event does).
func (f *Form) Tags() [][]string {
	var tags [][]string
	add := func(t ...string) { tags = append(tags, t) }
	if f.Alt != "" {
		add("alt", f.Alt)
	}
	if f.Context != "" {
		add("context", f.Context)
	}
	for _, e := range f.Events {
		add("e", e)
	}
	for _, a := range f.Addrs {
		add("a", a)
	}
	if f.Group != "" {
		add("h", f.Group)
	}
	for _, p := range f.Parties {
		switch {
		case p.Role == RoleObserver:
			add("p", p.PubKey, p.Relay, RoleObserver)
		case p.Relay != "":
			add("p", p.PubKey, p.Relay)
		default:
			add("p", p.PubKey)
		}
	}
	if f.Quorum > 0 {
		add("quorum", strconv.Itoa(f.Quorum))
	}
	if f.Priority {
		add("priority", "high")
	}
	if f.EndsAt > 0 {
		add("endsAt", strconv.FormatInt(f.EndsAt, 10))
	}
	if f.Expiration > 0 {
		add("expiration", strconv.FormatInt(f.Expiration, 10))
	}
	for _, r := range f.Relays {
		add("relay", r)
	}
	if f.ResultsAll {
		add("results", "all")
	}
	qs := slices.Clone(f.Questions)
	sort.SliceStable(qs, func(i, j int) bool { return qs[i].Index < qs[j].Index })
	var recs, notes []string
	for _, q := range qs {
		i := strconv.Itoa(q.Index)
		if q.Why != "" {
			add("question", i, q.Text, q.Type, q.Why)
		} else {
			add("question", i, q.Text, q.Type)
		}
		for _, o := range q.Options {
			add("option", o.ID, o.Label, i)
			if o.Rec {
				recs = append(recs, o.ID)
			}
			if o.NoteRequired {
				notes = append(notes, o.ID)
			}
		}
		if q.Optional {
			add("optional", i)
		}
		if q.Min != "" {
			add("min", i, q.Min)
		}
		if q.Max != "" {
			add("max", i, q.Max)
		}
		for _, d := range q.Defaults {
			add("default", i, d)
		}
	}
	for _, id := range recs {
		add("rec", id)
	}
	for _, id := range notes {
		add("noteRequired", id)
	}
	return tags
}

// Event: the form as an unsigned kind-1069 event by author at createdAt,
// read back before it is returned. A public or group form without Alt gets
// "Form: <title>" (NIP-31's alt is required there).
func (f *Form) Event(author string, createdAt int64) (*nip01.Event, error) {
	g := *f
	if !g.Private && g.Alt == "" {
		g.Alt = "Form: " + g.Title
	}
	tags := g.Tags()
	back, err := ParseFormTags(g.Title, tags, g.Private)
	if err != nil {
		return nil, err
	}
	if !slices.EqualFunc(back.Tags(), tags, slices.Equal) {
		return nil, invalidForm("the form doesn't read back as written")
	}
	ev := nip01.NewUnsignedEvent(KindForm, author, g.Title, tags...)
	ev.CreatedAt = uint64(createdAt)
	return ev, nil
}

// Text: the form for a reader — the title, context, each question with its
// options (recommended ones marked, with why; notes required; defaults),
// bounds and whether it is optional. Plain text, for display only.
func (f *Form) Text() string {
	var b strings.Builder
	b.WriteString(f.Title + "\n")
	if f.Context != "" {
		b.WriteString(f.Context + "\n")
	}
	for _, q := range f.Questions {
		fmt.Fprintf(&b, "\nQ%d. %s (%s", q.Index+1, q.Text, q.Type)
		if q.Optional {
			b.WriteString(", optional")
		}
		if q.Min != "" {
			fmt.Fprintf(&b, ", min %s", q.Min)
		}
		if q.Max != "" {
			fmt.Fprintf(&b, ", max %s", q.Max)
		}
		b.WriteString(")\n")
		for _, o := range q.Options {
			fmt.Fprintf(&b, "  [%s] %s", o.ID, o.Label)
			if o.Rec {
				b.WriteString(" — recommended")
			}
			if o.NoteRequired {
				b.WriteString(" (a note is required)")
			}
			b.WriteString("\n")
		}
		if q.Why != "" {
			fmt.Fprintf(&b, "  why: %s\n", q.Why)
		}
		if len(q.Defaults) > 0 {
			fmt.Fprintf(&b, "  default: %s\n", strings.Join(q.Defaults, ", "))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
