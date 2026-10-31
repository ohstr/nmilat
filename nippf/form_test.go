package nippf

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// baseTags: a valid form with every question type and every tag.
func baseTags(t testing.TB) [][]string {
	t.Helper()
	return [][]string{
		{"alt", "Form: base"},
		{"context", "why we ask"},
		{"e", alertID},
		{"a", "30023:" + pub(t, authorPriv) + ":doc"},
		{"p", pub(t, op1Priv)},
		{"p", pub(t, op2Priv), "wss://relay.example.com"},
		{"p", pub(t, observerPriv), "", "observer"},
		{"quorum", "2"},
		{"priority", "high"},
		{"endsAt", "2000"},
		{"expiration", "3000"},
		{"relay", "wss://relay.example.com"},
		{"results", "all"},
		{"question", "0", "One?", TypeSingle, "because"},
		{"option", "yes", "Yes", "0"},
		{"option", "no", "No", "0"},
		{"option", "other", "Other", "0"},
		{"rec", "yes"},
		{"noteRequired", "other"},
		{"default", "0", "no"},
		{"question", "1", "Days?", TypeMulti},
		{"option", "sat", "Saturday", "1"},
		{"option", "sun", "Sunday", "1"},
		{"default", "1", "sat"},
		{"default", "1", "sun"},
		{"question", "2", "Words?", TypeText},
		{"optional", "2"},
		{"question", "3", "How many?", TypeNumber},
		{"min", "3", "-1.5"},
		{"max", "3", "10"},
		{"default", "3", "2"},
		{"question", "4", "When?", TypeDate},
		{"min", "4", "2026-01-01"},
		{"max", "4", "2026-12-31"},
		{"optional", "4"},
		{"question", "5", "Deadline?", TypeTime},
		{"min", "5", "1000"},
		{"optional", "5"},
	}
}

func baseForm(t testing.TB, private bool) *Form {
	t.Helper()
	f, err := ParseFormTags("base", baseTags(t), private)
	if err != nil {
		t.Fatal(err)
	}
	f.ID, f.Author = strings.Repeat("f", 64), pub(t, authorPriv)
	return f
}

// without: the tags but the ones for which drop is true.
func without(tags [][]string, drop func([]string) bool) [][]string {
	return slices.DeleteFunc(slices.Clone(tags), drop)
}

func with(tags [][]string, more ...[]string) [][]string { return append(slices.Clone(tags), more...) }

func named(name string, args ...string) func([]string) bool {
	return func(t []string) bool {
		if len(t) == 0 || t[0] != name {
			return false
		}
		for i, a := range args {
			if len(t) <= i+1 || t[i+1] != a {
				return false
			}
		}
		return true
	}
}

func TestFormBaseIsValid(t *testing.T) {
	for _, private := range []bool{false, true} {
		f := baseForm(t, private)
		if len(f.Questions) != 6 || f.ReadOnly || !f.ResultsAll || f.Quorum != 2 || f.Context != "why we ask" || len(f.Addrs) != 1 {
			t.Fatalf("form: %+v", f)
		}
		if !slices.Equal(f.Questions[1].Defaults, []string{"sat", "sun"}) {
			t.Fatalf("multi defaults: %v", f.Questions[1].Defaults)
		}
		// written and read back
		ev, err := f.Event(f.Author, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !sameTags(ev.Tags, baseTags(t)) {
			t.Fatalf("written back:\n%v", ev.Tags)
		}
	}
}

// Every validity rule of a form, one failing case each (and the malformed tags).
func TestFormValidityRules(t *testing.T) {
	b := baseTags(t)
	q := func(i, typ string) []string { return []string{"question", i, "Q?", typ} }
	cases := []struct {
		name    string
		tags    [][]string
		private bool
	}{
		// at least one question, unique indexes without gaps
		{"no question", without(b, func(t []string) bool {
			return slices.Contains([]string{"question", "option", "optional", "min", "max", "default"}, t[0])
		}), false},
		{"index twice", with(b, q("2", TypeText)), false},
		{"index gap", with(b, q("7", TypeText)), false},
		{"index with a leading zero", with(b, q("06", TypeText)), false},
		{"index not decimal", with(b, q("x", TypeText)), false},
		{"negative index", with(b, q("-1", TypeText)), false},
		// options
		{"option names no question", with(b, []string{"option", "x", "X", "9"}), false},
		{"option names a text question", with(b, []string{"option", "x", "X", "2"}), false},
		{"option names a number question", with(b, []string{"option", "x", "X", "3"}), false},
		{"option with a bad index", with(b, []string{"option", "x", "X", "00"}), false},
		{"choice question without option", without(b, func(t []string) bool { return t[0] == "option" && t[3] == "1" || named("default", "1")(t) }), false},
		{"option id twice", with(b, []string{"option", "yes", "Again", "1"}), false},
		{"option id with a space", with(b, []string{"option", "a b", "X", "1"}), false},
		{"option id not ASCII", with(b, []string{"option", "café", "X", "1"}), false},
		{"empty option id", with(b, []string{"option", "", "X", "1"}), false},
		// indexes named by optional, min, max, default exist
		{"optional names no question", with(b, []string{"optional", "9"}), false},
		{"min names no question", with(b, []string{"min", "9", "1"}), false},
		{"max names no question", with(b, []string{"max", "x", "1"}), false},
		{"default names no question", with(b, []string{"default", "9", "yes"}), false},
		// min, max, default match the type, min <= max
		{"min on a choice question", with(b, []string{"min", "0", "1"}), false},
		{"max on a text question", with(b, []string{"max", "2", "1"}), false},
		{"number min not a number", with(without(b, named("min", "3")), []string{"min", "3", "1e3"}), false},
		{"date max not a date", with(without(b, named("max", "4")), []string{"max", "4", "2026-02-30"}), false},
		{"time min not unix seconds", with(without(b, named("min", "5")), []string{"min", "5", "-1"}), false},
		{"min above max (number, numerically)", with(without(b, named("min", "3")), []string{"min", "3", "10.5"}), false},
		{"min above max (date)", with(without(b, named("min", "4")), []string{"min", "4", "2027-01-01"}), false},
		{"min twice", with(b, []string{"min", "5", "1001"}), false},
		{"choice default not an option", with(without(b, named("default", "0")), []string{"default", "0", "sat"}), false},
		{"number default not a number", with(without(b, named("default", "3")), []string{"default", "3", "two"}), false},
		{"text default empty", with(b, []string{"default", "2", ""}), false},
		// at most one default but for multiplechoice
		{"two defaults on singlechoice", with(b, []string{"default", "0", "yes"}), false},
		{"two defaults on number", with(b, []string{"default", "3", "3"}), false},
		// quorum
		{"quorum zero", with(without(b, named("quorum")), []string{"quorum", "0"}), false},
		{"quorum negative", with(without(b, named("quorum")), []string{"quorum", "-1"}), false},
		{"quorum not an integer", with(without(b, named("quorum")), []string{"quorum", "1.5"}), false},
		{"quorum above the responders", with(without(b, named("quorum")), []string{"quorum", "3"}), false},
		// expiration not earlier than endsAt
		{"expiration before endsAt", with(without(b, named("expiration")), []string{"expiration", "1999"}), false},
		{"endsAt not unix seconds", with(without(b, named("endsAt")), []string{"endsAt", "soon"}), false},
		// a private form has a p tag
		{"private without p", without(b, func(t []string) bool { return t[0] == "p" || t[0] == "quorum" }), true},
		// once-only tags
		{"context twice", with(b, []string{"context", "again"}), false},
		{"quorum twice", with(b, []string{"quorum", "2"}), false},
		{"priority twice", with(b, []string{"priority", "low"}), false},
		{"endsAt twice", with(b, []string{"endsAt", "2000"}), false},
		{"expiration twice", with(b, []string{"expiration", "3000"}), false},
		{"results twice", with(b, []string{"results", "none"}), false},
		{"alt twice", with(b, []string{"alt", "again"}), false},
		// malformed tags
		{"question tag too short", with(b, []string{"question", "6", "Q?"}), false},
		{"option tag too short", with(b, []string{"option", "x", "X"}), false},
		{"min tag too short", with(b, []string{"min", "5"}), false},
		{"default tag too short", with(b, []string{"default", "0"}), false},
		{"optional tag empty", with(b, []string{"optional"}), false},
		{"alt tag without value", with(without(b, named("alt")), []string{"alt"}), false},
		{"p tag not a pubkey", with(b, []string{"p", "<operator 4>"}), false},
		{"p tag upper-case hex", with(b, []string{"p", strings.ToUpper(pub(t, op3Priv))}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseFormTags("t", c.tags, c.private)
			t.Log(err)
			if !errors.Is(err, ErrInvalidForm) {
				t.Fatalf("got %v, want ErrInvalidForm", err)
			}
		})
	}
}

// What the spec allows: a missing alt, order-free tags, ignored values.
func TestFormAllowed(t *testing.T) {
	b := baseTags(t)
	rev := slices.Clone(b)
	slices.Reverse(rev)
	cases := []struct {
		name  string
		tags  [][]string
		check func(*Form) bool
	}{
		{"no alt", without(b, named("alt")), func(f *Form) bool { return f.Alt == "" }},
		{"tags in reverse order", rev, func(f *Form) bool { return len(f.Questions) == 6 && f.Questions[0].Options[0].ID == "other" }},
		{"rec naming no option is ignored", with(b, []string{"rec", "nope"}), func(f *Form) bool { return f.Questions[0].Options[0].Rec }},
		{"noteRequired naming no option is ignored", with(b, []string{"noteRequired", "nope"}), func(f *Form) bool { return f.Questions[0].Options[2].NoteRequired }},
		{"priority other than high is ignored", with(without(b, named("priority")), []string{"priority", "urgent"}), func(f *Form) bool { return !f.Priority }},
		{"results other than all is ignored", with(without(b, named("results")), []string{"results", "some"}), func(f *Form) bool { return !f.ResultsAll }},
		{"unknown role is observer", with(b, []string{"p", pub(t, op3Priv), "", "auditor"}), func(f *Form) bool {
			return !slices.Contains(f.Responders(), pub(t, op3Priv)) && slices.Contains(f.Observers(), pub(t, op3Priv))
		}},
		{"an explicit responder role", with(b, []string{"p", pub(t, op3Priv), "", "responder"}), func(f *Form) bool {
			return slices.Contains(f.Responders(), pub(t, op3Priv))
		}},
		{"both roles is a responder", with(b, []string{"p", pub(t, observerPriv)}), func(f *Form) bool {
			return slices.Contains(f.Responders(), pub(t, observerPriv)) && len(f.Observers()) == 0
		}},
		{"quorum without responders", without(b, func(t []string) bool { return t[0] == "p" }), func(f *Form) bool { return f.Quorum == 2 }},
		{"expiration equal to endsAt", with(without(b, named("expiration")), []string{"expiration", "2000"}), func(f *Form) bool { return f.Expiration == 2000 }},
		{"positions past the spec's are ignored", with(b, []string{"question", "6", "Q?", TypeText, "why", "extra"}), func(f *Form) bool { return f.Questions[6].Why == "why" }},
		{"unknown tags are ignored", with(b, []string{"client", "x"}, []string{"t", "ops"}), func(f *Form) bool { return true }},
		{"group h tag", with(b, []string{"h", "ops"}), func(f *Form) bool { return f.Group == "ops" }},
		{"min equal to max", with(b, []string{"max", "5", "1000"}), func(f *Form) bool { return f.Questions[5].Max == "1000" }},
		{"multiplechoice with two defaults", b, func(f *Form) bool { return len(f.Questions[1].Defaults) == 2 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseFormTags("t", c.tags, false)
			if err != nil {
				t.Fatal(err)
			}
			if !c.check(f) {
				t.Fatalf("form: %+v", f)
			}
		})
	}
}

// A question type the spec doesn't list makes the form read-only, not
// invalid; the rules that depend on a type skip that question.
func TestFormReadOnly(t *testing.T) {
	tags := with(baseTags(t),
		[]string{"question", "6", "Rank them", "ranking"},
		[]string{"option", "r1", "First", "6"},
		[]string{"min", "6", "anything"},
		[]string{"default", "6", "r1"},
		[]string{"default", "6", "r2"},
	)
	f, err := ParseFormTags("t", tags, false)
	if err != nil {
		t.Fatal(err)
	}
	if !f.ReadOnly || len(f.Questions[6].Options) != 1 {
		t.Fatalf("form: %+v", f)
	}
	f.ID, f.Author = strings.Repeat("f", 64), pub(t, authorPriv)
	if _, err := f.NewResponse(pub(t, op1Priv), 1, []Choice{{Option: "yes"}}, nil); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("a read-only form is never answered: %v", err)
	}
	// An index named by optional/min/max/default must still exist.
	if _, err := ParseFormTags("t", with(tags, []string{"optional", "7"}), false); !errors.Is(err, ErrInvalidForm) {
		t.Fatalf("got %v", err)
	}
}

func TestFormEventFillsAlt(t *testing.T) {
	f := baseForm(t, false)
	f.Alt = ""
	ev, err := f.Event(f.Author, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(ev.Tags, func(t []string) bool { return t[0] == "alt" && t[1] == "Form: base" }) {
		t.Fatalf("alt: %v", ev.Tags)
	}
	f.Private = true
	ev, err = f.Event(f.Author, 1)
	if err != nil || slices.ContainsFunc(ev.Tags, func(t []string) bool { return t[0] == "alt" }) {
		t.Fatalf("a private form gets no alt: %v %v", err, ev)
	}
	// A form the rules refuse is never built.
	f.Quorum = 9
	if _, err := f.Event(f.Author, 1); !errors.Is(err, ErrInvalidForm) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(baseForm(t, false).Text(), "[yes] Yes — recommended") {
		t.Fatal(baseForm(t, false).Text())
	}
}
