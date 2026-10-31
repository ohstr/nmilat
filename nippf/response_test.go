package nippf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// respTags: a response's tags to baseForm, its e and p first.
func respTags(f *Form, more ...[]string) [][]string {
	return append([][]string{{"e", f.ID}, {"p", f.Author}}, more...)
}

// validMore: the response and answer tags of a valid response to baseForm.
func validMore() [][]string {
	return [][]string{
		{"response", "yes"},
		{"response", "sat"},
		{"answer", "3", "2"},
	}
}

func checkTags(t *testing.T, f *Form, tags [][]string) error {
	t.Helper()
	ev := nip01.NewUnsignedEvent(KindResponse, pub(t, op1Priv), "", tags...)
	ev.ID = strings.Repeat("1", 64)
	r, err := ParseResponse(ev)
	if err != nil {
		return err
	}
	return f.Check(r)
}

func TestResponseValid(t *testing.T) {
	f := baseForm(t, false)
	cases := map[string][][]string{
		"the minimum": validMore(),
		"every question answered": append(validMore(),
			[]string{"answer", "2", "free words"},
			[]string{"answer", "4", "2026-06-30"},
			[]string{"answer", "5", "1000"}),
		"multiplechoice with both":         append(validMore(), []string{"response", "sun"}),
		"noteRequired with a note":         {{"response", "other", "my own way"}, {"response", "sat"}, {"answer", "3", "2"}},
		"a note on any answer":             {{"response", "yes", "sure"}, {"response", "sat", "after noon"}, {"answer", "3", "2", "about"}},
		"number at the min":                {{"response", "yes"}, {"response", "sat"}, {"answer", "3", "-1.5"}},
		"number at the max, written 10.00": {{"response", "yes"}, {"response", "sat"}, {"answer", "3", "10.00"}},
		"number zero":                      {{"response", "yes"}, {"response", "sat"}, {"answer", "3", "0"}},
		"number of 18 significant digits":  {{"response", "yes"}, {"response", "sat"}, {"answer", "3", "0.000123456789012345678"}},
		"tags in any order":                {{"answer", "3", "2"}, {"response", "sat"}, {"response", "yes"}},
		"positions past the spec's":        {{"response", "yes", "", "x"}, {"response", "sat"}, {"answer", "3", "2", "", "y"}},
	}
	for name, more := range cases {
		t.Run(name, func(t *testing.T) {
			if err := checkTags(t, f, respTags(f, more...)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every response rule, one failing case each.
func TestResponseRules(t *testing.T) {
	f := baseForm(t, false)
	v := validMore()
	set := func(i int, tag ...string) [][]string { m := slices.Clone(v); m[i] = tag; return m }
	cases := map[string][][]string{
		// exactly one e tag
		"two e tags": append([][]string{{"e", strings.Repeat("e", 64)}}, respTags(f, v...)...),
		"no e tag":   append([][]string{{"p", f.Author}}, v...),
		// option ids exist, once each
		"unknown option": append(v, []string{"response", "maybe"}),
		"option twice":   append(v, []string{"response", "sat"}),
		// singlechoice: exactly one
		"singlechoice with none": v[1:],
		"singlechoice with two":  append(v, []string{"response", "no"}),
		// multiplechoice: at least one
		"multiplechoice with none": {v[0], v[2]},
		// other questions: exactly one answer, valid, within bounds
		"number unanswered":           v[:2],
		"number answered twice":       append(v, []string{"answer", "3", "3"}),
		"number below its min":        set(2, "answer", "3", "-2"),
		"number above its max":        set(2, "answer", "3", "10.01"),
		"number with a plus sign":     set(2, "answer", "3", "+2"),
		"number with a leading zero":  set(2, "answer", "3", "02"),
		"number with an exponent":     set(2, "answer", "3", "1e1"),
		"number ending in a dot":      set(2, "answer", "3", "2."),
		"number of 19 significant":    set(2, "answer", "3", "1.234567890123456789"),
		"number with non-ASCII digit": set(2, "answer", "3", "٢"),
		"text empty":                  append(v, []string{"answer", "2", ""}),
		"text answered twice":         append(v, []string{"answer", "2", "a"}, []string{"answer", "2", "b"}),
		"date not a calendar date":    append(v, []string{"answer", "4", "2026-02-29"}),
		"date in another format":      append(v, []string{"answer", "4", "30/06/2026"}),
		"date below its min":          append(v, []string{"answer", "4", "2025-12-31"}),
		"date above its max":          append(v, []string{"answer", "4", "2027-01-01"}),
		"time with a leading zero":    append(v, []string{"answer", "5", "01000"}),
		"time negative":               append(v, []string{"answer", "5", "-5"}),
		"time below its min":          append(v, []string{"answer", "5", "999"}),
		// every answer names such a question
		"answer to a choice question": append(v, []string{"answer", "0", "yes"}),
		"answer to no question":       append(v, []string{"answer", "9", "x"}),
		// noteRequired
		"noteRequired without a note":    set(0, "response", "other"),
		"noteRequired with a blank note": set(0, "response", "other", "  \t "),
		// malformed tags
		"response tag without an id":      append(v, []string{"response"}),
		"answer tag without a value":      append(v, []string{"answer", "2"}),
		"answer with a bad index":         append(v, []string{"answer", "02", "x"}),
		"e tag that isn't an id":          append([][]string{{"e", "form"}, {"p", f.Author}}, v...),
		"e tag empty":                     append([][]string{{"e"}, {"p", f.Author}}, v...),
		"response naming another form id": append([][]string{{"e", strings.Repeat("e", 64)}, {"p", f.Author}}, v...),
	}
	for name, more := range cases {
		t.Run(name, func(t *testing.T) {
			tags := more
			if len(more) == 0 || more[0][0] != "e" && more[0][0] != "p" {
				tags = respTags(f, more...)
			}
			err := checkTags(t, f, tags)
			t.Log(err)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("got %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestResponseOptional(t *testing.T) {
	tags := [][]string{
		{"question", "0", "One?", TypeSingle}, {"option", "a", "A", "0"}, {"option", "b", "B", "0"}, {"optional", "0"},
		{"question", "1", "Any?", TypeMulti}, {"option", "c", "C", "1"}, {"option", "d", "D", "1"}, {"optional", "1"},
		{"question", "2", "Say", TypeText}, {"optional", "2"},
	}
	f, err := ParseFormTags("t", tags, false)
	if err != nil {
		t.Fatal(err)
	}
	f.ID, f.Author = strings.Repeat("f", 64), pub(t, authorPriv)
	ok := [][][]string{
		{{"response", "a"}},
		{{"response", "c"}, {"response", "d"}},
		{{"answer", "2", "x"}},
	}
	for _, more := range ok {
		if err := checkTags(t, f, respTags(f, more...)); err != nil {
			t.Fatalf("%v: %v", more, err)
		}
	}
	bad := [][][]string{
		{{"response", "a"}, {"response", "b"}},                // at most one, optional singlechoice
		{{"answer", "2", "x"}, {"answer", "2", "y"}},          // at most one answer
		{{"response", "a"}, {"response", "a", "twice"}},       // once each
		{{"answer", "2", "x"}, {"answer", "1", "not a text"}}, // a choice question
	}
	for _, more := range bad {
		if err := checkTags(t, f, respTags(f, more...)); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("%v: got %v", more, err)
		}
	}
	// No response or answer tag at all is a withdrawal, never a response.
	ev := nip01.NewUnsignedEvent(KindResponse, pub(t, op1Priv), "", respTags(f)...)
	r, err := ParseResponse(ev)
	if err != nil || !r.Withdrawal() || f.Check(r) != nil {
		t.Fatalf("withdrawal: %v %+v", err, r)
	}
	if _, err := f.NewResponse(pub(t, op1Priv), 1, nil, nil); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("an empty response is NewWithdrawal's: %v", err)
	}
}

func TestWithdrawal(t *testing.T) {
	f := baseForm(t, false)
	ev, err := f.NewWithdrawal(pub(t, op1Priv), 5)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseResponse(ev)
	if err != nil || !r.Withdrawal() || r.CreatedAt != 5 {
		t.Fatalf("withdrawal: %v %+v", err, r)
	}
	if !slices.ContainsFunc(ev.Tags, func(t []string) bool { return t[0] == "expiration" && t[1] == "3000" }) {
		t.Fatalf("a withdrawal carries the form's expiration: %v", ev.Tags)
	}
	// Two e tags and nothing else is neither a withdrawal nor a response.
	two := nip01.NewUnsignedEvent(KindResponse, pub(t, op1Priv), "", []string{"e", f.ID}, []string{"e", f.ID})
	if _, err := ParseResponse(two); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.NewWithdrawal(pub(t, observerPriv), 5); !errors.Is(err, ErrNotResponder) {
		t.Fatalf("an observer never responds: %v", err)
	}
}

func TestNewResponse(t *testing.T) {
	f := baseForm(t, false)
	f.Group = "ops"
	ev, err := f.NewResponse(pub(t, op2Priv), 7,
		[]Choice{{Option: "other", Note: "a third way"}, {Option: "sun", Note: "   "}},
		[]Answer{{Question: 3, Value: "4", Note: "roughly"}})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"e", f.ID}, {"p", f.Author}, {"expiration", "3000"}, {"h", "ops"},
		{"response", "other", "a third way"}, {"response", "sun"}, {"answer", "3", "4", "roughly"},
	}
	if !sameTags(ev.Tags, want) || ev.Kind != KindResponse || ev.Content != "" || ev.CreatedAt != 7 || ev.PubKey != pub(t, op2Priv) {
		t.Fatalf("response: %+v", ev)
	}
	// A client never publishes an invalid response.
	if _, err := f.NewResponse(pub(t, op2Priv), 7, []Choice{{Option: "other"}, {Option: "sun"}}, []Answer{{Question: 3, Value: "4"}}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("noteRequired: %v", err)
	}
	if _, err := f.NewResponse(pub(t, strangerPriv), 7, []Choice{{Option: "yes"}, {Option: "sun"}}, []Answer{{Question: 3, Value: "4"}}); !errors.Is(err, ErrNotResponder) {
		t.Fatalf("not a responder: %v", err)
	}
}

func TestValidValue(t *testing.T) {
	good := map[string][]string{
		TypeText:   {"x", " "},
		TypeNumber: {"0", "-0", "7", "-7.25", "123456789012345678", "0.000000000000000001"},
		TypeDate:   {"2024-02-29", "0001-01-01", "9999-12-31"},
		TypeTime:   {"0", "1793430000", "99999999999999999999"},
	}
	bad := map[string][]string{
		TypeText:   {""},
		TypeNumber: {"", "-", ".5", "1.", "1,5", "01", "1234567890123456789", " 1", "NaN"},
		TypeDate:   {"2023-02-29", "2026-13-01", "2026-1-01", "26-01-01", "2026-01-01T00:00:00Z"},
		TypeTime:   {"", "01", "-1", "1.5", "1e9"},
		TypeSingle: {"a"},
		"ranking":  {"1"},
	}
	for typ, vs := range good {
		for _, v := range vs {
			if !ValidValue(typ, v) {
				t.Errorf("%s %q should be valid", typ, v)
			}
		}
	}
	for typ, vs := range bad {
		for _, v := range vs {
			if ValidValue(typ, v) {
				t.Errorf("%s %q should be invalid", typ, v)
			}
		}
	}
	if compareValues(TypeNumber, "10", "9.99") <= 0 || compareValues(TypeNumber, "-0", "0") != 0 || compareValues(TypeTime, "100", "99") <= 0 {
		t.Error("numeric comparison")
	}
}
