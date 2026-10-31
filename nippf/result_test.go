package nippf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func resultEv(t testing.TB, f *Form, author string, createdAt int64, id string, more ...[]string) *nip01.Event {
	t.Helper()
	ev := nip01.NewUnsignedEvent(KindResult, author, "", append([][]string{{"e", f.ID}}, more...)...)
	ev.CreatedAt, ev.ID = uint64(createdAt), id
	return ev
}

func checkResult(t *testing.T, f *Form, more ...[]string) error {
	t.Helper()
	r, err := ParseResult(resultEv(t, f, f.Author, 1, strings.Repeat("1", 64), more...))
	if err != nil {
		return err
	}
	return f.CheckResult(r)
}

func TestResultValid(t *testing.T) {
	f := baseForm(t, false)
	cases := map[string][][]string{
		"decided":                        {{"status", "decided"}, {"response", "yes"}, {"response", "sat"}, {"answer", "3", "2"}},
		"decided, noteRequired, no note": {{"status", "decided"}, {"response", "other"}, {"response", "sat"}, {"answer", "3", "2"}},
		"decided with notes":             {{"status", "decided"}, {"response", "yes", "unanimous"}, {"response", "sat"}, {"answer", "3", "2"}},
		"default":                        {{"status", "default"}, {"response", "no"}, {"response", "sat"}, {"response", "sun"}, {"answer", "3", "2"}},
		"default in another order":       {{"answer", "3", "2"}, {"response", "sun"}, {"status", "default"}, {"response", "sat"}, {"response", "no"}},
		"cancelled":                      {{"status", "cancelled"}},
		"p tags and content":             {{"p", pub(t, op1Priv)}, {"status", "cancelled"}},
	}
	for name, more := range cases {
		t.Run(name, func(t *testing.T) {
			if err := checkResult(t, f, more...); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every result rule, one failing case each.
func TestResultRules(t *testing.T) {
	f := baseForm(t, false)
	cases := map[string][][]string{
		"no status":                    {{"response", "yes"}},
		"two status tags":              {{"status", "cancelled"}, {"status", "cancelled"}},
		"unknown status":               {{"status", "approved"}},
		"decided, invalid outcome":     {{"status", "decided"}, {"response", "yes"}},
		"decided, no outcome":          {{"status", "decided"}},
		"decided, value out of bounds": {{"status", "decided"}, {"response", "yes"}, {"response", "sat"}, {"answer", "3", "11"}},
		"default, missing one default": {{"status", "default"}, {"response", "no"}, {"response", "sat"}, {"answer", "3", "2"}},
		"default, one more":            {{"status", "default"}, {"response", "no"}, {"response", "sat"}, {"response", "sun"}, {"answer", "3", "2"}, {"answer", "2", "x"}},
		"default, another value":       {{"status", "default"}, {"response", "yes"}, {"response", "sat"}, {"response", "sun"}, {"answer", "3", "2"}},
		"default, an option twice":     {{"status", "default"}, {"response", "no"}, {"response", "sat"}, {"response", "sat"}, {"answer", "3", "2"}},
		"cancelled with an outcome":    {{"status", "cancelled"}, {"response", "yes"}},
		"cancelled with an answer":     {{"status", "cancelled"}, {"answer", "2", "x"}},
		"a malformed answer":           {{"status", "cancelled"}, {"answer", "2"}},
		"a second e tag":               {{"e", strings.Repeat("e", 64)}, {"status", "cancelled"}},
	}
	for name, more := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkResult(t, f, more...)
			t.Log(err)
			if !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("got %v, want ErrInvalidResult", err)
			}
		})
	}
	// A default result needs a form with a default tag.
	g, err := ParseFormTags("t", [][]string{{"question", "0", "Say", TypeText}}, false)
	if err != nil {
		t.Fatal(err)
	}
	g.ID, g.Author = strings.Repeat("f", 64), pub(t, authorPriv)
	if err := checkResult(t, g, []string{"status", "default"}); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("default without default tags: %v", err)
	}
	// Another form's result.
	other := *f
	other.ID = strings.Repeat("e", 64)
	r, _ := ParseResult(resultEv(t, f, f.Author, 1, strings.Repeat("1", 64), []string{"status", "cancelled"}))
	if err := other.CheckResult(r); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("another form's: %v", err)
	}
}

func TestNewResult(t *testing.T) {
	f := baseForm(t, false)
	ev, err := f.NewResult(9, StatusDefault, "nobody answered", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"e", f.ID}, {"p", pub(t, op1Priv)}, {"p", pub(t, op2Priv)}, {"expiration", "3000"}, {"status", "default"},
		{"response", "no"}, {"response", "sat"}, {"response", "sun"}, {"answer", "3", "2"},
	}
	if !sameTags(ev.Tags, want) || ev.PubKey != f.Author || ev.Content != "nobody answered" {
		t.Fatalf("result: %v", ev.Tags)
	}
	if _, err := f.NewResult(9, StatusCancelled, "", []Choice{{Option: "yes"}}, nil); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.NewResult(9, "approved", "", nil, nil); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("got %v", err)
	}
	cs, as := f.DefaultOutcome()
	if !slices.Equal(cs, []Choice{{Option: "no"}, {Option: "sat"}, {Option: "sun"}}) || !slices.Equal(as, []Answer{{Question: 3, Value: "2"}}) {
		t.Fatalf("defaults: %v %v", cs, as)
	}
}
