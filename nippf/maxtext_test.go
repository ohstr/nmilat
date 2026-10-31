package nippf

import (
	"errors"
	"strings"
	"testing"
)

// The builders keep notes and answers under MaxText characters; the parsers
// accept longer ones (a SHOULD of the writer, not a validity rule).
func TestMaxText(t *testing.T) {
	f := baseForm(t, false)
	long := strings.Repeat("é", MaxText)
	short := strings.Repeat("é", MaxText-1)
	base := []Choice{{Option: "yes"}, {Option: "sat"}}
	num := []Answer{{Question: 3, Value: "2"}}
	if _, err := f.NewResponse(pub(t, op1Priv), 1, []Choice{{Option: "yes", Note: short}, {Option: "sat"}}, num); err != nil {
		t.Fatalf("%d characters: %v", MaxText-1, err)
	}
	if _, err := f.NewResponse(pub(t, op1Priv), 1, []Choice{{Option: "yes", Note: long}, {Option: "sat"}}, num); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("a long note: %v", err)
	}
	if _, err := f.NewResponse(pub(t, op1Priv), 1, base, append(num, Answer{Question: 2, Value: long})); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("a long answer: %v", err)
	}
	if err := checkTags(t, f, respTags(f, []string{"response", "yes", long}, []string{"response", "sat"}, []string{"answer", "3", "2"}, []string{"answer", "2", long})); err != nil {
		t.Fatalf("read: %v", err)
	}
}
