package nippf

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func id(c byte) string { return strings.Repeat(string(c), 64) }

func mustResult(t *testing.T, f *Form, author string, at int64, eid string, more ...[]string) *Result {
	t.Helper()
	r, err := ParseResult(resultEv(t, f, author, at, eid, more...))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// resp: a parsed response to f by priv's pubkey at createdAt with id eid.
func resp(t *testing.T, f *Form, priv string, at int64, eid string, more ...[]string) *Response {
	t.Helper()
	ev := nip01.NewUnsignedEvent(KindResponse, pub(t, priv), "", respTags(f, more...)...)
	ev.CreatedAt, ev.ID = uint64(at), eid
	r, err := ParseResponse(ev)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestClosingResult(t *testing.T) {
	f := baseForm(t, false)
	cancel := []string{"status", "cancelled"}
	early := mustResult(t, f, f.Author, 100, id('5'), cancel)
	tieLow := mustResult(t, f, f.Author, 100, id('3'), cancel)
	late := mustResult(t, f, f.Author, 200, id('1'), cancel)
	byOther := mustResult(t, f, pub(t, op1Priv), 50, id('0'), cancel)
	invalid := mustResult(t, f, f.Author, 10, id('0'), []string{"status", "decided"})
	if got := f.Closing([]*Result{late, early, byOther, invalid}); got != early {
		t.Fatalf("the earliest valid result by the author: %+v", got)
	}
	if got := f.Closing([]*Result{early, tieLow, late}); got != tieLow {
		t.Fatalf("ties go to the lowest id: %+v", got)
	}
	if f.Closing([]*Result{byOther, invalid}) != nil || f.Closing(nil) != nil {
		t.Fatal("no closing result")
	}
}

func TestStates(t *testing.T) {
	f := baseForm(t, false) // endsAt 2000, expiration 3000
	decided := mustResult(t, f, f.Author, 1500, id('1'), []string{"status", "decided"}, []string{"response", "yes"}, []string{"response", "sat"}, []string{"answer", "3", "2"})
	def := mustResult(t, f, f.Author, 1500, id('1'), []string{"status", "default"}, []string{"response", "no"}, []string{"response", "sat"}, []string{"response", "sun"}, []string{"answer", "3", "2"})
	cancelled := mustResult(t, f, f.Author, 1500, id('1'), []string{"status", "cancelled"})
	cases := []struct {
		closing *Result
		now     int64
		want    State
	}{
		{nil, 1000, StateOpen},
		{nil, 2000, StateOpen}, // endsAt not passed until after it
		{nil, 2001, StateEnded},
		{decided, 1600, StateDecided},
		{def, 2500, StateDefault},
		{cancelled, 1600, StateCancelled},
		{nil, 3001, StateExpired},
		{decided, 3001, StateExpired}, // expired overrides
	}
	for _, c := range cases {
		if got := f.State(c.closing, c.now); got != c.want {
			t.Errorf("at %d: %s, want %s", c.now, got, c.want)
		}
	}
	g := baseForm(t, false)
	g.EndsAt, g.Expiration = 0, 0
	if g.State(nil, 1<<40) != StateOpen {
		t.Error("no endsAt, no expiration: open")
	}
	if StateOpen.Closed() || StateExpired.Closed() || !StateEnded.Closed() || !StateDefault.Closed() {
		t.Error("Closed")
	}
}

func TestSelection(t *testing.T) {
	f := baseForm(t, false) // responders op1, op2; observer; endsAt 2000
	v := validMore()
	alt := [][]string{{"response", "no"}, {"response", "sun"}, {"answer", "3", "5"}}
	op1Old := resp(t, f, op1Priv, 100, id('a'), v...)
	op1New := resp(t, f, op1Priv, 200, id('b'), alt...)
	op1Late := resp(t, f, op1Priv, 2001, id('c'), v...)   // after endsAt
	op1Bad := resp(t, f, op1Priv, 300, id('d'), v[:1]...) // invalid: ignored
	op2 := resp(t, f, op2Priv, 150, id('e'), v...)
	op2Withdraw := resp(t, f, op2Priv, 160, id('f'))
	observer := resp(t, f, observerPriv, 100, id('1'), v...)
	stranger := resp(t, f, strangerPriv, 100, id('2'), v...)

	sel := f.Select([]*Response{op1Old, op1New, op1Late, op1Bad, op2, op2Withdraw, observer, stranger}, nil)
	if len(sel) != 1 || sel[0] != op1New {
		t.Fatalf("selected: %+v", sel)
	}
	// The closing result's created_at bounds the selection too.
	closing := mustResult(t, f, f.Author, 155, id('9'), []string{"status", "cancelled"})
	sel = f.Select([]*Response{op1Old, op1New, op2, op2Withdraw}, closing)
	if len(sel) != 2 || sel[0] != op1Old || sel[1] != op2 {
		t.Fatalf("selected before the closing result: %+v", sel)
	}
	// A response at the closing result's created_at and at endsAt still counts.
	atClose := resp(t, f, op1Priv, 155, id('3'), alt...)
	atEnd := resp(t, f, op2Priv, 2000, id('4'), alt...)
	sel = f.Select([]*Response{op1Old, atClose}, closing)
	if len(sel) != 1 || sel[0] != atClose {
		t.Fatalf("at the closing result: %+v", sel)
	}
	if sel = f.Select([]*Response{op2, atEnd}, nil); len(sel) != 1 || sel[0] != atEnd {
		t.Fatalf("at endsAt: %+v", sel)
	}
	// Ties on created_at go to the lowest id, a withdrawal included.
	tieHigh := resp(t, f, op1Priv, 500, id('8'), v...)
	tieLow := resp(t, f, op1Priv, 500, id('7'), alt...)
	if sel = f.Select([]*Response{tieHigh, tieLow}, nil); len(sel) != 1 || sel[0] != tieLow {
		t.Fatalf("tie: %+v", sel)
	}
	tieWithdraw := resp(t, f, op1Priv, 500, id('6'))
	if sel = f.Select([]*Response{tieHigh, tieLow, tieWithdraw}, nil); len(sel) != 0 {
		t.Fatalf("a withdrawal with the lowest id wins the tie: %+v", sel)
	}
	// A response to another form is ignored.
	other := *f
	other.ID = id('e')
	if sel = other.Select([]*Response{op1Old}, nil); len(sel) != 0 {
		t.Fatalf("another form's: %+v", sel)
	}
}

func TestResponders(t *testing.T) {
	pubF := baseForm(t, false)
	pubF.Parties = nil
	if !pubF.Allowed(pub(t, strangerPriv)) {
		t.Error("a public form without responders accepts any pubkey")
	}
	privF := baseForm(t, true)
	privF.Parties = []Party{{PubKey: pub(t, observerPriv), Role: RoleObserver}}
	if privF.Allowed(pub(t, strangerPriv)) || privF.Allowed(pub(t, observerPriv)) || !privF.Allowed(privF.Author) {
		t.Error("a private form without responders accepts only its author")
	}
	pubF.Parties = []Party{{PubKey: pub(t, observerPriv), Role: RoleObserver}}
	if pubF.Allowed(pub(t, observerPriv)) || !pubF.Allowed(pub(t, strangerPriv)) {
		t.Error("an observer may not respond")
	}
	f := baseForm(t, false)
	if f.Allowed(pub(t, strangerPriv)) || !f.Allowed(pub(t, op2Priv)) {
		t.Error("with responders, only they")
	}
}

func TestTally(t *testing.T) {
	f := baseForm(t, false)
	sel := f.Select([]*Response{
		resp(t, f, op1Priv, 100, id('a'), []string{"response", "other", "a third way"}, []string{"response", "sat"}, []string{"response", "sun"}, []string{"answer", "3", "4", "about"}),
		resp(t, f, op2Priv, 100, id('b'), []string{"response", "other", "same"}, []string{"response", "sat", "only sat"}, []string{"answer", "3", "1"}, []string{"answer", "2", "hi"}),
	}, nil)
	tl := f.Tally(sel)
	if tl.Responses != 2 || !tl.QuorumMet {
		t.Fatalf("tally: %+v", tl)
	}
	q0, q1, q2, q3 := tl.Questions[0], tl.Questions[1], tl.Questions[2], tl.Questions[3]
	if q0.Counts["other"] != 2 || q0.Counts["yes"] != 0 || len(q0.Counts) != 3 || len(q0.Notes["other"]) != 2 || q0.Notes["other"][1].Text != "same" {
		t.Fatalf("q0: %+v", q0)
	}
	if q1.Counts["sat"] != 2 || q1.Counts["sun"] != 1 || q1.Notes["sat"][0] != (Note{PubKey: pub(t, op2Priv), Text: "only sat"}) {
		t.Fatalf("q1: %+v", q1)
	}
	if len(q2.Answers) != 1 || q2.Answers[0].Value != "hi" || q2.Counts != nil {
		t.Fatalf("q2: %+v", q2)
	}
	if len(q3.Answers) != 2 || q3.Answers[0] != (AnswerBy{PubKey: pub(t, op1Priv), Value: "4", Note: "about"}) {
		t.Fatalf("q3: %+v", q3)
	}
	if f.Tally(sel[:1]).QuorumMet {
		t.Fatal("one response doesn't meet a quorum of 2")
	}
}
