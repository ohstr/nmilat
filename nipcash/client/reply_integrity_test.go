package client

// Reply integrity and outcome states (NIP-CASH §Responses (kind 23191), §Chunked
// Replies). Every case drives collectReply from a channel: the reply path has no
// network in it, so each rule is checked on its own.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash/transport"
)

type replyFixture struct {
	t      *testing.T
	limits transport.Limits
	nonce  string
	key    [32]byte
	s      *BatchSession
}

func newReplyFixture(t *testing.T) *replyFixture {
	t.Helper()
	nonce, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	f := &replyFixture{t: t, limits: transport.DefaultLimits(), nonce: nonce}
	copy(f.key[:], strings.Repeat("r", 32))
	f.s = hostileSession(f.limits, strings.Repeat("b", 64))
	return f
}

// chunk seals one response of this fixture's request, with the given event id.
func (f *replyFixture) chunk(id string, seq, total int, results ...transport.Result) *nip01.Event {
	f.t.Helper()
	ev := sealChunk(f.t, f.key, f.limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: f.nonce, Seq: seq, Total: total, Results: results,
	})
	ev.ID = id
	return ev
}

// raw seals a plaintext as is, bypassing EncodeResponse's own checks.
func (f *replyFixture) raw(id, plaintext string) *nip01.Event {
	f.t.Helper()
	sealed, err := nip44.Encrypt(plaintext, f.key[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return &nip01.Event{ID: id, Kind: transport.KindPrivateResponse, Content: sealed}
}

func (f *replyFixture) collect(p packedEnvelope, events ...*nip01.Event) ([]ItemOutcome, time.Duration, error) {
	f.t.Helper()
	ch := make(chan *nip01.Event, len(events))
	for _, ev := range events {
		ch <- ev
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	got, err := f.s.collectReply(ctx, ch, f.key, p, 0)
	return got, time.Since(start), err
}

func ok(id string) transport.Result {
	return transport.Result{ID: id, ResultType: "cash_status", Result: json.RawMessage(`{"id":"` + id + `"}`)}
}

func refused(id, code string) transport.Result {
	return transport.Result{ID: id, Error: &transport.ResultError{Code: code, Message: "m"}}
}

func states(got []ItemOutcome) map[string]OutcomeState {
	out := make(map[string]OutcomeState, len(got))
	for _, o := range got {
		out[o.ID] = o.State
	}
	return out
}

func wantStates(t *testing.T, got []ItemOutcome, want map[string]OutcomeState) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d outcomes, want %d: %+v", len(got), len(want), got)
	}
	have := states(got)
	for id, w := range want {
		if have[id] != w {
			t.Errorf("item %s: state %v, want %v", id, have[id], w)
		}
	}
}

func soon() int64 { return time.Now().Add(1500 * time.Millisecond).Unix() }

// T01-01 (S-CASH-154): chunks disagreeing on total make the reply incomplete; the
// outcomes they decided are kept and the error says the chunks contradict each other.
func TestT01_01_DisagreeingTotalKeepsOutcomes(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b", "c")
	got, _, err := f.collect(p, f.chunk("e1", 1, 2, ok("a")), f.chunk("e2", 2, 3, ok("b")))
	if !errors.Is(err, ErrReplyConflict) || !errors.Is(err, ErrIncompleteReply) {
		t.Fatalf("err = %v, want ErrReplyConflict wrapping ErrIncompleteReply", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeResult, "c": OutcomeUnanswered})
}

// T01-02 (S-CASH-154): two different events with one seq → incomplete, outcomes kept.
func TestT01_02_TwoEventsOneSeqKeepsOutcomes(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b", "c")
	got, _, err := f.collect(p, f.chunk("e1", 1, 2, ok("a")), f.chunk("e2", 1, 2, ok("b")))
	if !errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrReplyConflict", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeResult, "c": OutcomeUnanswered})
}

// T01-03 (S-CASH-154): seq 0 and seq above total → incomplete; the outcomes of the
// valid chunks are kept.
func TestT01_03_SeqOutOfRangeIsIncomplete(t *testing.T) {
	for name, bad := range map[string][2]int{"seq 0": {0, 2}, "seq > total": {3, 2}} {
		t.Run(name, func(t *testing.T) {
			f := newReplyFixture(t)
			p := statusPacked(f.nonce, soon(), "a", "b", "c")
			badChunk := f.raw("e2", `{"req_nonce":"`+f.nonce+`","seq":`+itoa(bad[0])+`,"total":`+itoa(bad[1])+
				`,"results":[{"id":"b","result_type":"cash_status","result":{}}]}`)
			got, _, err := f.collect(p, f.chunk("e1", 1, 2, ok("a")), badChunk, f.chunk("e3", 2, 2, ok("c")))
			if !errors.Is(err, ErrReplyConflict) {
				t.Fatalf("err = %v, want ErrReplyConflict", err)
			}
			if s := states(got); s["a"] != OutcomeResult || s["c"] != OutcomeResult {
				t.Fatalf("valid chunks' outcomes lost: %v", s)
			}
		})
	}
}

// E-XFER-12, T01-04 (S-CASH-155): an item answered in two chunks is OutcomeConflict in every
// arrival order, whether the answers agree or not; only that item.
func TestT01_04_ItemAnsweredInTwoChunks(t *testing.T) {
	for name, second := range map[string]transport.Result{
		"identical": ok("2"),
		"different": refused("2", "NOT_FOUND"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newReplyFixture(t)
			p := statusPacked(f.nonce, soon(), "1", "2", "3")
			c1 := f.chunk("e1", 1, 3, ok("1"), ok("2"))
			c2 := f.chunk("e2", 2, 3, second)
			c3 := f.chunk("e3", 3, 3, ok("3"))
			for _, order := range [][]*nip01.Event{{c1, c2, c3}, {c2, c3, c1}, {c3, c1, c2}} {
				got, _, err := f.collect(p, order...)
				if !errors.Is(err, ErrReplyConflict) {
					t.Errorf("err = %v, want ErrReplyConflict", err)
				}
				wantStates(t, got, map[string]OutcomeState{"1": OutcomeResult, "2": OutcomeConflict, "3": OutcomeResult})
			}
		})
	}
}

// T01-05 (S-CASH-155): an item answered twice inside one chunk is OutcomeConflict;
// the chunk's other answers are kept.
func TestT01_05_ItemAnsweredTwiceInOneChunk(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	got, _, err := f.collect(p, f.chunk("e1", 1, 1, ok("a"), ok("b"), refused("b", "NOT_FOUND")))
	if !errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrReplyConflict", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeConflict})
}

// T01-06 (S-CASH-152, S-CASH-157): total 3, chunks 3 then 1 arrive and not_after
// passes. Their outcomes are kept (a split's two tokens), the missing chunk's items
// are unanswered and never read as omitted.
func TestT01_06_MissingChunkIsUnansweredNotOmitted(t *testing.T) {
	f := newReplyFixture(t)
	p := methodPacked(f.nonce, soon(), "cash_transfer", "new", "rest", "x", "y")
	tok := func(id string) transport.Result {
		return transport.Result{ID: id, ResultType: "cash_transfer", Result: json.RawMessage(`{"token":"` + id + `"}`)}
	}
	got, _, err := f.collect(p, f.chunk("e3", 3, 3, tok("rest")), f.chunk("e1", 1, 3, tok("new")))
	if !errors.Is(err, ErrIncompleteReply) || errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrIncompleteReply only", err)
	}
	wantStates(t, got, map[string]OutcomeState{
		"new": OutcomeResult, "rest": OutcomeResult, "x": OutcomeUnanswered, "y": OutcomeUnanswered,
	})
	if string(got[0].Result) != `{"token":"new"}` || string(got[1].Result) != `{"token":"rest"}` {
		t.Errorf("tokens not kept: %s / %s", got[0].Result, got[1].Result)
	}
}

// T01-07 (S-CASH-153): the same event id from two relays is counted once.
func TestT01_07_SameEventTwiceIsOneChunk(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	c1 := f.chunk("e1", 1, 2, ok("a"))
	got, _, err := f.collect(p, c1, c1, f.chunk("e2", 2, 2, ok("b")))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeResult})
}

// T01-08 (S-CASH-156): a two-item envelope whose reply claims total 5 is complete
// after 2 chunks, without waiting for not_after.
func TestT01_08_InflatedTotalIsBounded(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, time.Now().Add(5*time.Second).Unix(), "a", "b")
	got, took, err := f.collect(p, f.chunk("e1", 1, 5, ok("a")), f.chunk("e2", 2, 5, ok("b")))
	if err != nil || took > time.Second {
		t.Fatalf("err = %v after %s, want complete at once", err, took)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeResult})
}

// E-XFER-14 (partial), T01-09 (S-CASH-158): an envelope-level QUOTA_EXCEEDED is every item's error.
func TestT01_09_EnvelopeErrorForEveryItem(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	ev := f.raw("e1", `{"req_nonce":"`+f.nonce+`","seq":1,"total":1,"error":{"code":"QUOTA_EXCEEDED","message":"m"}}`)
	got, _, err := f.collect(p, ev)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, o := range got {
		if o.State != OutcomeError || o.Error == nil || o.Error.Code != "QUOTA_EXCEEDED" {
			t.Errorf("%s: %+v, want QUOTA_EXCEEDED", o.ID, o)
		}
	}
}

// T01-10: an envelope error in chunk 1 and results in chunk 2 → the answered ids are
// OutcomeConflict, the others carry the error.
func TestT01_10_EnvelopeErrorAndResults(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b", "c")
	envErr := f.raw("e1", `{"req_nonce":"`+f.nonce+`","seq":1,"total":2,"error":{"code":"RATE_LIMITED","message":"m"}}`)
	got, _, err := f.collect(p, envErr, f.chunk("e2", 2, 2, ok("a")))
	if !errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrReplyConflict", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeConflict, "b": OutcomeError, "c": OutcomeError})
	if got[1].Error == nil || got[1].Error.Code != "RATE_LIMITED" {
		t.Errorf("b: %+v, want the envelope's RATE_LIMITED", got[1])
	}
}

// T01-11 (S-CASH-148): a result for an id never sent is dropped and the rest of the
// chunk kept; a chunk answering another request (req_nonce) is ignored.
func TestT01_11_AlienIDsAndForeignNonce(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	got, _, err := f.collect(p, f.chunk("e1", 1, 1, ok("a"), ok("never-sent")))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeNotServed})

	other, err := transport.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.raw("e0", `{"req_nonce":"`+other+`","seq":1,"total":1,"results":[{"id":"a","result_type":"cash_status","result":{}}]}`)
	got, _, err = f.collect(p, foreign, f.chunk("e1", 1, 1, refused("a", "NOT_FOUND")))
	if err != nil {
		t.Fatalf("err = %v: a foreign chunk must be ignored, not void the reply", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeError, "b": OutcomeNotServed})
}

// T01-12 (S-CASH-147): a complete reply omitting items → OutcomeNotServed, no error.
func TestT01_12_CompleteReplyOmissions(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b", "c")
	got, _, err := f.collect(p, f.chunk("e1", 1, 1, ok("b")))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeNotServed, "b": OutcomeResult, "c": OutcomeNotServed})
}

// T01-13 (S-CASH-226): a chunk encrypted to another key is ignored and the wait
// continues; the author is never checked.
func TestT01_13_ForeignKeyIgnoredAuthorUnchecked(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a")
	var otherKey [32]byte
	copy(otherKey[:], strings.Repeat("x", 32))
	forged := sealChunk(t, otherKey, f.limits, transport.ResponseEnvelope{
		Version: transport.EnvelopeVersion, ReqNonce: f.nonce, Seq: 1, Total: 1,
		Results: []transport.Result{refused("a", "NOT_FOUND")},
	})
	forged.ID = "forged"
	real := f.chunk("e1", 1, 1, ok("a"))
	real.PubKey = strings.Repeat("f", 64) // any author: only the key authenticates
	got, _, err := f.collect(p, forged, real)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult})
}

// T01-14: the wait ends at not_after even when the caller's context is longer.
func TestT01_14_WaitEndsAtNotAfter(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, time.Now().Add(time.Second).Unix(), "a", "b")
	got, took, err := f.collect(p, f.chunk("e1", 1, 2, ok("a")))
	if took > 3*time.Second {
		t.Fatalf("waited %s, past not_after", took)
	}
	if !errors.Is(err, ErrIncompleteReply) {
		t.Fatalf("err = %v, want ErrIncompleteReply", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeUnanswered})
}

// T01-15: a chunk with neither results nor error decides nothing and leaves the reply
// incomplete, keeping the other chunks' outcomes; "results": [] is a complete reply of
// omissions.
func TestT01_15_ChunkThatDecidesNothing(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	empty := f.raw("e2", `{"req_nonce":"`+f.nonce+`","seq":2,"total":2}`)
	got, _, err := f.collect(p, f.chunk("e1", 1, 2, ok("a")), empty)
	if !errors.Is(err, ErrIncompleteReply) || errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrIncompleteReply", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeResult, "b": OutcomeUnanswered})

	p = statusPacked(f.nonce, soon(), "a", "b") // the first wait used up not_after
	none := f.raw("e3", `{"req_nonce":"`+f.nonce+`","seq":1,"total":1,"results":[]}`)
	got, _, err = f.collect(p, none)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeNotServed, "b": OutcomeNotServed})

	// And a hub encoding an all-omitted reply through EncodeResponse sends exactly that.
	got, _, err = f.collect(p, f.chunk("e4", 1, 1))
	if err != nil {
		t.Fatalf("EncodeResponse of no results: err = %v", err)
	}
	wantStates(t, got, map[string]OutcomeState{"a": OutcomeNotServed, "b": OutcomeNotServed})
}

// T01-16: an item error's detail survives to the outcome; an envelope-level detail is
// on every item; no detail reads as "".
func TestT01_16_ErrorDetail(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "a", "b")
	ev := f.raw("e1", `{"req_nonce":"`+f.nonce+`","seq":1,"total":1,"results":[`+
		`{"id":"a","error":{"code":"RESTRICTED","message":"m","detail":"own_address"}},`+
		`{"id":"b","error":{"code":"RESTRICTED","message":"m"}}]}`)
	got, _, err := f.collect(p, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Error.Detail != "own_address" || got[1].Error.Detail != "" {
		t.Fatalf("details = %q, %q", got[0].Error.Detail, got[1].Error.Detail)
	}

	env := f.raw("e2", `{"req_nonce":"`+f.nonce+`","seq":1,"total":1,"error":{"code":"RESTRICTED","message":"m","detail":"network"}}`)
	got, _, err = f.collect(p, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o.Error == nil || o.Error.Detail != "network" {
			t.Errorf("%s: %+v, want detail network", o.ID, o.Error)
		}
	}
}

// T01-17 (CASH-RESP-04): a result whose result_type is not the item's method, or is
// missing, is OutcomeConflict for that item only; an error needs no result_type.
func TestT01_17_ResultTypeMustMatchMethod(t *testing.T) {
	f := newReplyFixture(t)
	p := statusPacked(f.nonce, soon(), "wrong", "missing", "err", "good")
	got, _, err := f.collect(p, f.chunk("e1", 1, 1,
		transport.Result{ID: "wrong", ResultType: "cash_redeem", Result: json.RawMessage(`{}`)},
		transport.Result{ID: "missing", Result: json.RawMessage(`{}`)},
		refused("err", "NOT_FOUND"),
		ok("good"),
	))
	if !errors.Is(err, ErrReplyConflict) {
		t.Fatalf("err = %v, want ErrReplyConflict", err)
	}
	wantStates(t, got, map[string]OutcomeState{
		"wrong": OutcomeConflict, "missing": OutcomeConflict, "err": OutcomeError, "good": OutcomeResult,
	})
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
