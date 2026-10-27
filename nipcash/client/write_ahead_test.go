package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// transferOK is a cash_transfer success the client can parse.
var transferOK = json.RawMessage(`{"amount_millis":7000,"identity_type":"pubkey","identity_value":"` + strings.Repeat("ab", 32) + `"}`)

func answerTransfer(item transport.Item) *transport.Result {
	return &transport.Result{ID: item.ID, ResultType: item.Method, Result: transferOK}
}

func answerCode(code string) func(transport.Item) *transport.Result {
	return func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Error: &transport.ResultError{Code: code, Message: "test"}}
	}
}

// waTransfer is one transfer of a fresh bill, and the session to send it on.
type waTransfer struct {
	s     *BatchSession
	relay *cashtest.Relay
	item  BatchTransfer
}

func newWATransfer(t *testing.T, hub *fakeHub, opts ...SessionOption) waTransfer {
	t.Helper()
	relay := cashtest.NewRelay(t)
	hub.hub(t, relay)
	return newWATransferOn(t, hub, relay, opts...)
}

func newWATransferOn(t *testing.T, hub *fakeHub, relay *cashtest.Relay, opts ...SessionOption) waTransfer {
	t.Helper()
	ctx, cancel := e2eContext(t)
	defer cancel()
	s, err := OpenBatchSession(ctx, hub.hubXOnly, []string{relay.URL()}, opts...)
	if err != nil {
		t.Fatalf("OpenBatchSession: %v", err)
	}
	priv, target := sessionKeypair(t)
	_, to := sessionKeypair(t)
	return waTransfer{s: s, relay: relay, item: BatchTransfer{ID: "1", Bill: mustBill(t, target), Params: nipcash.CashTransferParams{
		To: nipcash.Pubkey(to), Credential: nipcash.BySigning(priv), CurrentAmount: 7000,
	}}}
}

func requestsOn(r *cashtest.Relay) []*nip01.Event {
	var out []*nip01.Event
	for _, ev := range r.Accepted() {
		if ev.Kind == transport.KindPrivateRequest {
			out = append(out, ev)
		}
	}
	return out
}

// T11: the call is written ahead with the exact deadline the envelope carries,
// before anything is published, and the outcome names its request_id.
func TestWriteAhead_ExactDeadlineBeforePublish(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	w := newWATransfer(t, hub)
	j := newTestJournal()
	ctx, cancel := e2eContext(t)
	defer cancel()

	var publishedBeforeWrite bool
	ctx = WithPublishFilter(ctx, func(*nip01.Event) bool {
		publishedBeforeWrite = len(j.all()) == 0
		return true
	})
	out, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "dev-a")
	if err != nil {
		t.Fatalf("TransferMany: %v", err)
	}
	if publishedBeforeWrite {
		t.Fatal("the request was published before the call was written ahead")
	}
	calls := j.all()
	if len(calls) != 1 {
		t.Fatalf("%d calls written ahead, want 1", len(calls))
	}
	pc := calls[0]
	envs := hub.envelopes()
	if len(envs) != 1 {
		t.Fatalf("hub saw %d envelopes", len(envs))
	}
	if pc.Deadline != envs[0].NotAfter {
		t.Errorf("written deadline %d, envelope not_after %d", pc.Deadline, envs[0].NotAfter)
	}
	if pc.RequestID == "" || pc.RequestID != out[0].RequestID {
		t.Errorf("request_id written %q, outcome %q", pc.RequestID, out[0].RequestID)
	}
	if pc.Method != nipcash.MethodCashTransfer || pc.Device != "dev-a" || pc.Target != w.item.Bill.Target() ||
		pc.HubIdentity != hub.hubXOnly || pc.MaxRequestAge != transport.DefaultMaxRequestAge || pc.Amount != 7000 {
		t.Errorf("written call = %+v", pc)
	}
	if strings.Contains(string(pc.Params), "cash_secret") {
		t.Error("Params hold a cash secret")
	}
	if w := nipcash.DeadlineWindow(transport.DefaultMaxRequestAge); pc.Deadline > time.Now().Unix()+w {
		t.Errorf("deadline %d beyond now + %d", pc.Deadline, w)
	}
	if out[0].NeedsLookup() {
		t.Error("a decoded result needs no lookup")
	}
}

func TestWriteAhead_RefusedBeforeAnythingIsWritten(t *testing.T) {
	ctx, cancel := e2eContext(t)
	defer cancel()

	t.Run("no journal", func(t *testing.T) {
		w := newWATransfer(t, newTestHub(t, answerTransfer))
		if _, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, nil, "d"); !errors.Is(err, ErrNoJournal) {
			t.Fatalf("err = %v, want ErrNoJournal", err)
		}
		if n := len(requestsOn(w.relay)); n != 0 {
			t.Fatalf("%d requests published", n)
		}
	})
	t.Run("duplicate request_id", func(t *testing.T) {
		w := newWATransfer(t, newTestHub(t, answerTransfer))
		a, b := w.item, w.item
		a.Params.RequestID, b.Params.RequestID = testRequestID, testRequestID
		b.ID = "2"
		j := newTestJournal()
		if _, err := w.s.TransferMany(ctx, []BatchTransfer{a, b}, j, "d"); !errors.Is(err, ErrDuplicateRequestID) {
			t.Fatalf("err = %v, want ErrDuplicateRequestID", err)
		}
		if len(j.all()) != 0 || len(requestsOn(w.relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("hub without max_request_age", func(t *testing.T) {
		hub := newTestHub(t, answerTransfer)
		w := newWATransfer(t, hub)
		// A newer announcement with no max_request_age at all.
		ev := hub.hub(t).Announcement()
		ev.CreatedAt++
		kept := ev.Tags[:0]
		for _, tag := range ev.Tags {
			if len(tag) >= 2 && tag[0] == "limit" && tag[1] == transport.LimitMaxRequestAge {
				continue
			}
			kept = append(kept, tag)
		}
		ev.Tags = kept
		if err := ev.Sign(hub.hubPriv); err != nil {
			t.Fatal(err)
		}
		if ok, msg := w.relay.Publish(ev); !ok {
			t.Fatal(msg)
		}
		if err := w.s.Refresh(ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		j := newTestJournal()
		if _, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d"); !errors.Is(err, ErrHubUnusable) {
			t.Fatalf("err = %v, want ErrHubUnusable", err)
		}
		if len(j.all()) != 0 || len(requestsOn(w.relay)) != 0 {
			t.Fatal("something was written or published")
		}
	})
	t.Run("journal failure", func(t *testing.T) {
		w := newWATransfer(t, newTestHub(t, answerTransfer))
		j := newTestJournal()
		j.failNext = errors.New("disk full")
		if _, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d"); !errors.Is(err, ErrNotSent) {
			t.Fatalf("err = %v, want ErrNotSent", err)
		}
		if len(requestsOn(w.relay)) != 0 {
			t.Fatal("published after a failed write-ahead")
		}
	})
}

const testRequestID = "0123456789abcdef0123456789abcdef"

// The outcome model of a single call carrying a request_id.
func TestCashTransfer_OutcomeModel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decide   func(transport.Item) *transport.Result
		final    bool
		lastCode string
		reused   bool
	}{
		{"BAD_REQUEST is final", answerCode(nipcash.ErrCodeBadRequest), true, "", false},
		{"RATE_LIMITED is pending", answerCode(nipcash.ErrCodeRateLimited), false, nipcash.ErrCodeRateLimited, false},
		{"REQUEST_REUSED is pending, no LastCode", answerCode(nipcash.ErrCodeRequestReused), false, "", true},
		{"omission is pending", func(transport.Item) *transport.Result { return nil }, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hub := newTestHub(t, tc.decide)
			w := newWATransfer(t, hub)
			ctx, cancel := e2eContext(t)
			defer cancel()
			j := newTestJournal()
			out, sendErr := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d")
			if len(out) != 1 {
				t.Fatalf("outcomes %v, err %v", out, sendErr)
			}
			err := oneCall(out[0].ItemOutcome, sendErr, nipcash.MethodCashTransfer)
			var fe *FinalError
			var ie *IndeterminateError
			switch {
			case tc.final:
				if !errors.As(err, &fe) || out[0].NeedsLookup() {
					t.Fatalf("err = %v, NeedsLookup %v; want a FinalError and no lookup", err, out[0].NeedsLookup())
				}
			default:
				if !errors.As(err, &ie) || !out[0].NeedsLookup() {
					t.Fatalf("err = %v, NeedsLookup %v; want an IndeterminateError and a lookup", err, out[0].NeedsLookup())
				}
				if ie.Call.RequestID != out[0].RequestID || ie.Call.Deadline == 0 {
					t.Errorf("pending call %+v", ie.Call)
				}
				if ie.Call.LastCode != tc.lastCode || ie.Call.SawReused != tc.reused {
					t.Errorf("LastCode %q SawReused %v, want %q %v", ie.Call.LastCode, ie.Call.SawReused, tc.lastCode, tc.reused)
				}
			}
		})
	}
}

// T07-17 (S-CASH-34): a newer announcement with a smaller H is adopted, and the
// next deadline fits the new H.
func TestSession_AdoptsNewerSmallerH(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	w := newWATransfer(t, hub)
	ctx, cancel := e2eContext(t)
	defer cancel()

	core := hub.hub(t)
	core.Limits.MaxRequestAgeSeconds = 60
	ev := core.Announcement()
	ev.CreatedAt++ // newer than the one the session holds
	if err := ev.Sign(hub.hubPriv); err != nil {
		t.Fatal(err)
	}
	if ok, msg := w.relay.Publish(ev); !ok {
		t.Fatal(msg)
	}
	if err := w.s.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := w.s.MaxRequestAge(); got != 60 {
		t.Fatalf("H = %d, want 60", got)
	}
	j := newTestJournal()
	if _, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d"); err != nil {
		t.Fatalf("TransferMany: %v", err)
	}
	pc := j.all()[0]
	if pc.MaxRequestAge != 60 || pc.Deadline > time.Now().Unix()+30 {
		t.Errorf("call %+v: deadline beyond now + DeadlineWindow(60)", pc)
	}
}

// A newest announcement the client cannot adopt makes the Hub unusable; the
// older, valid one is never used in its place.
func TestSession_NewestRejectedIsUnusable(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	w := newWATransfer(t, hub)
	ctx, cancel := e2eContext(t)
	defer cancel()

	ev := hub.hub(t).Announcement()
	ev.CreatedAt++
	ev.Tags = append(ev.Tags, []string{"inbox", strings.Repeat("cd", 32)}) // two inbox tags
	if err := ev.Sign(hub.hubPriv); err != nil {
		t.Fatal(err)
	}
	if ok, msg := w.relay.Publish(ev); !ok {
		t.Fatal(msg)
	}
	if err := w.s.Refresh(ctx); !errors.Is(err, ErrHubUnusable) {
		t.Fatalf("Refresh err = %v, want ErrHubUnusable", err)
	}
	j := newTestJournal()
	if _, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d"); !errors.Is(err, ErrHubUnusable) {
		t.Fatalf("TransferMany err = %v, want ErrHubUnusable", err)
	}
	if len(j.all()) != 0 {
		t.Fatal("a call was written ahead to an unusable Hub")
	}
}

// Proof of work (NIP-CASH §Proof of Work): a request to a relay with a minimum
// is mined to it with expiration = not_after, and served.
func TestPow_MinedToTheRelayMinimum(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	relay := cashtest.NewRelay(t)
	relay.SetMinPow(8)
	hub.hub(t, relay)
	w := newWATransferOn(t, hub, relay)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	out, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d")
	if err != nil || !out[0].Succeeded() {
		t.Fatalf("TransferMany: %v %+v", err, out)
	}
	reqs := requestsOn(relay)
	if len(reqs) != 1 {
		t.Fatalf("%d requests accepted", len(reqs))
	}
	if d, _ := nip13.Difficulty(reqs[0].ID); d < 8 {
		t.Errorf("difficulty %d, want ≥ 8", d)
	}
	if exp, _ := expirationTag(reqs[0]); exp != j.all()[0].Deadline {
		t.Errorf("expiration %d, deadline %d", exp, j.all()[0].Deadline)
	}
}

// CASH-POW-03 (T11-43): a relay that raised its minimum refuses "pow: …"; the
// same request is re-mined and published again, and the Hub runs it once.
func TestPow_RemineOnRefusal(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	relay := cashtest.NewRelay(t)
	relay.SetMinPow(2)
	hub.hub(t, relay)
	w := newWATransferOn(t, hub, relay)
	ctx, cancel := e2eContext(t)
	defer cancel()
	if w.s.powMinimum(ctx) != 2 { // read and cached
		t.Fatal("minimum not read")
	}
	relay.SetMinPow(10)
	out, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, newTestJournal(), "d")
	if err != nil || !out[0].Succeeded() {
		t.Fatalf("TransferMany: %v %+v", err, out)
	}
	reqs := requestsOn(relay)
	if len(reqs) != 1 {
		t.Fatalf("%d requests accepted", len(reqs))
	}
	if d, _ := nip13.Difficulty(reqs[0].ID); d < 10 {
		t.Errorf("difficulty %d, want ≥ 10", d)
	}
	if n := len(hub.envelopes()); n != 1 {
		t.Errorf("hub ran %d envelopes", n)
	}
}

// T11-46 / E-POW-03: a minimum above the budget is ErrPowTooHard, which is
// ErrNotSent: nothing published, the written-ahead call closed as not sent.
func TestPow_TooHardForTheBudget(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	relay := cashtest.NewRelay(t)
	relay.SetMinPow(30)
	hub.hub(t, relay)
	w := newWATransferOn(t, hub, relay, WithPowBudget(20, 0))
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()
	_, err := w.s.TransferMany(ctx, []BatchTransfer{w.item}, j, "d")
	if !errors.Is(err, ErrPowTooHard) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("err = %v, want ErrPowTooHard wrapping ErrNotSent", err)
	}
	if len(requestsOn(relay)) != 0 {
		t.Fatal("published")
	}
	if len(j.all()) != 1 {
		t.Fatal("the call was not written ahead before mining")
	}

	// Mining not done within the budget's duration is ErrPowTooHard too.
	relay.SetMinPow(40)
	w2 := newWATransferOn(t, hub, relay, WithPowBudget(0, 50*time.Millisecond))
	if _, err := w2.s.TransferMany(ctx, []BatchTransfer{w2.item}, newTestJournal(), "d"); !errors.Is(err, ErrPowTooHard) {
		t.Fatalf("slow mining err = %v, want ErrPowTooHard", err)
	}
}

func expirationTag(ev *nip01.Event) (int64, bool) {
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "expiration" {
			var n int64
			for _, c := range tag[1] {
				n = n*10 + int64(c-'0')
			}
			return n, true
		}
	}
	return 0, false
}
