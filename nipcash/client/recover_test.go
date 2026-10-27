package client

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

func answered(lo LookupOutcome) func(context.Context, nipcash.PendingCall) (LookupOutcome, error) {
	return func(context.Context, nipcash.PendingCall) (LookupOutcome, error) { return lo, nil }
}

// T11-10, T11-16, T11-41, T11-45, T11-59, E-LK-04, E-LK-06, E-LK-07.
func TestRecover_Table(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	base := nipcash.PendingCall{RequestID: testRequestID, Method: nipcash.MethodCashTransfer, Device: "a",
		Deadline: now.Unix() - 100, MaxRequestAge: 300}
	with := func(f func(*nipcash.PendingCall)) nipcash.PendingCall { pc := base; f(&pc); return pc }
	done := json.RawMessage(`{"amount_millis":1}`)

	for _, tc := range []struct {
		name   string
		pc     nipcash.PendingCall
		lo     LookupOutcome
		device string
		want   Action
	}{
		{"done closes", base, LookupOutcome{Status: nipcash.LookupDone, Result: done}, "a", Action{Kind: ActionClose, Result: done}},
		{"pending waits", base, LookupOutcome{Status: nipcash.LookupPending, RetryAfter: 42}, "a", Action{Kind: ActionWait, Until: 42}},
		{"unknown, owner transfer, replaces", base, LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionReplace}},
		{"unknown, other device, shows", base, LookupOutcome{Status: nipcash.LookupUnknown}, "b", Action{Kind: ActionShow, Reason: "foreign_device"}},
		{"unknown, owner mint, confirms", with(func(p *nipcash.PendingCall) { p.Method = nipcash.MethodMintCash }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionConfirmReplace}},
		{"unknown after a coded refusal closes refused", with(func(p *nipcash.PendingCall) { p.LastCode = "RATE_LIMITED" }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionCloseRefused, Reason: "RATE_LIMITED"}},
		{"unknown at the cap shows", with(func(p *nipcash.PendingCall) { p.Attempt = 3 }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionShow, Reason: "replace_cap"}},
		{"expired shows", base, LookupOutcome{Status: nipcash.LookupExpired}, "a", Action{Kind: ActionShow, Reason: "lookup_expired"}},
		{"unserved waits", base, LookupOutcome{NotServed: true}, "a", Action{Kind: ActionWait}},
		{"unserved past deadline + H shows", with(func(p *nipcash.PendingCall) { p.Deadline = now.Unix() - 400 }),
			LookupOutcome{NotServed: true}, "a", Action{Kind: ActionShow, Reason: "lookup_unanswered"}},
		{"REQUEST_REUSED lookup reads as unanswered", base, LookupOutcome{Code: nipcash.ErrCodeRequestReused}, "a", Action{Kind: ActionWait}},
		{"malformed shows", base, LookupOutcome{Malformed: true}, "a", Action{Kind: ActionShow, Reason: "lookup_malformed"}},
		{"order done waits for the order", with(func(p *nipcash.PendingCall) { p.Method = nipcash.MethodCashOrder }),
			LookupOutcome{Status: nipcash.LookupDone, Result: done}, "a", Action{Kind: ActionWait, Result: done}},
		{"held order unknown before pay_by shows", with(func(p *nipcash.PendingCall) { p.Method = nipcash.MethodCashOrder; p.PayBy = now.Unix() + 10 }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionShow, Reason: "lookup_unknown"}},
		{"held order unknown after pay_by waits", with(func(p *nipcash.PendingCall) { p.Method = nipcash.MethodCashOrder; p.PayBy = now.Unix() - 10 }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionWait, Reason: "unknown"}},
		{"withdraw that saw REQUEST_REUSED confirms", with(func(p *nipcash.PendingCall) {
			p.Method = nipcash.MethodCashWithdraw
			p.SawReused = true
			p.Quote = "{}"
		}),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionConfirmReplace}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Recover(context.Background(), tc.pc, answered(tc.lo), tc.device, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tc.want.Kind || got.Reason != tc.want.Reason || got.Until != tc.want.Until || string(got.Result) != string(tc.want.Result) {
				t.Fatalf("Recover = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// T11-11, T11-12, T11-45.
func TestReplace(t *testing.T) {
	ctx := context.Background()
	pc := nipcash.PendingCall{RequestID: testRequestID, Method: nipcash.MethodCashTransfer, Device: "a", MaxRequestAge: 300, Amount: 5}
	derived, err := nipcash.DerivedRequestID(testRequestID)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sends under the derived id, recording its parent", func(t *testing.T) {
		j := newTestJournal()
		var sent nipcash.PendingCall
		act, err := Replace(ctx, pc, j, ReplaceOptions{}, func(_ context.Context, next nipcash.PendingCall) error {
			if _, ok := j.call(next.RequestID); ok {
				t.Error("Replace wrote the derived call itself; the send path writes it")
			}
			sent = next
			return nil
		})
		if j.parents[derived] != testRequestID {
			t.Errorf("parent recorded %q, want %q", j.parents[derived], testRequestID)
		}
		if err != nil || act.Kind != ActionWait {
			t.Fatalf("Replace = %+v, %v", act, err)
		}
		if sent.RequestID != derived || sent.DerivedFrom != testRequestID || sent.Attempt != 1 || sent.Amount != 5 {
			t.Errorf("sent %+v", sent)
		}
		if placed, _ := j.DerivedPlaced(ctx, derived); !placed {
			t.Error("derived id not recorded")
		}
		// A second Replace of the same call closes it without sending.
		act, err = Replace(ctx, pc, j, ReplaceOptions{}, func(context.Context, nipcash.PendingCall) error {
			t.Error("sent twice")
			return nil
		})
		if err != nil || act.Kind != ActionClose {
			t.Fatalf("second Replace = %+v, %v", act, err)
		}
	})
	t.Run("a derived entry kept elsewhere closes", func(t *testing.T) {
		act, err := Replace(ctx, pc, newTestJournal(), ReplaceOptions{DerivedEntryExists: func(context.Context, string) (bool, error) { return true, nil }},
			func(context.Context, nipcash.PendingCall) error { t.Error("sent"); return nil })
		if err != nil || act.Kind != ActionClose {
			t.Fatalf("Replace = %+v, %v", act, err)
		}
	})
	t.Run("a mint needs confirmation", func(t *testing.T) {
		mint := pc
		mint.Method = nipcash.MethodMintCash
		if _, err := Replace(ctx, mint, newTestJournal(), ReplaceOptions{}, nil); !errors.Is(err, ErrReplaceNeedsConfirmation) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("an order gets a fresh notify", func(t *testing.T) {
		order := pc
		order.Method, order.Notify = nipcash.MethodCashOrder, testRequestID
		var sent nipcash.PendingCall
		if _, err := Replace(ctx, order, newTestJournal(), ReplaceOptions{Confirmed: true}, func(_ context.Context, n nipcash.PendingCall) error {
			sent = n
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if sent.Notify == "" || sent.Notify == order.Notify {
			t.Errorf("notify %q", sent.Notify)
		}
	})
	t.Run("at the cap shows", func(t *testing.T) {
		capped := pc
		capped.Attempt = 3
		act, err := Replace(ctx, capped, newTestJournal(), ReplaceOptions{}, nil)
		if err != nil || act.Kind != ActionShow || act.Reason != "replace_cap" {
			t.Fatalf("Replace = %+v, %v", act, err)
		}
	})
	t.Run("no journal", func(t *testing.T) {
		if _, err := Replace(ctx, pc, nil, ReplaceOptions{}, nil); !errors.Is(err, ErrNoJournal) {
			t.Fatalf("err = %v", err)
		}
	})
}

func nowForTest() time.Time { return time.Unix(1_900_000_000, 0) }

// T11-12.
// A re-placement through the SDK send path is written ahead exactly once, with
// its exact deadline, DerivedFrom and Attempt; a Journal without the parent
// extension gets RecordDerived.
func TestReplace_WrittenOnceThroughTheSendPath(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	w := newWATransfer(t, hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	tj := newTestJournal()
	j := plainJournal{tj}

	first := w.item
	first.Params.RequestID = testRequestID
	out, err := w.s.TransferMany(ctx, []BatchTransfer{first}, j, "d")
	if err != nil || len(out) != 1 {
		t.Fatalf("TransferMany: %v", err)
	}
	pc, _ := tj.call(testRequestID)
	act, err := Replace(ctx, pc, j, ReplaceOptions{}, func(ctx context.Context, next nipcash.PendingCall) error {
		again := w.item
		again.Params.RequestID = next.RequestID
		_, err := w.s.TransferMany(ctx, []BatchTransfer{again}, j, "d")
		return err
	})
	if err != nil || act.Kind != ActionWait {
		t.Fatalf("Replace = %+v, %v", act, err)
	}
	derived, _ := nipcash.DerivedRequestID(testRequestID)
	if n := tj.writes[derived]; n != 1 {
		t.Fatalf("derived call written %d times, want once", n)
	}
	got, _ := tj.call(derived)
	envs := hub.envelopes()
	if got.DerivedFrom != testRequestID || got.Attempt != 1 || got.Deadline != envs[len(envs)-1].NotAfter {
		t.Errorf("derived call %+v (envelope not_after %d)", got, envs[len(envs)-1].NotAfter)
	}
	if _, ok := tj.derived[derived]; !ok || tj.parents[derived] != "" {
		t.Errorf("RecordDerived not used for a plain journal: %v %q", tj.derived, tj.parents[derived])
	}
}

// M1: a re-placement whose send path packs a fresh id, or the derived id with
// another amount, is refused before anything is written ahead or sent.
func TestReplace_RefusesAFreshIDOrAChangedCall(t *testing.T) {
	hub := newTestHub(t, answerTransfer)
	w := newWATransfer(t, hub)
	ctx, cancel := e2eContext(t)
	defer cancel()
	j := newTestJournal()

	first := w.item
	first.Params.RequestID = testRequestID
	if _, err := w.s.TransferMany(ctx, []BatchTransfer{first}, j, "d"); err != nil {
		t.Fatalf("TransferMany: %v", err)
	}
	pc, _ := j.call(testRequestID)
	sentBefore := len(hub.envelopes())
	for name, edit := range map[string]func(*BatchTransfer, nipcash.PendingCall){
		"fresh id": func(b *BatchTransfer, _ nipcash.PendingCall) { b.Params.RequestID = "" },
		"another amount": func(b *BatchTransfer, n nipcash.PendingCall) {
			b.Params.RequestID = n.RequestID
			b.Params.CurrentAmount++
		},
	} {
		_, err := Replace(ctx, pc, newTestJournal(), ReplaceOptions{}, func(ctx context.Context, next nipcash.PendingCall) error {
			again := w.item
			edit(&again, next)
			_, err := w.s.TransferMany(ctx, []BatchTransfer{again}, j, "d")
			return err
		})
		if !errors.Is(err, errReplacementMismatch) {
			t.Errorf("%s: err = %v, want errReplacementMismatch", name, err)
		}
	}
	if n := len(hub.envelopes()); n != sentBefore {
		t.Fatalf("%d envelopes sent by refused re-placements", n-sentBefore)
	}
	if len(j.writes) != 1 {
		t.Fatalf("journal holds %d calls, want only the original", len(j.writes))
	}
}

// L4: a re-placement whose send fails before the derived call is written ahead
// records nothing, so a later Replace still places it instead of closing it as
// derived_already_placed.
func TestReplace_FailureBeforeWriteAheadRecordsNothing(t *testing.T) {
	ctx := context.Background()
	pc := nipcash.PendingCall{RequestID: testRequestID, Method: nipcash.MethodCashTransfer, Device: "a", MaxRequestAge: 300, Amount: 5}
	j := newTestJournal()
	if _, err := Replace(ctx, pc, j, ReplaceOptions{}, func(context.Context, nipcash.PendingCall) error {
		return ErrHubUnusable
	}); !errors.Is(err, ErrHubUnusable) {
		t.Fatalf("err = %v", err)
	}
	derived, _ := nipcash.DerivedRequestID(testRequestID)
	if placed, _ := j.DerivedPlaced(ctx, derived); placed {
		t.Fatal("the derived id was recorded although nothing was written ahead")
	}
	sent := false
	act, err := Replace(ctx, pc, j, ReplaceOptions{}, func(context.Context, nipcash.PendingCall) error { sent = true; return nil })
	if err != nil || act.Kind != ActionWait || !sent {
		t.Fatalf("second Replace = %+v, %v, sent %v", act, err, sent)
	}
}
