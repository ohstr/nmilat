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
		{"order done waits for the order", with(func(p *nipcash.PendingCall) { p.Method = methodCashOrder }),
			LookupOutcome{Status: nipcash.LookupDone, Result: done}, "a", Action{Kind: ActionWait, Result: done}},
		{"held order unknown before pay_by shows", with(func(p *nipcash.PendingCall) { p.Method = methodCashOrder; p.PayBy = now.Unix() + 10 }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionShow, Reason: "lookup_unknown"}},
		{"held order unknown after pay_by waits", with(func(p *nipcash.PendingCall) { p.Method = methodCashOrder; p.PayBy = now.Unix() - 10 }),
			LookupOutcome{Status: nipcash.LookupUnknown}, "a", Action{Kind: ActionWait, Reason: "unknown"}},
		{"withdraw that saw REQUEST_REUSED confirms", with(func(p *nipcash.PendingCall) { p.Method = methodCashWithdraw; p.SawReused = true }),
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

func TestReplace(t *testing.T) {
	ctx := context.Background()
	pc := nipcash.PendingCall{RequestID: testRequestID, Method: nipcash.MethodCashTransfer, Device: "a", MaxRequestAge: 300, Amount: 5}
	derived, err := nipcash.DerivedRequestID(testRequestID)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sends under the derived id, written ahead first", func(t *testing.T) {
		j := newTestJournal()
		var sent nipcash.PendingCall
		act, err := Replace(ctx, pc, j, ReplaceOptions{}, func(_ context.Context, next nipcash.PendingCall) error {
			if _, ok := j.call(next.RequestID); !ok {
				t.Error("sent before the derived call was written ahead")
			}
			sent = next
			return nil
		})
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
		order.Method, order.Notify = methodCashOrder, testRequestID
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
