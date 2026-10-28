package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// T11-27 (S-CASH-58, S-CASH-197): a timeout or an omission is Indeterminate; a
// tombstone is Spent with its reason; NOT_FOUND is NoSlice, never Spent and
// never Indeterminate.
func TestT11_27_ClassifyNoSlice(t *testing.T) {
	until := int64(1758800000)
	tomb := &nipcash.CashStatusResult{Tombstone: &nipcash.Tombstone{Status: nipcash.StatusSpent, Reason: nipcash.ReasonRedeemed, RetainedUntil: &until}}
	for name, tc := range map[string]struct {
		res  *nipcash.CashStatusResult
		err  error
		want BillState
	}{
		"timeout":           {err: context.DeadlineExceeded, want: BillIndeterminate},
		"omission":          {err: &NotServedError{Method: nipcash.MethodCashStatus}, want: BillIndeterminate},
		"tombstone":         {res: tomb, want: BillSpent},
		"NOT_FOUND":         {err: &relayclient.WalletError{Method: nipcash.MethodCashStatus, Code: nipcash.ErrCodeNotFound}, want: BillNoSlice},
		"NOT_FOUND wrapped": {err: fmt.Errorf("read: %w", &relayclient.WalletError{Code: nipcash.ErrCodeNotFound}), want: BillNoSlice},
		"another code":      {err: &relayclient.WalletError{Code: nipcash.ErrCodeUnauthorized}, want: BillIndeterminate},
	} {
		state, res, err := classify(tc.res, tc.err)
		if state != tc.want {
			t.Errorf("%s: state = %v, want %v", name, state, tc.want)
		}
		if state == BillSpent && (res == nil || res.Tombstone.Reason != nipcash.ReasonRedeemed) {
			t.Errorf("%s: the tombstone's reason is not passed through", name)
		}
		if state == BillNoSlice && err == nil {
			t.Errorf("%s: NoSlice must keep the refusal as its error", name)
		}
	}
	if BillNoSlice.String() != "no slice" {
		t.Errorf("String = %q", BillNoSlice.String())
	}
}

// stateClient is a bill client whose Hub answers cash_status with answer.
func stateClient(t *testing.T, answer func(me string, item transport.Item) *transport.Result) (*Client, nipcash.Credential) {
	t.Helper()
	priv, me := sessionKeypair(t)
	hub := newTestHub(t, func(item transport.Item) *transport.Result { return answer(me, item) })
	s, _ := openTestSession(t, hub)
	_, target := sessionKeypair(t)
	return &Client{walletPubkey: target, connSecret: connSecretFor(target), session: s}, nipcash.BySigning(priv)
}

func rowJSON(pub string) string {
	return `{"identity_type":"pubkey","identity_value":"` + pub + `","amount_millis":5000,"claimed":false,"redeem_fee_millis":0,"net_redeemable_millis":5000,"min_transfer_millis":0}`
}

// T11-27 end to end: the Hub's NOT_FOUND reaches State as NoSlice.
func TestT11_27_StateNoSlice(t *testing.T) {
	c, cred := stateClient(t, func(_ string, item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, Error: &transport.ResultError{Code: nipcash.ErrCodeNotFound, Message: "no slice"}}
	})
	ctx, cancel := e2eContext(t)
	defer cancel()
	state, _, err := c.State(ctx, cred)
	if state != BillNoSlice || err == nil {
		t.Fatalf("State = %v, %v; want BillNoSlice with the refusal", state, err)
	}
}

// T11-57: a scope-mine answer that is not exactly the caller's row is
// Indeterminate with nipcash.ErrMineWidened, whose local reason is
// status_widened (retryable); the caller's own single row is Available.
func TestT11_57_StatusWidened(t *testing.T) {
	_, other := sessionKeypair(t)
	for name, tc := range map[string]struct {
		rows    func(me string) string
		want    BillState
		widened bool
	}{
		"own row":       {rows: func(me string) string { return rowJSON(me) }, want: BillAvailable},
		"two rows":      {rows: func(me string) string { return rowJSON(me) + "," + rowJSON(other) }, want: BillIndeterminate, widened: true},
		"another's row": {rows: func(string) string { return rowJSON(other) }, want: BillIndeterminate, widened: true},
		"no row":        {rows: func(string) string { return "" }, want: BillIndeterminate, widened: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, cred := stateClient(t, func(me string, item transport.Item) *transport.Result {
				return &transport.Result{ID: item.ID, ResultType: item.Method, Result: json.RawMessage(`{"recipients":[` + tc.rows(me) + `]}`)}
			})
			ctx, cancel := e2eContext(t)
			defer cancel()
			state, _, err := c.State(ctx, cred)
			if state != tc.want || errors.Is(err, nipcash.ErrMineWidened) != tc.widened {
				t.Fatalf("State = %v, %v", state, err)
			}
			if tc.widened && (LocalReason(err) != ReasonStatusWidened || !LocalRetryable(err)) {
				t.Fatalf("LocalReason = %q, retryable %v", LocalReason(err), LocalRetryable(err))
			}
		})
	}
}

func TestLocalReason(t *testing.T) {
	for err, want := range map[error]string{
		nil: "",
		fmt.Errorf("x: %w", nipcash.ErrMineWidened): ReasonStatusWidened,
		ErrHubUnusable: ReasonHubUnusable,
		fmt.Errorf("%w: %w", ErrNotSent, ErrDeadlineTooClose): ReasonNotSent,
		ErrPowTooHard:                  ReasonNotSent,
		ErrMixedOrdered:                ReasonMixedOrdered,
		nipcash.ErrChainMismatch:       ReasonConnectionMismatch,
		nipcash.ErrHubIdentityMismatch: ReasonConnectionMismatch,
		errors.New("hub said no"):      "",
	} {
		if got := LocalReason(err); got != want {
			t.Errorf("LocalReason(%v) = %q, want %q", err, got, want)
		}
	}
	if LocalRetryable(ErrHubUnusable) {
		t.Error("hub_unusable is not retryable")
	}
}
