package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

// ActionKind is what Recover tells the caller to do with a pending call.
type ActionKind int

const (
	// ActionClose: the call is decided; Result holds its rebuilt response.
	ActionClose ActionKind = iota
	// ActionWait: ask again at Until (0: on the caller's next refresh).
	ActionWait
	// ActionShow: surface the call to its user; Reason says why.
	ActionShow
	// ActionReplace: re-place it automatically under the derived id.
	ActionReplace
	// ActionConfirmReplace: re-place it only with the user's confirmation.
	ActionConfirmReplace
	// ActionCloseFailed: close it; it never committed.
	ActionCloseFailed
	// ActionCloseRefused: close it as refused with Reason (its LastCode); the
	// user re-runs the operation as a new call.
	ActionCloseRefused
)

// Action is Recover's answer.
type Action struct {
	Kind   ActionKind
	Until  int64
	Reason string
	Result json.RawMessage
}

// LookupOutcome is a lookup's answer as Recover needs it. NotServed is an
// omitted or unanswered lookup; Malformed an answer that did not parse; Code an
// item-level refusal, never folded into NotServed.
type LookupOutcome struct {
	Status     nipcash.LookupStatus
	RetryAfter int64
	Result     json.RawMessage
	NotServed  bool
	Malformed  bool
	Code       string
}

// MaxReplaceAttempts bounds the re-placements of one call.
const MaxReplaceAttempts = 3

// Recover decides what to do with a pending call from its lookup (NIP-CASH
// §Looking Up a Call, Finality): done closes it (an order's done waits, its
// caller closes on the order's state); pending waits; unknown is the owner's to
// re-place (a mint or order only with confirmation; a call refused with a code
// is closed as refused instead), a foreign device's to show; expired is shown;
// an unanswered lookup waits, and is shown past deadline + H; a malformed one is
// shown.
func Recover(ctx context.Context, pc nipcash.PendingCall, lookup func(context.Context, nipcash.PendingCall) (LookupOutcome, error), localDevice string, now time.Time) (Action, error) {
	lo, err := lookup(ctx, pc)
	if err != nil {
		return Action{}, err
	}
	unanswered := func() Action {
		if now.Unix() > pc.Deadline+pc.MaxRequestAge {
			return Action{Kind: ActionShow, Reason: "lookup_unanswered"}
		}
		return Action{Kind: ActionWait}
	}
	switch {
	case lo.Malformed:
		return Action{Kind: ActionShow, Reason: "lookup_malformed"}, nil
	case lo.NotServed, lo.Code == nipcash.ErrCodeRequestReused:
		return unanswered(), nil
	case lo.Code != "":
		return Action{Kind: ActionShow, Reason: "lookup_refused:" + lo.Code}, nil
	}
	isOrder := pc.Method == methodCashOrder
	if isOrder && pc.PayBy != 0 && (lo.Status == nipcash.LookupUnknown || lo.Status == nipcash.LookupExpired) {
		// The held reply proves the order was placed: never re-placed. Before
		// pay_by it is shown; after it the caller ends the order unpaid.
		if now.Unix() < pc.PayBy {
			return Action{Kind: ActionShow, Reason: "lookup_unknown"}, nil
		}
		return Action{Kind: ActionWait, Reason: string(lo.Status)}, nil
	}
	switch lo.Status {
	case nipcash.LookupDone:
		if isOrder || pc.Method == methodCashWithdraw {
			return Action{Kind: ActionWait, Result: lo.Result}, nil
		}
		return Action{Kind: ActionClose, Result: lo.Result}, nil
	case nipcash.LookupPending:
		return Action{Kind: ActionWait, Until: lo.RetryAfter}, nil
	case nipcash.LookupExpired:
		return Action{Kind: ActionShow, Reason: "lookup_expired"}, nil
	case nipcash.LookupUnknown:
		switch {
		case pc.Device != localDevice:
			return Action{Kind: ActionShow, Reason: "foreign_device"}, nil
		case pc.LastCode != "":
			return Action{Kind: ActionCloseRefused, Reason: pc.LastCode}, nil
		case pc.Attempt >= MaxReplaceAttempts:
			return Action{Kind: ActionShow, Reason: "replace_cap"}, nil
		case pc.Method == nipcash.MethodMintCash || isOrder || (pc.Method == methodCashWithdraw && pc.SawReused):
			return Action{Kind: ActionConfirmReplace}, nil
		default:
			return Action{Kind: ActionReplace}, nil
		}
	}
	return Action{Kind: ActionShow, Reason: "lookup_malformed"}, nil
}

// ReplaceOptions tunes Replace.
type ReplaceOptions struct {
	// Confirmed is the user's explicit confirmation, required for a mint or order.
	Confirmed bool
	// DerivedEntryExists reports a written-ahead record of the derived id the
	// caller keeps elsewhere.
	DerivedEntryExists func(context.Context, string) (bool, error)
	// MaxAttempts defaults to MaxReplaceAttempts.
	MaxAttempts int
}

// Replace re-places a call after an unknown lookup: under its derived id, never
// a fresh one, and never twice (a derived id already placed or written ahead
// closes the call instead). It writes the derived call ahead, then sends it
// through send, which builds fresh proofs and a new deadline.
func Replace(ctx context.Context, pc nipcash.PendingCall, j Journal, o ReplaceOptions, send func(context.Context, nipcash.PendingCall) error) (Action, error) {
	if j == nil {
		return Action{}, ErrNoJournal
	}
	if (pc.Method == nipcash.MethodMintCash || pc.Method == methodCashOrder) && !o.Confirmed {
		return Action{}, ErrReplaceNeedsConfirmation
	}
	max := o.MaxAttempts
	if max == 0 {
		max = MaxReplaceAttempts
	}
	if pc.Attempt >= max {
		return Action{Kind: ActionShow, Reason: "replace_cap"}, nil
	}
	id, err := nipcash.DerivedRequestID(pc.RequestID)
	if err != nil {
		return Action{}, err
	}
	placed, err := j.DerivedPlaced(ctx, id)
	if err != nil {
		return Action{}, err
	}
	if !placed && o.DerivedEntryExists != nil {
		if placed, err = o.DerivedEntryExists(ctx, id); err != nil {
			return Action{}, err
		}
	}
	if placed {
		return Action{Kind: ActionClose, Reason: "derived_already_placed"}, nil
	}
	next := pc
	next.RequestID, next.DerivedFrom, next.Attempt, next.LastCode, next.SawReused = id, pc.RequestID, pc.Attempt+1, "", false
	if pc.Method == methodCashOrder {
		notify, err := nipcash.NewRequestID()
		if err != nil {
			return Action{}, err
		}
		next.Notify = notify
	}
	h := max64(pc.MaxRequestAge, nipcash.MinMaxRequestAge)
	next.Deadline = time.Now().Unix() + nipcash.DeadlineWindow(h)
	if err := j.RecordDerived(ctx, id, next.Deadline+h); err != nil {
		return Action{}, fmt.Errorf("nipcash/client: record derived id: %w", err)
	}
	// Written ahead before sending; the send path writes it again with the
	// exact deadline it is packed under.
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{next}); err != nil {
		return Action{}, fmt.Errorf("%w: write ahead: %v", ErrNotSent, err)
	}
	if err := send(ctx, next); err != nil {
		return Action{}, err
	}
	return Action{Kind: ActionWait}, nil
}

// The methods nipcash/client does not send itself but recovers like its own.
const (
	methodCashOrder    = "cash_order"
	methodCashWithdraw = "cash_withdraw"
)

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
