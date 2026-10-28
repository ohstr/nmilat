package nipCP

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
)

// PendingEntry is the pending entry written ahead of pc (NIP-CP §Kind 9525):
// w = request_id, rev 1, state pending checked now, request_id, deadline as
// sent, target, device, chain, amount (what the call sends) and the secrets the
// call generated; for a cash_order also its order_key (a pubkey or
// connection_key recipient's buyer key; a cash recipient's buyer key is derived
// from its secret) and notify; for a cash_withdraw (target the bill, amount the
// slice's amount_millis) its notify, address, quote, receipt once received and,
// for a cash-mode slice, the secret behind its remint_commitment (role
// SecretRoleRemint). pc must carry Chain and Device. Other methods are
// ErrMethod.
func PendingEntry(pc nipcash.PendingCall) (Entry, error) {
	switch pc.Method {
	case nipcash.MethodCashTransfer, nipcash.MethodCashConsolidate, nipcash.MethodMintCash, nipcash.MethodCashOrder,
		nipcash.MethodCashWithdraw:
	default:
		return Entry{}, fmt.Errorf("%w: %q", ErrMethod, pc.Method)
	}
	e := Entry{
		W: pc.RequestID, Rev: 1, State: StatePending, CheckedAt: now(),
		RequestID: pc.RequestID, Deadline: pc.Deadline, Target: pc.Target, Device: pc.Device,
		Chain: pc.Chain, Amount: pc.Amount,
		Secrets: append([]nipcash.PendingSecret(nil), pc.Secrets...),
	}
	if pc.Method == nipcash.MethodCashOrder {
		e.OrderKey, e.Notify = pc.BuyerKey, pc.Notify
		if e.Notify == "" || (e.OrderKey == "" && len(e.Secrets) == 0) {
			return Entry{}, bad("a cash_order entry keeps its notify, and its secret or order_key")
		}
	}
	if pc.Method == nipcash.MethodCashWithdraw {
		e.Notify, e.Address, e.Quote, e.Receipt = pc.Notify, pc.Address, pc.Quote, pc.Receipt
		if e.Notify == "" || e.Address == "" || e.Quote == "" {
			return Entry{}, bad("a cash_withdraw entry keeps its notify, address and quote")
		}
		if len(e.Secrets) > 1 || (len(e.Secrets) == 1 && e.Secrets[0].Role != SecretRoleRemint) {
			return Entry{}, bad("a cash_withdraw entry's only secret is its remint secret")
		}
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Close is pending at its next rev in state done, checked at at (NIP-CP
// §Writing, Close). Publish it, then delete the old wrap; never close by
// deletion alone.
func Close(pending Entry, at int64) (Entry, error) {
	if !pending.IsCall() || pending.State != StatePending {
		return Entry{}, ErrNotPending
	}
	return WithState(pending, StateDone, at), nil
}

// CanRemoveSources reports whether a call's source entries, and their secrets,
// may be removed: only once its entry is done.
func CanRemoveSources(pending Entry) bool {
	return pending.IsCall() && pending.State == StateDone
}

// NewBill is one bill a reply, or a lookup's done result, made, as the caller
// read it from the method's result. Token holds the token, or the tombstone a
// lookup put in its place. Identity is the identity the call bound it to
// (Type cash for a cash-mode bill, whose Commitment names the secret). InPlace
// marks a bill transferred in place: it keeps the w of the source it was.
type NewBill struct {
	W          string
	Token      nipcash.TokenOrTombstone
	Amount     uint64
	Identity   EntryIdentity
	Commitment string
	ExpiresAt  int64
	InPlace    bool
}

// Outcome is a call's answer as ApplyResult needs it. Err is the call's error
// as nipcash/client returns it: nil for a result (a reply or a lookup done),
// *client.FinalError for BAD_REQUEST, *nipcash.BillGone for a tombstone in
// place of the result; any other error leaves the call pending. GoneW names the
// source a BillGone is about (default: the entry's target). Own lists the
// identities the user holds; HandOn the cash secrets the wallet hands on to
// someone else (their bills are not kept). At is the check time written.
type Outcome struct {
	Err    error
	Bills  []NewBill
	GoneW  string
	Own    []EntryIdentity
	HandOn []string
	At     int64
}

// ApplyResult turns a call's outcome into the pocket's writes (NIP-CP
// §Writing): writes are the new entries, written and read back first;
// closeBatch is then written in one batch: the pending entry done and every
// source not rewritten in place spent.
//
//   - BAD_REQUEST: the pending entry done, sources unchanged.
//   - a tombstone in place of the result: the pending entry done, and the named
//     source in the state MapStatus gives.
//   - any other error: ErrLookup, nothing written.
//   - a result: an entry for each bill the user keeps (one made for an identity
//     in Own, or a cash bill whose secret the pending entry holds and the wallet
//     does not hand on, carrying that secret) and none for another's; a bill
//     transferred in place to the user rewrites its source's w at the next rev;
//     a tombstone in place of a bill's token gives an entry without cash, in
//     its mapped final state.
func ApplyResult(pending Entry, sources []Entry, r Outcome) (writes []Entry, closeBatch []Entry, err error) {
	if !pending.IsCall() || pending.State != StatePending {
		return nil, nil, ErrNotPending
	}
	at := r.At
	if at == 0 {
		at = now()
	}
	done := WithState(pending, StateDone, at)
	var final *client.FinalError
	var gone *nipcash.BillGone
	switch {
	case errors.As(r.Err, &final):
		return nil, []Entry{done}, nil
	case errors.As(r.Err, &gone):
		w := r.GoneW
		if w == "" {
			w = pending.Target
		}
		closeBatch = []Entry{done}
		for _, s := range sources {
			if s.W == w {
				st, _ := MapStatus(StatusInput{Tombstone: &gone.Tombstone})
				closeBatch = append(closeBatch, WithState(s, st, at))
			}
		}
		return nil, closeBatch, nil
	case r.Err != nil:
		return nil, nil, fmt.Errorf("%w: %v", ErrLookup, r.Err)
	}
	rewritten := map[string]bool{}
	for _, b := range r.Bills {
		e, keep, err := billEntry(pending, sources, r, b, at)
		if err != nil {
			return nil, nil, err
		}
		if !keep {
			continue
		}
		if b.InPlace {
			rewritten[b.W] = true
		}
		writes = append(writes, e)
	}
	closeBatch = []Entry{done}
	for _, s := range sources {
		if !rewritten[s.W] {
			closeBatch = append(closeBatch, WithState(s, StateSpent, at))
		}
	}
	return writes, closeBatch, nil
}

// billEntry is the entry for one new bill, and whether the user keeps it.
func billEntry(pending Entry, sources []Entry, r Outcome, b NewBill, at int64) (Entry, bool, error) {
	var secrets []nipcash.PendingSecret
	keep := false
	if b.Identity.Type == IdentityCash {
		for _, s := range pending.Secrets {
			c, err := nipcash.CashCommitment(s.Secret)
			if err != nil || !nipcash.CommitmentsEqual(c, b.Commitment) {
				continue
			}
			handed := false
			for _, h := range r.HandOn {
				handed = handed || h == s.Secret
			}
			if !handed || s.Role == SecretRoleRemainder {
				keep = true
				secrets = []nipcash.PendingSecret{{Secret: s.Secret}}
			}
		}
	} else {
		for _, id := range r.Own {
			keep = keep || id == b.Identity
		}
	}
	if !keep {
		return Entry{}, false, nil
	}
	e := Entry{W: b.W, Rev: 1, Amount: b.Amount, Chain: pending.Chain, Identity: b.Identity, CheckedAt: at, Secrets: secrets}
	if b.Identity.Type == IdentityCash {
		e.Identity = EntryIdentity{Type: IdentityCash}
	}
	if b.InPlace {
		for _, s := range sources {
			if s.W == b.W {
				n := rewrite(s, at)
				n.Identity, n.Secrets = e.Identity, secrets
				e = n
			}
		}
		if e.Rev == 1 {
			return Entry{}, false, bad("bill %s is in place but no source has its w", b.W)
		}
	}
	if b.Token.Tombstone != nil {
		e.Cash, e.ExpiresAt = "", nil
		e.State, _ = MapStatus(StatusInput{Tombstone: b.Token.Tombstone})
	} else {
		e.Cash, e.State = b.Token.Token, StateLive
		if b.Amount != 0 {
			e.Amount = b.Amount
		}
		e.ExpiresAt = nil
		if b.ExpiresAt > 0 {
			x := b.ExpiresAt
			e.ExpiresAt = &x
		}
	}
	if err := e.Validate(); err != nil {
		return Entry{}, false, err
	}
	return e, true, nil
}

// PocketActionKind is what ApplyLookup tells the wallet to do with an entry.
type PocketActionKind int

const (
	// PocketWait: leave the entry pending and ask again (at Until when set). An
	// order's or withdrawal's done answer waits too, with Result set: apply it
	// (ApplyOrder, or ApplyWithdraw with the parsed payout) and close on the
	// order's or payout's state.
	PocketWait PocketActionKind = iota
	// PocketApply: the lookup is done; parse Result and ApplyResult it.
	PocketApply
	// PocketShow: show the call to the user and leave the entry pending; the
	// user MAY close it (Close), and it is then never placed again.
	PocketShow
	// PocketClose: write Done (the entry closed without a result).
	PocketClose
	// PocketReplace: the owner device places the call again under Derived:
	// sync, confirm the entry is still open, and if DerivedEntryExists reports
	// an entry with w = Derived write Done only; else client.Replace (written
	// ahead through PocketJournal), then write Done.
	PocketReplace
	// PocketConfirm: as PocketReplace, but only after the user's explicit
	// confirmation (a mint_cash or cash_order); until then show it.
	PocketConfirm
)

// PocketAction is ApplyLookup's answer.
type PocketAction struct {
	Kind    PocketActionKind
	Until   int64
	Reason  string
	Result  []byte
	Derived string
	Done    *Entry
}

// ApplyLookup maps client.Recover's action for the pending entry's call to the
// pocket (NIP-CP §Writing, lookup answers). localDevice is this device's id: an
// expired lookup is closed only by the device that wrote the entry, any other
// leaves it open and shows it.
func ApplyLookup(pending Entry, pc nipcash.PendingCall, a client.Action, localDevice string) PocketAction {
	if !pending.IsCall() || pending.State != StatePending {
		return PocketAction{Kind: PocketWait, Reason: "not_pending"}
	}
	closeIt := func(reason string) PocketAction {
		d := WithState(pending, StateDone, now())
		return PocketAction{Kind: PocketClose, Reason: reason, Done: &d}
	}
	switch a.Kind {
	case client.ActionClose:
		if a.Result == nil {
			return closeIt(a.Reason)
		}
		return PocketAction{Kind: PocketApply, Result: a.Result}
	case client.ActionWait:
		return PocketAction{Kind: PocketWait, Until: a.Until, Reason: a.Reason, Result: a.Result}
	case client.ActionShow:
		if a.Reason == "lookup_expired" && pending.Device == localDevice {
			return closeIt(a.Reason)
		}
		return PocketAction{Kind: PocketShow, Reason: a.Reason}
	case client.ActionCloseFailed, client.ActionCloseRefused:
		return closeIt(a.Reason)
	case client.ActionReplace, client.ActionConfirmReplace:
		id, err := nipcash.DerivedRequestID(pc.RequestID)
		if err != nil {
			return PocketAction{Kind: PocketShow, Reason: "lookup_malformed"}
		}
		d := WithState(pending, StateDone, now())
		k := PocketReplace
		if a.Kind == client.ActionConfirmReplace {
			k = PocketConfirm
		}
		return PocketAction{Kind: k, Derived: id, Done: &d}
	}
	return PocketAction{Kind: PocketShow, Reason: "lookup_malformed"}
}
