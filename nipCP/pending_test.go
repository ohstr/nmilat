package nipCP

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
)

func call(method string, amount uint64) nipcash.PendingCall {
	return nipcash.PendingCall{RequestID: hx('2', 32), Deadline: 1760000300, Method: method, Target: hx('b', 64),
		Device: hx('d', 32), Chain: "bitcoin", Amount: amount}
}

// T15-28: PendingEntry per method (CP-EV-05).
func TestPendingEntryPerMethod(t *testing.T) {
	fixClock(t, 1760000000)
	for _, c := range []struct {
		method string
		amount uint64
	}{
		{nipcash.MethodCashTransfer, 5000},    // a split: amount_millis; a full transfer: the source's amount
		{nipcash.MethodCashConsolidate, 5000}, // 3000 + 2000, target sources[0]
		{nipcash.MethodMintCash, 5000},        // 1000 + 4000, target the Cash Hub connection's TLV 0
	} {
		pc := call(c.method, c.amount)
		e, err := PendingEntry(pc)
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		want := Entry{W: pc.RequestID, Rev: 1, State: StatePending, CheckedAt: 1760000000, RequestID: pc.RequestID,
			Deadline: pc.Deadline, Target: pc.Target, Device: pc.Device, Chain: "bitcoin", Amount: c.amount}
		if !reflect.DeepEqual(e, want) {
			t.Fatalf("%s: %+v", c.method, e)
		}
	}
	// The amounts PendingEntry copies are the ones nipcash's builders compute.
	mint := nipcash.MintCashParams{RequestID: hx('2', 32), Recipients: []nipcash.Allocation{
		nipcash.Send(nipcash.Pubkey(hx('a', 64)), 1000), nipcash.Send(nipcash.Pubkey(hx('e', 64)), 4000)}}
	pc, err := mint.Pending(hx('b', 64))
	if err != nil {
		t.Fatal(err)
	}
	{
		pc.Deadline, pc.Device, pc.Chain = 1760000300, hx('d', 32), "bitcoin"
		if e, err := PendingEntry(pc); err != nil || e.Amount != 5000 || e.Target != hx('b', 64) {
			t.Fatalf("mint: %+v %v", e, err)
		}
	}
	for _, m := range []string{"cash_withdraw", nipcash.MethodCashRedeem, nipcash.MethodCashStatus} {
		if _, err := PendingEntry(call(m, 1)); !errors.Is(err, ErrMethod) {
			t.Fatalf("%s: %v", m, err)
		}
	}
	noChain := call(nipcash.MethodCashTransfer, 1)
	noChain.Chain = ""
	if _, err := PendingEntry(noChain); !errors.Is(err, ErrEntry) {
		t.Fatal("a pending entry without chain")
	}
}

// T15-12: a cash split to a cash recipient writes both secrets ahead, the
// remainder marked; the remainder's entry gets its secret (S-CP-38).
func TestCashSplitSecrets(t *testing.T) {
	fixClock(t, 1760000000)
	s1, s2, src := secret(t), secret(t), secret(t)
	pc := call(nipcash.MethodCashTransfer, 5000)
	pc.Secrets = []nipcash.PendingSecret{{Secret: s1}, {Secret: s2, Role: "remainder"}}
	pc.SourceSecret = src
	p, err := PendingEntry(pc)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, p); !reflect.DeepEqual(got.Secrets, pc.Secrets) {
		t.Fatalf("secrets %+v", got.Secrets)
	}
	source := bill(pc.Target, 3, StateLive)
	source.Identity = EntryIdentity{Type: IdentityCash}
	source.Secrets = []nipcash.PendingSecret{{Secret: src}}
	out := Outcome{At: 1760000100, HandOn: []string{s1}, Bills: []NewBill{
		{W: hx('5', 64), Token: nipcash.TokenOrTombstone{Token: "satscash1new"}, Amount: 5000, Identity: EntryIdentity{Type: IdentityCash}, Commitment: commitment(t, s1)},
		{W: hx('6', 64), Token: nipcash.TokenOrTombstone{Token: "satscash1rem"}, Amount: 16000, Identity: EntryIdentity{Type: IdentityCash}, Commitment: commitment(t, s2), ExpiresAt: 1790000000},
	}}
	writes, closeBatch, err := ApplyResult(p, []Entry{source}, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 || writes[0].W != hx('6', 64) || writes[0].Secrets[0].Secret != s2 || s2 == src || *writes[0].ExpiresAt != 1790000000 {
		t.Fatalf("writes %+v", writes)
	}
	if len(closeBatch) != 2 || closeBatch[0].State != StateDone || closeBatch[1].State != StateSpent || closeBatch[1].Rev != 4 || closeBatch[1].Secrets[0].Secret != src {
		t.Fatalf("close %+v", closeBatch)
	}
}

// T15-08, T15-11: ApplyResult rows (S-CP-13, 17..20, 34..37).
func TestApplyResult(t *testing.T) {
	fixClock(t, 1760000000)
	user := EntryIdentity{Type: IdentityPubkey, Value: hx('a', 64)}
	p, _ := PendingEntry(call(nipcash.MethodCashTransfer, 5000))
	src := bill(p.Target, 2, StateLive)

	// BAD_REQUEST: done, sources unchanged.
	w, c, err := ApplyResult(p, []Entry{src}, Outcome{Err: &client.FinalError{Code: "BAD_REQUEST"}})
	if err != nil || w != nil || len(c) != 1 || c[0].State != StateDone || c[0].Rev != 2 {
		t.Fatalf("BAD_REQUEST: %v %v %v", w, c, err)
	}
	// A tombstone in place of the result: done, and the source mapped.
	gone := &nipcash.BillGone{Method: "cash_transfer", Tombstone: nipcash.Tombstone{Status: "spent", Reason: "expired"}}
	w, c, err = ApplyResult(p, []Entry{src}, Outcome{Err: fmt.Errorf("wrapped: %w", gone)})
	if err != nil || w != nil || len(c) != 2 || c[1].State != StateExpired || c[1].Rev != 3 || c[1].Cash == "" {
		t.Fatalf("tombstone: %v %v %v", w, c, err)
	}
	// Any other error, REQUEST_REUSED included: still pending, look it up.
	for _, e := range []error{&client.IndeterminateError{Code: "REQUEST_REUSED"}, errors.New("timeout")} {
		if w, c, err = ApplyResult(p, []Entry{src}, Outcome{Err: e}); !errors.Is(err, ErrLookup) || w != nil || c != nil {
			t.Fatalf("%v: %v %v %v", e, w, c, err)
		}
	}
	// A result: kept bills only, then done + sources spent in one batch.
	res := Outcome{Own: []EntryIdentity{user}, Bills: []NewBill{
		{W: hx('5', 64), Token: nipcash.TokenOrTombstone{Token: "satscash1x"}, Amount: 5000, Identity: EntryIdentity{Type: IdentityPubkey, Value: hx('e', 64)}},
		{W: hx('6', 64), Token: nipcash.TokenOrTombstone{Token: "satscash1y"}, Amount: 16000, Identity: user},
		{W: hx('7', 64), Token: nipcash.TokenOrTombstone{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: "reclaimed"}}, Amount: 1, Identity: user},
	}}
	w, c, err = ApplyResult(p, []Entry{src}, res)
	if err != nil || len(w) != 2 || w[0].W != hx('6', 64) || w[0].State != StateLive || w[1].Cash != "" || w[1].State != StateReclaimed {
		t.Fatalf("result writes %+v %v", w, err)
	}
	if len(c) != 2 || c[0].State != StateDone || c[1].W != src.W || c[1].State != StateSpent {
		t.Fatalf("result close %+v", c)
	}
	// Crash after the entries, before done: the same answer again rewrites the
	// same w (the caller writes it at NextVersion) and closes the same way.
	w2, c2, _ := ApplyResult(p, []Entry{src}, res)
	if w2[0].W != w[0].W || c2[0].Rev != c[0].Rev {
		t.Fatal("not idempotent over a crash")
	}
	// In-place transfer to self: the source's w rewritten live, not spent.
	inPlace := Outcome{Own: []EntryIdentity{user}, Bills: []NewBill{{W: src.W, InPlace: true, Token: nipcash.TokenOrTombstone{Token: "satscash1z"}, Amount: 21000, Identity: user}}}
	w, c, err = ApplyResult(p, []Entry{src}, inPlace)
	if err != nil || len(w) != 1 || w[0].W != src.W || w[0].Rev != 3 || w[0].State != StateLive || len(c) != 1 {
		t.Fatalf("in place: %+v %+v %v", w, c, err)
	}
	// Sources kept until done; closing by deletion alone is not a close.
	if CanRemoveSources(p) || !CanRemoveSources(c[0]) {
		t.Fatal("CanRemoveSources")
	}
	if _, err := Close(c[0], 1); !errors.Is(err, ErrNotPending) {
		t.Fatal("closed a done entry again")
	}
	d, err := Close(p, 1760000500)
	if err != nil || d.Rev != p.Rev+1 || d.State != StateDone || d.RequestID != p.RequestID {
		t.Fatalf("Close %+v %v", d, err)
	}
}

// T15-08, T15-21: ApplyLookup rows (S-CP-16, 21..23, 26, 27, 29, 30).
func TestApplyLookup(t *testing.T) {
	fixClock(t, 1760000000)
	pc := call(nipcash.MethodCashTransfer, 5000)
	p, _ := PendingEntry(pc)
	own, other := pc.Device, hx('9', 32)
	derived, _ := nipcash.DerivedRequestID(pc.RequestID)
	cases := []struct {
		name  string
		a     client.Action
		dev   string
		kind  PocketActionKind
		close bool
	}{
		{"done", client.Action{Kind: client.ActionClose, Result: []byte(`{}`)}, own, PocketApply, false},
		{"pending", client.Action{Kind: client.ActionWait, Until: 5}, own, PocketWait, false},
		{"omitted", client.Action{Kind: client.ActionWait}, own, PocketWait, false},
		{"unknown, owner, transfer", client.Action{Kind: client.ActionReplace}, own, PocketReplace, true},
		{"unknown, mint", client.Action{Kind: client.ActionConfirmReplace}, own, PocketConfirm, true},
		{"unknown, other device", client.Action{Kind: client.ActionShow, Reason: "foreign_device"}, other, PocketShow, false},
		{"expired, owner", client.Action{Kind: client.ActionShow, Reason: "lookup_expired"}, own, PocketClose, true},
		{"expired, other", client.Action{Kind: client.ActionShow, Reason: "lookup_expired"}, other, PocketShow, false},
		{"refused", client.Action{Kind: client.ActionCloseRefused, Reason: "RESTRICTED"}, own, PocketClose, true},
	}
	for _, c := range cases {
		got := ApplyLookup(p, pc, c.a, c.dev)
		if got.Kind != c.kind || (got.Done != nil) != c.close {
			t.Errorf("%s: %+v", c.name, got)
			continue
		}
		if got.Done != nil && (got.Done.State != StateDone || got.Done.Rev != 2) {
			t.Errorf("%s: done %+v", c.name, got.Done)
		}
		if (c.kind == PocketReplace || c.kind == PocketConfirm) && got.Derived != derived {
			t.Errorf("%s: derived %s", c.name, got.Derived)
		}
	}
	// A user-closed (done) entry is never acted on again.
	d, _ := Close(p, 1)
	if got := ApplyLookup(d, pc, client.Action{Kind: client.ActionReplace}, own); got.Kind != PocketWait || got.Derived != "" {
		t.Fatalf("closed entry: %+v", got)
	}
}

// T15-22: PendingEntry for cash_order (K-POCKET-5).
func TestPendingEntryOrder(t *testing.T) {
	fixClock(t, 1760000000)
	notify, _ := nipCO.NewNotify()
	ct, err := nipCO.NewCashOrderTarget()
	if err != nil {
		t.Fatal(err)
	}
	cashPC := call(nipcash.MethodCashOrder, 21000)
	cashPC.Notify, cashPC.Secrets = notify, []nipcash.PendingSecret{{Secret: ct.Secret()}}
	e, err := PendingEntry(cashPC)
	if err != nil {
		t.Fatal(err)
	}
	if e.OrderKey != "" || e.Notify != notify || e.Secrets[0].Secret != ct.Secret() || e.Amount != 21000 || e.Target != cashPC.Target {
		t.Fatalf("cash order %+v", e)
	}
	if got := tagNames(t, e); !reflect.DeepEqual(got, []string{"w", "rev", "amount", "chain", "state", "request_id", "deadline", "target", "device", "secret", "notify", "wrap_key"}) {
		t.Fatalf("cash order tags %v", got)
	}
	bk, _, _ := nipCO.NewBuyerKey()
	pkPC := call(nipcash.MethodCashOrder, 21000)
	pkPC.Notify, pkPC.BuyerKey = notify, bk
	e, err = PendingEntry(pkPC)
	if err != nil || e.OrderKey != bk || len(e.Secrets) != 0 {
		t.Fatalf("pubkey order %+v %v", e, err)
	}
	if got := roundTrip(t, e); got.OrderKey != bk || got.Notify != notify {
		t.Fatalf("round trip %+v", got)
	}
	pkPC.Notify = ""
	if _, err := PendingEntry(pkPC); !errors.Is(err, ErrEntry) {
		t.Fatal("an order entry without notify")
	}
	pkPC.Notify, pkPC.BuyerKey = notify, ""
	if _, err := PendingEntry(pkPC); !errors.Is(err, ErrEntry) {
		t.Fatal("an order entry without order_key or secret")
	}
	pkPC.BuyerKey = hx('A', 64)
	if _, err := PendingEntry(pkPC); !errors.Is(err, ErrEntry) {
		t.Fatal("uppercase order_key")
	}
}
