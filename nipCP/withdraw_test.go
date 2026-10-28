package nipCP

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
)

// The withdraw KAT common inputs (plan §4.2): Hub node identity = key 1, bill =
// key 2, pubkey slice = key 3, the K-WQ-1 quote and K-WR-2 receipt. Their BIP-340
// signatures are deterministic here and frozen as sent.
const (
	wdHubPriv = "0000000000000000000000000000000000000000000000000000000000000001"
	wdHub     = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	wdBill    = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	wdSlice   = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	wdAddr    = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	wdRID     = "00112233445566778899aabbccddeeff"
	// wdUserPriv is key 4, the pocket's user.
	wdUserPriv = "0000000000000000000000000000000000000000000000000000000000000004"
	wdUser     = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"

	kWQ1Raw = `{"id":"bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1720000000,"kind":23187,"tags":[["d","c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"],["i","f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"],["address","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],["amount_millis","21000000"],["network_fee_millis","1200000"],["hub_fee_millis","542000"],["payout_millis","19258000"],["sent_by","1720003600"],["holds_until","870413"]],"content":"","sig":"81cb67d07115a5358c661d90bd1293e03a73554dcd119a5ac0435be27bb6c15cab084c2eedb666b654b7c32d778b6435020785b47055105084443e98732af779"}`
	kWR2Raw = `{"id":"2b376b910505799c6f92edcb3c3543e47e73fc210b877cdd91738c367d21cfef","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1720000100,"kind":23188,"tags":[["d","c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"],["q","bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22"],["request_hash","5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720"],["address","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],["payout_millis","19258000"],["sent_by","1720003600"]],"content":"","sig":"2b61c6a23e5cfdb3a6fd01c51ba70ea3f393139238df9952ae4f044cc6a80ab02eb3f9fc8984a7b90189a53fd8443caba2bfbb25b056bc4e6fe7710d985f4d19"}`

	// K-POCKET-6 rumor ids (kind 9525 by wdUser, created_at 1720000000,
	// wrap_key "c"×64): the pending entry for the pubkey slice (rev 1), with the
	// K-WR-2 receipt (rev 2), its done entry rewritten (rev 4), and the
	// cash-mode pending entry with ["secret", "7"×64, "remint"] (rev 1).
	kPocket6Pending  = "c49dbd482343b3c68e9ba59ae6d120b991f17bd88b98620145eac562ad6b2c39"
	kPocket6Receipt  = "37e38de3fba644966e59095d2da2b7d51277137ee6ee43024ea0b227dcf7a661"
	kPocket6Rewrite  = "3137f0f66c68af647fe3f2f2942042c8346ce4e6c63ad952c5aea820373fa0e4"
	kPocket6CashMode = "1add82fd822acf561e8934d09f063894eb5dbb38979794c392135676899ba246"
)

var (
	wdNotify = hx('5', 64)
	wdRemint = hx('7', 64)
)

// wdCall is the write-ahead of a K-WQ-1 withdrawal, as nipcash builds it.
func wdCall(t *testing.T, cashMode bool) nipcash.PendingCall {
	t.Helper()
	q, err := nipcash.ParseWithdrawQuote(kWQ1Raw)
	if err != nil || q.ID != "bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22" {
		t.Fatalf("K-WQ-1: %v", err)
	}
	p := nipcash.CashWithdrawParams{Quote: q, Credential: nipcash.BySigning("0000000000000000000000000000000000000000000000000000000000000003"),
		RequestID: wdRID, Notify: wdNotify}
	if cashMode {
		r, err := nipcash.CashTargetFromSecret(wdRemint)
		if err != nil {
			t.Fatal(err)
		}
		p.Credential, p.Remint = nipcash.BySecret(hx('6', 64)), r
	}
	pc, err := p.Pending(wdBill)
	if err != nil {
		t.Fatal(err)
	}
	pc.Deadline, pc.Device, pc.Chain, pc.HubIdentity = 1720000300, hx('d', 32), "bitcoin", wdHub
	return pc
}

func wdEntry(t *testing.T, cashMode bool) Entry {
	t.Helper()
	e, err := PendingEntry(wdCall(t, cashMode))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// wdSource is the bill entry the withdrawal names.
func wdSource(cashMode bool) Entry {
	s := bill(wdBill, 3, StateLive)
	s.Amount = 21000000
	s.Identity = EntryIdentity{Type: IdentityPubkey, Value: wdSlice}
	if cashMode {
		s.Identity, s.Secrets = EntryIdentity{Type: IdentityCash}, []nipcash.PendingSecret{{Secret: hx('6', 64)}}
	}
	return s
}

func wdPayout(st nipcash.PayoutState) *nipcash.Payout {
	p := &nipcash.Payout{State: st, Address: wdAddr, AmountMillis: 21000000, FeeMillis: 1742000, PayoutMillis: 19258000,
		SentBy: 1720003600, FinalDepth: 6, Signed: st != nipcash.PayoutQueued, Receipt: kWR2Raw}
	if st == nipcash.PayoutCancelled {
		p.Signed, p.NewWalletPubkey, p.NewWalletToken = false, hx('e', 64), nipcash.TokenOrTombstone{Token: "satscash1remint"}
	}
	return p
}

// wdRumorID is e's rumor id as K-POCKET-6 freezes it.
func wdRumorID(t *testing.T, e Entry) string {
	t.Helper()
	e.WrapKey = hx('c', 64)
	e.CheckedAt = 1720000000
	r, err := e.Rumor(wdUser, 1720000000)
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// T15-25: PendingEntry for cash_withdraw (CP-WD-01, K-POCKET-6).
func TestPendingEntryWithdraw(t *testing.T) {
	fixClock(t, 1720000000)
	if u, _ := keyPub(t, wdUserPriv); u != wdUser {
		t.Fatalf("key 4 is %s", u)
	}
	e := wdEntry(t, false)
	want := Entry{W: wdRID, Rev: 1, State: StatePending, CheckedAt: 1720000000, RequestID: wdRID, Deadline: 1720000300,
		Target: wdBill, Device: hx('d', 32), Chain: "bitcoin", Amount: 21000000, Notify: wdNotify, Address: wdAddr, Quote: kWQ1Raw}
	if !reflect.DeepEqual(e, want) {
		t.Fatalf("pubkey slice:\n%+v\nwant\n%+v", e, want)
	}
	if got := tagNames(t, e); !reflect.DeepEqual(got, []string{"w", "rev", "amount", "chain", "state", "request_id", "deadline",
		"target", "device", "notify", "address", "quote", "wrap_key"}) {
		t.Fatalf("tags %v", got)
	}
	if got := roundTrip(t, e); got.Address != wdAddr || got.Quote != kWQ1Raw || got.Notify != wdNotify {
		t.Fatalf("round trip %+v", got)
	}
	c := wdEntry(t, true)
	if len(c.Secrets) != 1 || c.Secrets[0] != (nipcash.PendingSecret{Secret: wdRemint, Role: SecretRoleRemint}) ||
		c.Cash != "" || c.Identity.Type != "" || c.ExpiresAt != nil {
		t.Fatalf("cash-mode slice %+v", c)
	}
	if got := tagNames(t, c); !reflect.DeepEqual(got, []string{"w", "rev", "amount", "chain", "state", "request_id", "deadline",
		"target", "device", "secret", "notify", "address", "quote", "wrap_key"}) {
		t.Fatalf("cash-mode tags %v", got)
	}
	if got := roundTrip(t, c); !reflect.DeepEqual(got.Secrets, c.Secrets) {
		t.Fatalf("remint secret round trip %+v", got.Secrets)
	}
	// K-POCKET-6, frozen.
	if id := wdRumorID(t, e); id != kPocket6Pending {
		t.Errorf("K-POCKET-6 pending: %s", id)
	}
	if id := wdRumorID(t, c); id != kPocket6CashMode {
		t.Errorf("K-POCKET-6 cash mode: %s", id)
	}
	// Refusals: no notify, address or quote; another secret role; a remint
	// secret outside a call; address, quote or receipt on a bill entry.
	for name, edit := range map[string]func(*nipcash.PendingCall){
		"no notify":  func(pc *nipcash.PendingCall) { pc.Notify = "" },
		"no address": func(pc *nipcash.PendingCall) { pc.Address = "" },
		"no quote":   func(pc *nipcash.PendingCall) { pc.Quote = "" },
		"remainder":  func(pc *nipcash.PendingCall) { pc.Secrets[0].Role = SecretRoleRemainder },
		"two":        func(pc *nipcash.PendingCall) { pc.Secrets = append(pc.Secrets, pc.Secrets[0]) },
	} {
		pc := wdCall(t, true)
		edit(&pc)
		if _, err := PendingEntry(pc); !errors.Is(err, ErrEntry) {
			t.Errorf("%s: %v", name, err)
		}
	}
	b := bill(hx('1', 64), 1, StateLive)
	b.Secrets = []nipcash.PendingSecret{{Secret: wdRemint, Role: SecretRoleRemint}}
	if err := b.Validate(); !errors.Is(err, ErrEntry) {
		t.Error("a remint secret on a bill entry")
	}
	for _, f := range []func(*Entry){func(e *Entry) { e.Address = wdAddr }, func(e *Entry) { e.Quote = kWQ1Raw }, func(e *Entry) { e.Receipt = kWR2Raw }} {
		b := bill(hx('1', 64), 1, StateLive)
		f(&b)
		if err := b.Validate(); !errors.Is(err, ErrEntry) {
			t.Errorf("withdraw field on a bill entry: %+v", b)
		}
	}
	r := e
	r.Receipt, r.Quote, r.Address = kWR2Raw, "", ""
	if err := r.Validate(); !errors.Is(err, ErrEntry) {
		t.Error("a receipt without its quote")
	}
}

// T15-26: ApplyLookup's unknown row for cash_withdraw follows client.Recover;
// a re-placed entry keeps notify and the remint secret (CP-WD-02, CP-WD-03).
func TestApplyLookupWithdraw(t *testing.T) {
	ctx := context.Background()
	m, dev := newMem(), newDevice(t)
	j := &PocketJournal{UserPriv: wdUserPriv, Relays: []string{"a", "b"}, IO: m, Device: dev, Chain: "bitcoin"}
	pc := wdCall(t, true)
	pc.Device, pc.MaxRequestAge = dev.id, 600
	if err := j.WriteAhead(ctx, []nipcash.PendingCall{pc}); err != nil {
		t.Fatal(err)
	}
	pending, ok := j.Written(wdRID)
	if !ok || pending.Quote != kWQ1Raw || pending.Notify != wdNotify {
		t.Fatalf("written ahead %+v", pending)
	}
	recoverWith := func(pc nipcash.PendingCall, lo client.LookupOutcome) client.Action {
		t.Helper()
		a, err := client.Recover(ctx, pc, func(context.Context, nipcash.PendingCall) (client.LookupOutcome, error) { return lo, nil },
			dev.id, time.Unix(1720000100, 0))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	unknown := client.LookupOutcome{Status: nipcash.LookupUnknown}
	derived := "1f0d61013abef39098ffb0a7c72008a17099c52aca3d5ee8d6ce8de065db5d37" // K-DID-1
	got := ApplyLookup(pending, pc, recoverWith(pc, unknown), dev.id)
	if got.Kind != PocketReplace || got.Derived != derived || got.Done == nil || got.Done.State != StateDone {
		t.Fatalf("lost replies only: %+v", got)
	}
	reused := pc
	reused.SawReused = true
	if got := ApplyLookup(pending, reused, recoverWith(reused, unknown), dev.id); got.Kind != PocketConfirm {
		t.Fatalf("after REQUEST_REUSED: %+v", got)
	}
	refused := pc
	refused.LastCode, refused.LastDetail = "RESTRICTED", "quote_expired"
	if got := ApplyLookup(pending, refused, recoverWith(refused, unknown), dev.id); got.Kind != PocketClose || got.Reason != "RESTRICTED/quote_expired" {
		t.Fatalf("after a coded refusal: %+v", got)
	}
	foreign := pc
	foreign.Device = hx('e', 32)
	if got := ApplyLookup(pending, foreign, recoverWith(foreign, unknown), dev.id); got.Kind != PocketShow || got.Reason != "foreign_device" {
		t.Fatalf("another device: %+v", got)
	}
	done, _ := json.Marshal(wdPayout(nipcash.PayoutQueued))
	if got := ApplyLookup(pending, pc, recoverWith(pc, client.LookupOutcome{Status: nipcash.LookupDone, Result: done}), dev.id); got.Kind != PocketWait || got.Result == nil {
		t.Fatalf("done: %+v", got)
	}

	// The re-placement through PocketJournal: the derived entry keeps notify,
	// quote and the remint secret.
	send := func(ctx context.Context, next nipcash.PendingCall) error {
		return j.WriteAhead(ctx, []nipcash.PendingCall{next})
	}
	if _, err := client.Replace(ctx, pc, j, client.ReplaceOptions{DerivedEntryExists: j.DerivedEntryExists, ChainTip: pc.HoldsUntil}, send); err != nil {
		t.Fatal(err)
	}
	re, ok := j.Written(derived)
	if !ok || re.Notify != wdNotify || re.Quote != kWQ1Raw || re.Address != wdAddr || !reflect.DeepEqual(re.Secrets, pending.Secrets) ||
		re.Target != wdBill || re.Amount != 21000000 {
		t.Fatalf("re-placed entry %+v", re)
	}
	// Placed again with a new quote (confirmed): the new quote, the same notify and secret.
	q2ev, err := nipcash.NewWithdrawQuoteEvent(nipcash.QuoteFields{Wallet: wdBill, IdentityValue: wdSlice, Address: wdAddr,
		AmountMillis: 21000000, NetworkFeeMillis: 1500000, HubFeeMillis: 542000, PayoutMillis: 18958000, SentBy: 1720090000, HoldsUntil: 870500},
		1720086400, func(ev *nip01.Event) error { return ev.Sign(wdHubPriv) })
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := json.Marshal(q2ev)
	q2, err := nipcash.ParseWithdrawQuote(string(raw2))
	if err != nil {
		t.Fatal(err)
	}
	next := pc
	next.RequestID, next.Attempt = derived, 1
	if _, err := client.Replace(ctx, next, j, client.ReplaceOptions{Confirmed: true, Quote: q2}, send); err != nil {
		t.Fatal(err)
	}
	id2, _ := nipcash.DerivedRequestID(derived)
	re2, ok := j.Written(id2)
	if !ok || re2.Quote != string(raw2) || re2.Notify != wdNotify || !reflect.DeepEqual(re2.Secrets, pending.Secrets) {
		t.Fatalf("re-placed with a new quote %+v", re2)
	}
}

// T15-27: ApplyWithdraw and WithdrawDoneRewrite (CP-WD-04, CP-WD-05,
// K-POCKET-6).
func TestApplyWithdraw(t *testing.T) {
	fixClock(t, 1720000000)
	e, src := wdEntry(t, false), wdSource(false)

	// The first verified receipt: the entry with its receipt and the source
	// spent (token and secret kept), in one batch; no done while queued.
	writes, done, err := ApplyWithdraw(e, src, wdPayout(nipcash.PayoutQueued), wdHub)
	if err != nil || done != nil || len(writes) != 2 {
		t.Fatalf("first receipt: %+v %+v %v", writes, done, err)
	}
	withReceipt, spent := writes[0], writes[1]
	if withReceipt.W != wdRID || withReceipt.Rev != 2 || withReceipt.State != StatePending || withReceipt.Receipt != kWR2Raw ||
		withReceipt.Quote != kWQ1Raw || withReceipt.Address != wdAddr || withReceipt.Notify != wdNotify {
		t.Fatalf("entry with receipt %+v", withReceipt)
	}
	if spent.W != wdBill || spent.Rev != 4 || spent.State != StateSpent || spent.Cash != src.Cash || spent.Identity != src.Identity {
		t.Fatalf("source %+v", spent)
	}
	if id := wdRumorID(t, withReceipt); id != kPocket6Receipt {
		t.Errorf("K-POCKET-6 receipt: %s", id)
	}
	if got := roundTrip(t, withReceipt); got.Receipt != kWR2Raw {
		t.Fatalf("receipt round trip %+v", got)
	}
	cs := wdSource(true)
	if w := applyOK(t, wdEntry(t, true), cs, nipcash.PayoutQueued); !reflect.DeepEqual(w[1].Secrets, cs.Secrets) {
		t.Fatalf("a spent cash-mode source keeps its secret: %+v", w[1])
	}

	// Invalid receipts: nothing written.
	other := func(edit func([][]string) [][]string) string {
		var ev nip01.Event
		if err := json.Unmarshal([]byte(kWR2Raw), &ev); err != nil {
			t.Fatal(err)
		}
		ev.Tags, ev.ID, ev.Sig = edit(ev.Tags), "", ""
		if err := ev.Sign(wdHubPriv); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(ev)
		return string(b)
	}
	for name, p := range map[string]*nipcash.Payout{
		"request_hash K-WR-4": withReceiptRaw(other(setTag("request_hash", "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"))),
		"another q":           withReceiptRaw(other(setTag("q", "484362992237afca0ec22c8ab27a6abb6214ac0294e38f702a5bb75e4678d276"))),
		"another address":     withReceiptRaw(other(setTag("address", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"))),
		"another d":           withReceiptRaw(other(setTag("d", hx('1', 64)))),
		"payout differs":      func() *nipcash.Payout { p := wdPayout(nipcash.PayoutQueued); p.PayoutMillis--; p.FeeMillis++; return p }(),
		"no receipt":          withReceiptRaw(""),
	} {
		w, d, err := ApplyWithdraw(e, src, p, wdHub)
		if !errors.Is(err, nipcash.ErrReceiptInvalid) || w != nil || d != nil {
			t.Errorf("%s: %+v %+v %v", name, w, d, err)
		}
	}
	if _, _, err := ApplyWithdraw(e, src, wdPayout(nipcash.PayoutQueued), hx('2', 64)); !errors.Is(err, nipcash.ErrReceiptInvalid) {
		t.Errorf("another Hub: %v", err)
	}

	// Once the receipt is kept: broadcast and confirmed write nothing.
	for _, st := range []nipcash.PayoutState{nipcash.PayoutQueued, nipcash.PayoutBroadcast, nipcash.PayoutConfirmed} {
		if w, d, err := ApplyWithdraw(withReceipt, spent, wdPayout(st), wdHub); err != nil || w != nil || d != nil {
			t.Errorf("%s: %+v %+v %v", st, w, d, err)
		}
	}

	// final: done at the next rev, then the SHOULD rewrite.
	w, d, err := ApplyWithdraw(withReceipt, spent, wdPayout(nipcash.PayoutFinal), wdHub)
	if err != nil || w != nil || d == nil || d.State != StateDone || d.Rev != 3 || d.Receipt != kWR2Raw {
		t.Fatalf("final: %+v %+v %v", w, d, err)
	}
	rw, err := WithdrawDoneRewrite(*d)
	if err != nil || rw.Rev != 4 || rw.State != StateDone || rw.Address != "" || rw.Quote != "" || rw.Receipt != "" ||
		rw.Notify != wdNotify || rw.RequestID != wdRID || rw.Target != wdBill {
		t.Fatalf("rewrite %+v %v", rw, err)
	}
	if id := wdRumorID(t, rw); id != kPocket6Rewrite {
		t.Errorf("K-POCKET-6 rewrite: %s", id)
	}
	if got := tagNames(t, rw); !reflect.DeepEqual(got, []string{"w", "rev", "amount", "chain", "state", "request_id", "deadline",
		"target", "device", "notify", "wrap_key"}) {
		t.Fatalf("rewrite tags %v", got)
	}
	if _, err := WithdrawDoneRewrite(rw); !errors.Is(err, ErrEntry) {
		t.Error("a rewrite rewritten")
	}
	if _, err := WithdrawDoneRewrite(withReceipt); !errors.Is(err, ErrEntry) {
		t.Error("a pending entry rewritten")
	}
	if _, _, err := ApplyWithdraw(*d, spent, wdPayout(nipcash.PayoutFinal), wdHub); !errors.Is(err, ErrNotPending) {
		t.Error("ApplyWithdraw on a done entry")
	}

	// final as the first answer: the receipt batch and done.
	w, d, err = ApplyWithdraw(e, src, wdPayout(nipcash.PayoutFinal), wdHub)
	if err != nil || len(w) != 2 || d == nil || d.Rev != 3 || d.Receipt != kWR2Raw {
		t.Fatalf("final first: %+v %+v %v", w, d, err)
	}

	// cancelled, cash mode: the re-minted bill live with the remint secret, then done.
	ce := wdEntry(t, true)
	cw := applyOK(t, ce, cs, nipcash.PayoutQueued)
	w, d, err = ApplyWithdraw(cw[0], cw[1], wdPayout(nipcash.PayoutCancelled), wdHub)
	if err != nil || len(w) != 1 || d == nil || d.Rev != 3 || d.State != StateDone {
		t.Fatalf("cancelled: %+v %+v %v", w, d, err)
	}
	rb := w[0]
	if rb.W != hx('e', 64) || rb.Rev != 1 || rb.State != StateLive || rb.Cash != "satscash1remint" || rb.Amount != 21000000 ||
		rb.Identity.Type != IdentityCash || !reflect.DeepEqual(rb.Secrets, []nipcash.PendingSecret{{Secret: wdRemint}}) || rb.ExpiresAt != nil {
		t.Fatalf("re-minted cash bill %+v", rb)
	}
	// cancelled, identity-bound: the source's identity, no secret.
	w, _, err = ApplyWithdraw(withReceipt, spent, wdPayout(nipcash.PayoutCancelled), wdHub)
	if err != nil || len(w) != 1 || w[0].Identity != src.Identity || len(w[0].Secrets) != 0 {
		t.Fatalf("re-minted identity bill %+v %v", w, err)
	}
	// cancelled with a tombstone in place of the token: no cash, mapped state.
	tp := wdPayout(nipcash.PayoutCancelled)
	tp.NewWalletToken = nipcash.TokenOrTombstone{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: "expired"}}
	w, _, err = ApplyWithdraw(withReceipt, spent, tp, wdHub)
	if err != nil || len(w) != 1 || w[0].Cash != "" || w[0].State != StateExpired {
		t.Fatalf("tombstone re-mint %+v %v", w, err)
	}

	// Not a withdrawal's open entry, or the wrong source.
	if _, _, err := ApplyWithdraw(pendingEntry(hx('2', 32)), src, wdPayout(nipcash.PayoutQueued), wdHub); !errors.Is(err, ErrNotPending) {
		t.Error("a transfer's entry")
	}
	if _, _, err := ApplyWithdraw(e, bill(hx('1', 64), 1, StateLive), wdPayout(nipcash.PayoutQueued), wdHub); !errors.Is(err, ErrEntry) {
		t.Error("another source")
	}
	if _, _, err := ApplyWithdraw(e, src, nil, wdHub); !errors.Is(err, ErrEntry) {
		t.Error("no payout")
	}
}

func withReceiptRaw(raw string) *nipcash.Payout {
	p := wdPayout(nipcash.PayoutQueued)
	p.Receipt = raw
	return p
}

// applyOK applies a first answer that must verify.
func applyOK(t *testing.T, e, src Entry, st nipcash.PayoutState) []Entry {
	t.Helper()
	w, _, err := ApplyWithdraw(e, src, wdPayout(st), wdHub)
	if err != nil || len(w) < 2 {
		t.Fatalf("apply %s: %+v %v", st, w, err)
	}
	return w
}
