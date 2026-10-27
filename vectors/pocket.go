package vectors

import (
	"encoding/json"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipCP"
	"github.com/ohstr/nmilat/nipcash"
)

// ---- pocket.json (NIP-CP)

type pocketFile struct {
	header
	User     string            `json:"user"`
	WrapKey  string            `json:"wrapKey"`
	At       int64             `json:"createdAt"`
	Rumors   []pocketRumorCase `json:"rumors"`
	Parse    []pocketParseCase `json:"parseRumor"`
	Resolve  []resolveCase     `json:"resolve"`
	Balance  balanceCase       `json:"balance"`
	Order    []orderApplyCase  `json:"order"`
	Withdraw []pocketRumorCase `json:"withdraw"`
	WdApply  []wdApplyCase     `json:"applyWithdraw"`
}

// pocketRumorCase: an entry as its kind 9525 rumor (unsigned, by User at
// At, wrap_key WrapKey, checked at At): its tags and NIP-01 id.
type pocketRumorCase struct {
	ID    string      `json:"id,omitempty"`
	Name  string      `json:"name"`
	Rumor nip01.Event `json:"rumor"`
	Error string      `json:"error,omitempty"`
}

type pocketParseCase struct {
	Name  string         `json:"name"`
	Rumor nip01.Event    `json:"rumor"`
	Error string         `json:"error,omitempty"`
	Want  map[string]any `json:"want,omitempty"`
}

// resolveCase: K-POCKET-3, Resolve over Entries (rev, rumor id, created_at,
// state): the winner's rumor id and the conflicting w's.
type resolveCase struct {
	ID        string        `json:"id,omitempty"`
	Name      string        `json:"name"`
	Entries   []resolveItem `json:"entries"`
	Winner    string        `json:"winnerRumorId"`
	State     string        `json:"winnerState"`
	Conflicts []string      `json:"conflicts"`
}

type resolveItem struct {
	Rev       uint64 `json:"rev"`
	State     string `json:"state"`
	RumorID   string `json:"rumorId"`
	CreatedAt int64  `json:"createdAt"`
	WrapID    string `json:"wrapId,omitempty"`
}

type balanceCase struct {
	ID      string            `json:"id"`
	Entries []resolveBalance  `json:"entries"`
	Balance map[string]uint64 `json:"balance"`
}

type resolveBalance struct {
	W      string `json:"w"`
	Chain  string `json:"chain"`
	Amount uint64 `json:"amount"`
	State  string `json:"state"`
}

// orderApplyCase: K-POCKET-5, ApplyOrder on the cash_order pending entry: the
// bill entries written and whether the order closes (done).
type orderApplyCase struct {
	ID      string           `json:"id,omitempty"`
	Name    string           `json:"name"`
	Order   map[string]any   `json:"order"`
	Keeps   bool             `json:"keeps"`
	Writes  []map[string]any `json:"writes"`
	Done    bool             `json:"done"`
	DoneRev uint64           `json:"doneRev,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// wdApplyCase: ApplyWithdraw on the cash_withdraw pending entry and its
// source bill for a payout reply: the writes and the done entry.
type wdApplyCase struct {
	Name   string            `json:"name"`
	State  string            `json:"payoutState"`
	Writes []pocketRumorCase `json:"writes"`
	Done   *pocketRumorCase  `json:"done,omitempty"`
	Error  string            `json:"error,omitempty"`
}

const (
	pocketUser = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13" // key 4
	pocketAt   = 1720000000
	kWQ1Raw    = `{"id":"bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1720000000,"kind":23187,"tags":[["d","c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"],["i","f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"],["address","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],["amount_millis","21000000"],["network_fee_millis","1200000"],["hub_fee_millis","542000"],["payout_millis","19258000"],["sent_by","1720003600"],["holds_until","870413"]],"content":"","sig":"81cb67d07115a5358c661d90bd1293e03a73554dcd119a5ac0435be27bb6c15cab084c2eedb666b654b7c32d778b6435020785b47055105084443e98732af779"}`
	kWR2Raw    = `{"id":"2b376b910505799c6f92edcb3c3543e47e73fc210b877cdd91738c367d21cfef","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1720000100,"kind":23188,"tags":[["d","c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"],["q","bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22"],["request_hash","5947d7c33d783f94b3b4c1a96ebc8991ed28f1b069b71e03376cba8caa98a720"],["address","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],["payout_millis","19258000"],["sent_by","1720003600"]],"content":"","sig":"2b61c6a23e5cfdb3a6fd01c51ba70ea3f393139238df9952ae4f044cc6a80ab02eb3f9fc8984a7b90189a53fd8443caba2bfbb25b056bc4e6fe7710d985f4d19"}`
)

func hx(c byte, n int) string { return strings.Repeat(string(c), n) }

func rumorOf(e nipCP.Entry) (nip01.Event, error) {
	e.WrapKey = hx('c', 64)
	e.CheckedAt = pocketAt
	r, err := e.Rumor(pocketUser, pocketAt)
	if err != nil {
		return nip01.Event{}, err
	}
	return *r, nil
}

func rumorCase(id, name string, e nipCP.Entry, err error) pocketRumorCase {
	c := pocketRumorCase{ID: id, Name: name}
	if err == nil {
		c.Rumor, err = rumorOf(e)
	}
	c.Error = errString(err)
	return c
}

func pbill(w string, rev uint64, st nipCP.State) nipCP.Entry {
	return nipCP.Entry{W: w, Rev: rev, Cash: "satscash1" + w[:8], Amount: 21000, Chain: "bitcoin",
		Identity: nipCP.EntryIdentity{Type: nipCP.IdentityPubkey, Value: hx('a', 64)}, State: st, CheckedAt: pocketAt}
}

func buildPocket() (any, error) {
	f := pocketFile{header: newHeader(
		"NIP-CP pocket entries (kind 9525 rumors): bill and pending entries as tags (K-POCKET-1..2), rumor parsing refusals, version resolution (K-POCKET-3), the per-chain balance (K-POCKET-4), the cash_order pending entry and its close rule (K-POCKET-5), and the cash_withdraw pending entry with its receipt, source spent, done and rewrite (K-POCKET-6).",
		"nipCP/{entry,pending,order,withdraw,resolve}.go; nipCP/entry_test.go, seal_test.go, pending_test.go, order_test.go, withdraw_test.go (K-POCKET-1..6)",
	), User: pocketUser, WrapKey: hx('c', 64), At: pocketAt}

	// K-POCKET-1: a bill entry.
	b := pbill(hx('1', 64), 1, nipCP.StateLive)
	b.Mint, b.Source = "02"+hx('e', 64), hx('f', 64)
	exp := int64(1790000000)
	b.ExpiresAt = &exp
	f.Rumors = append(f.Rumors, rumorCase("K-POCKET-1", "a bill entry", b, nil))
	cash := pbill(hx('2', 64), 3, nipCP.StateLive)
	cash.Identity = nipCP.EntryIdentity{Type: nipCP.IdentityCash}
	cash.Secrets = []nipcash.PendingSecret{{Secret: hx('6', 64)}}
	f.Rumors = append(f.Rumors, rumorCase("", "a cash-mode bill entry", cash, nil))
	tomb := nipCP.Entry{W: hx('3', 64), Rev: 5, Amount: 21000, Chain: "bitcoin", Identity: nipCP.EntryIdentity{Type: nipCP.IdentityPubkey, Value: hx('a', 64)}, State: nipCP.StateSpent, CheckedAt: pocketAt}
	f.Rumors = append(f.Rumors, rumorCase("", "an entry from a tombstone", tomb, nil))
	// K-POCKET-2: a pending entry.
	pc := nipcash.PendingCall{RequestID: hx('2', 32), Deadline: 1720000300, Method: nipcash.MethodCashTransfer, Target: hx('b', 64), Device: hx('d', 32), Chain: "bitcoin", Amount: 5000,
		Secrets: []nipcash.PendingSecret{{Secret: hx('7', 64)}}}
	pe, err := nipCP.PendingEntry(pc)
	f.Rumors = append(f.Rumors, rumorCase("K-POCKET-2", "a pending cash_transfer entry", pe, err))
	closed, err := nipCP.Close(pe, pocketAt)
	f.Rumors = append(f.Rumors, rumorCase("", "the done entry that closes it", closed, err))

	parse := func(name string, edit func([][]string) [][]string) {
		r, _ := rumorOf(b)
		r.Tags = edit(append([][]string(nil), r.Tags...))
		id, _ := r.HashID()
		r.ID = hexs(id)
		c := pocketParseCase{Name: name, Rumor: r}
		e, err := nipCP.ParseRumor(&r)
		c.Error = errString(err)
		if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(map[string]any{"w": e.W, "rev": e.Rev, "state": e.State, "rawState": e.RawState, "amount": e.Amount, "chain": e.Chain})), &c.Want)
		}
		f.Parse = append(f.Parse, c)
	}
	set := func(name string, v ...string) func([][]string) [][]string {
		return func(tags [][]string) [][]string {
			for i, tg := range tags {
				if tg[0] == name {
					tags[i] = append([]string{name}, v...)
				}
			}
			return tags
		}
	}
	parse("K-POCKET-1", func(t [][]string) [][]string { return t })
	parse("rev 07", set("rev", "07"))
	parse("amount +21000", set("amount", "+21000"))
	parse("amount 21000.0", set("amount", "21000.0"))
	parse("uppercase w", set("w", hx('A', 64)))
	parse("64-hex mint", set("mint", hx('e', 64)))
	parse("state time 01", set("state", "live", "01"))
	parse("no state time", set("state", "live"))
	parse("two amounts", func(t [][]string) [][]string { return append(t, []string{"amount", "1"}) })
	parse("expires_at 0", set("expires_at", "0"))
	parse("an unrecognised state is kept raw", set("state", "frozen", "1720000000"))

	// K-POCKET-3: resolution.
	w := hx('1', 64)
	ent := func(rev uint64, st nipCP.State, rumor byte, at int64) nipCP.Entry {
		e := pbill(w, rev, st)
		e.RumorID, e.RumorCreatedAt = hx(rumor, 64), at
		return e
	}
	res := func(id, name string, es ...nipCP.Entry) {
		win, conf := nipCP.Resolve(es)
		c := resolveCase{ID: id, Name: name, Winner: win[w].RumorID, State: string(win[w].State), Conflicts: nonNil(conf)}
		for _, e := range es {
			c.Entries = append(c.Entries, resolveItem{e.Rev, string(e.State), e.RumorID, e.RumorCreatedAt, e.WrapID})
		}
		f.Resolve = append(f.Resolve, c)
	}
	a, z := ent(4, nipCP.StateLive, 'a', 10), ent(4, nipCP.StateLive, '0', 10)
	copyA := a
	copyA.WrapID = hx('9', 64)
	res("", "v5 spent over v3 live", ent(5, nipCP.StateSpent, '5', 1), ent(3, nipCP.StateLive, '3', 1))
	res("K-POCKET-3", "the S-CP-11 tie: the lowest rumor id, a conflict", a, copyA, z)
	res("", "a rewrapped copy is no conflict", a, copyA)
	res("", "a later created_at wins a rev tie", a, ent(4, nipCP.StateLive, '0', 11))
	res("", "final v4 over live v4, a conflict", a, ent(4, nipCP.StateSpent, 'f', 1))
	res("", "a higher rev supersedes a final state", ent(5, nipCP.StateSpent, '5', 1), ent(6, nipCP.StateLive, '6', 1))

	// K-POCKET-4: the balance per chain.
	bal := map[string]nipCP.Entry{}
	for _, c := range []struct {
		w      byte
		chain  string
		amount uint64
		st     nipCP.State
	}{{'1', "bitcoin", 21000, nipCP.StateLive}, {'2', "flokicoin", 7000, nipCP.StateLive}, {'3', "bitcoin", 21000, nipCP.StateSpent}, {'4', "bitcoin", 21000, nipCP.StateUnknown}, {'5', "bitcoin", 21000, nipCP.StateLive}} {
		e := pbill(hx(c.w, 64), 1, c.st)
		e.Chain, e.Amount = c.chain, c.amount
		bal[e.W] = e
		f.Balance.Entries = append(f.Balance.Entries, resolveBalance{e.W, e.Chain, e.Amount, string(e.State)})
	}
	f.Balance.ID, f.Balance.Balance = "K-POCKET-4", nipCP.Balance(bal)

	// K-POCKET-5: the cash_order pending entry and its close rule.
	secret := hx('8', 64)
	opc := nipcash.PendingCall{RequestID: hx('2', 32), Deadline: 1720000300, Method: nipcash.MethodCashOrder, Target: hx('b', 64), Device: hx('d', 32), Chain: "bitcoin", Amount: 21000,
		Notify: orderNotify, Secrets: []nipcash.PendingSecret{{Secret: secret}}}
	oe, err := nipCP.PendingEntry(opc)
	f.Rumors = append(f.Rumors, rumorCase("K-POCKET-5", "a cash_order entry with secret and notify", oe, err))
	bk, _, _ := nipCO.BuyerKeyFromSecret(secret)
	kpc := opc
	kpc.Secrets, kpc.BuyerKey = nil, bk
	ke, err := nipCP.PendingEntry(kpc)
	f.Rumors = append(f.Rumors, rumorCase("K-POCKET-5", "a cash_order entry with order_key and notify", ke, err))
	nn := opc
	nn.Notify = ""
	_, err = nipCP.PendingEntry(nn)
	f.Rumors = append(f.Rumors, rumorCase("", "a cash_order entry without notify", nipCP.Entry{}, err))
	obill := func(w, token string) nipCO.OrderBill {
		return nipCO.OrderBill{WalletPubkey: w, Token: nipcash.TokenOrTombstone{Token: token}, AmountMillis: 21000, PaidMillis: 21000}
	}
	apply := func(id, name, payment string, st nipCO.OrderState, keeps bool, bills ...nipCO.OrderBill) {
		o := &nipCO.Order{State: st, Payment: payment, AmountMillis: 21000, PayMillis: 21000, PayBy: 1720003600, Bills: bills}
		c := orderApplyCase{ID: id, Name: name, Keeps: keeps, Writes: []map[string]any{}}
		_ = json.Unmarshal([]byte(rawJSON(o)), &c.Order)
		writes, done, err := nipCP.ApplyOrder(oe, o, keeps, nipCP.OrderAt(pocketAt))
		c.Error = errString(err)
		for _, w := range writes {
			c.Writes = append(c.Writes, map[string]any{"w": w.W, "cash": w.Cash, "state": w.State, "identity": w.Identity.Type, "amount": w.Amount, "secrets": len(w.Secrets)})
		}
		if done != nil {
			c.Done, c.DoneRev = true, done.Rev
		}
		f.Order = append(f.Order, c)
	}
	apply("K-POCKET-5", "Lightning open", nipCO.PaymentLightning, nipCO.OrderOpen, true)
	apply("K-POCKET-5", "Lightning paid", nipCO.PaymentLightning, nipCO.OrderPaid, true)
	apply("K-POCKET-5", "Lightning minted: the bill then done", nipCO.PaymentLightning, nipCO.OrderMinted, true, obill(hx('5', 64), "satscash1b"))
	apply("K-POCKET-5", "Lightning expired", nipCO.PaymentLightning, nipCO.OrderExpired, true)
	apply("K-POCKET-5", "on-chain minted stays open", nipCO.PaymentOnchain, nipCO.OrderMinted, true, obill(hx('5', 64), "satscash1b"))
	apply("K-POCKET-5", "on-chain expired", nipCO.PaymentOnchain, nipCO.OrderExpired, true)
	apply("K-POCKET-5", "on-chain closed", nipCO.PaymentOnchain, nipCO.OrderClosed, true)
	apply("", "a gift: no bill entry", nipCO.PaymentLightning, nipCO.OrderMinted, false, obill(hx('5', 64), "satscash1b"))
	apply("", "a tombstone bill", nipCO.PaymentLightning, nipCO.OrderMinted, true, nipCO.OrderBill{WalletPubkey: hx('6', 64), Token: nipcash.TokenOrTombstone{Tombstone: &nipcash.Tombstone{Status: "spent", Reason: "expired"}}, AmountMillis: 21000})

	// K-POCKET-6: the cash_withdraw entries.
	q, err := nipcash.ParseWithdrawQuote(kWQ1Raw)
	if err != nil {
		return nil, err
	}
	wdc := func(cashMode bool) (nipcash.PendingCall, error) {
		p := nipcash.CashWithdrawParams{Quote: q, Credential: nipcash.BySigning(wdPriv3), RequestID: vecRID, Notify: hx('5', 64)}
		if cashMode {
			r, err := nipcash.CashTargetFromSecret(hx('7', 64))
			if err != nil {
				return nipcash.PendingCall{}, err
			}
			p.Credential, p.Remint = nipcash.BySecret(hx('6', 64)), r
		}
		pc, err := p.Pending(wdBill)
		pc.Deadline, pc.Device, pc.Chain, pc.HubIdentity = 1720000300, hx('d', 32), "bitcoin", wdHub
		return pc, err
	}
	pcPub, err := wdc(false)
	if err != nil {
		return nil, err
	}
	ePub, err := nipCP.PendingEntry(pcPub)
	f.Withdraw = append(f.Withdraw, rumorCase("K-POCKET-6", "the pending entry: pubkey slice", ePub, err))
	pcCash, err := wdc(true)
	if err != nil {
		return nil, err
	}
	eCash, err := nipCP.PendingEntry(pcCash)
	f.Withdraw = append(f.Withdraw, rumorCase("K-POCKET-6", "the pending entry: cash-mode slice (remint secret)", eCash, err))
	for _, c := range []struct {
		name string
		edit func(*nipcash.PendingCall)
	}{
		{"no notify", func(p *nipcash.PendingCall) { p.Notify = "" }},
		{"no address", func(p *nipcash.PendingCall) { p.Address = "" }},
		{"no quote", func(p *nipcash.PendingCall) { p.Quote = "" }},
		{"a remainder secret", func(p *nipcash.PendingCall) { p.Secrets[0].Role = nipCP.SecretRoleRemainder }},
	} {
		p, _ := wdc(true)
		c.edit(&p)
		_, err := nipCP.PendingEntry(p)
		f.Withdraw = append(f.Withdraw, rumorCase("", "refused: "+c.name, nipCP.Entry{}, err))
	}

	src := pbill(wdBill, 3, nipCP.StateLive)
	src.Amount = 21000000
	src.Identity = nipCP.EntryIdentity{Type: nipCP.IdentityPubkey, Value: wdSlice}
	payout := func(st nipcash.PayoutState) *nipcash.Payout {
		p := &nipcash.Payout{State: st, Address: kAddr1, AmountMillis: 21000000, FeeMillis: 1742000, PayoutMillis: 19258000,
			SentBy: 1720003600, FinalDepth: 6, Signed: st != nipcash.PayoutQueued, Receipt: kWR2Raw}
		if st == nipcash.PayoutCancelled {
			p.Signed, p.NewWalletPubkey, p.NewWalletToken = false, hx('e', 64), nipcash.TokenOrTombstone{Token: "satscash1remint"}
		}
		return p
	}
	applyW := func(name string, e, s nipCP.Entry, p *nipcash.Payout) ([]nipCP.Entry, *nipCP.Entry) {
		c := wdApplyCase{Name: name, State: string(p.State), Writes: []pocketRumorCase{}}
		writes, done, err := nipCP.ApplyWithdraw(e, s, p, wdHub)
		c.Error = errString(err)
		for i, w := range writes {
			id := ""
			if i == 0 && name == "first receipt (queued)" {
				id = "K-POCKET-6"
			}
			c.Writes = append(c.Writes, rumorCase(id, w.W, w, nil))
		}
		if done != nil {
			d := rumorCase("", "done", *done, nil)
			c.Done = &d
		}
		f.WdApply = append(f.WdApply, c)
		return writes, done
	}
	writes, _ := applyW("first receipt (queued)", ePub, src, payout(nipcash.PayoutQueued))
	bad := payout(nipcash.PayoutQueued)
	bad.Receipt = ""
	applyW("no receipt", ePub, src, bad)
	if len(writes) == 2 {
		withReceipt, spent := writes[0], writes[1]
		applyW("broadcast after the receipt", withReceipt, spent, payout(nipcash.PayoutBroadcast))
		_, done := applyW("final", withReceipt, spent, payout(nipcash.PayoutFinal))
		applyW("cancelled: the re-mint entry", withReceipt, spent, payout(nipcash.PayoutCancelled))
		if done != nil {
			rw, err := nipCP.WithdrawDoneRewrite(*done)
			f.Withdraw = append(f.Withdraw, rumorCase("K-POCKET-6", "the done entry rewritten", rw, err))
		}
	}
	return f, nil
}
