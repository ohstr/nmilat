package vectors

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// ---- withdraw.json (NIP-CASH cash_withdraw_quote, cash_withdraw)

type withdrawFile struct {
	header
	Inputs        map[string]string `json:"inputs"`
	Quotes        []wdEventKAT      `json:"quotes"`
	RequestHash   []wdHashCase      `json:"requestHash"`
	Receipts      []wdEventKAT      `json:"receipts"`
	ClaimProof    claimKAT          `json:"claimProof"`
	Fee           []wdFeeCase       `json:"withdrawFee"`
	Address       []wdAddrCase      `json:"address"`
	Normalize     []wdNormalizeCase `json:"normalizeAddress"`
	Among         []wdAmongCase     `json:"classifyAddressAmong"`
	Detail        []wdDetailCase    `json:"detail"`
	Holds         []wdHoldCase      `json:"quoteValidAt"`
	Cancel        []wdCancelCase    `json:"cancel"`
	Remint        []wdRemintCase    `json:"remintExpiry"`
	Retention     []wdRetentionCase `json:"retention"`
	Cost          []costCase        `json:"verificationCost"`
	ParseQuote    []wdParseCase     `json:"parseQuote"`
	QuoteRefusals []wdRowCase       `json:"quoteRefusals"`
	CallRefusals  []wdParseCase     `json:"withdrawRequestRefusals"`
	PayoutRows    []wdRowCase       `json:"payoutRefusals"`
	Verify        []wdParseCase     `json:"verifyReceipt"`
	States        []wdStateCase     `json:"payoutStates"`
	Payouts       []wdParseCase     `json:"payouts"`
	CancelShapes  []wdParseCase     `json:"cancelShapes"`
	Terms         []wdParseCase     `json:"withdrawObject"`
}

// wdEventKAT: a quote (23187) or receipt (23188) built by nmilat, signed by
// the Hub key 1; the id is the KAT (signatures are verified, not frozen).
type wdEventKAT struct {
	ID        string      `json:"id"`
	Event     nip01.Event `json:"event"`
	FeeMillis uint64      `json:"feeMillis,omitempty"`
	Verify    string      `json:"verify"`
}

type wdHashCase struct {
	ID        string `json:"id"`
	RequestID string `json:"requestIdHex"`
	Note      string `json:"note,omitempty"`
	Hash      string `json:"hash"`
}

type wdFeeCase struct {
	ID        string `json:"id"`
	Amount    uint64 `json:"amountMillis"`
	Network   uint64 `json:"networkFeeMillis"`
	Base      uint64 `json:"withdrawFeeBase"`
	Ppm       uint64 `json:"withdrawFeePpm"`
	RedeemFee uint64 `json:"redeemFeeMillis"`
	Hub       uint64 `json:"hubFeeMillis"`
	Fee       uint64 `json:"feeMillis"`
	Payout    uint64 `json:"payoutMillis"`
	Error     string `json:"error,omitempty"`
}

type wdAddrCase struct {
	ID         string              `json:"id,omitempty"`
	Address    string              `json:"address"`
	HRP        string              `json:"hrp"`
	ScriptType *nipcash.ScriptType `json:"scriptType,omitempty"`
	Paid       *bool               `json:"paidByHub,omitempty"`
	Error      string              `json:"error,omitempty"`
	Class      string              `json:"class,omitempty"`
}

type wdNormalizeCase struct {
	ID     string `json:"id,omitempty"`
	Input  string `json:"input"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

type wdAmongCase struct {
	ID         string              `json:"id"`
	Address    string              `json:"address"`
	HRPs       []string            `json:"hrps"`
	ScriptType *nipcash.ScriptType `json:"scriptType,omitempty"`
	HRP        string              `json:"hrp,omitempty"`
	Error      string              `json:"error,omitempty"`
	Class      string              `json:"class,omitempty"`
}

type wdDetailCase struct {
	ID       string `json:"id"`
	Response string `json:"error"`
	Detail   string `json:"detail"`
}

type wdHoldCase struct {
	ID         string `json:"id"`
	HoldsUntil int64  `json:"holdsUntil"`
	Tip        int64  `json:"tip"`
	Valid      bool   `json:"valid"`
}

type wdCancelCase struct {
	ID          string `json:"id"`
	Call        string `json:"call"` // CancelDue or CancelRequestAnswer
	AboutToSign bool   `json:"aboutToSign"`
	Broadcast   bool   `json:"broadcast"`
	State       string `json:"state"`
	SentBy      int64  `json:"sentBy"`
	Now         int64  `json:"now"`
	Step        string `json:"step,omitempty"`
	Invalidate  bool   `json:"invalidate"`
	Code        string `json:"code,omitempty"`
}

type wdRemintCase struct {
	ID      string `json:"id"`
	Slice   *int64 `json:"sliceExpiresAt"`
	Cancel  int64  `json:"cancelAt"`
	Default *int64 `json:"defaultExpiry"`
	Expiry  *int64 `json:"expiresAt"`
}

type wdRetentionCase struct {
	ID           string                    `json:"id"`
	Retention    nipcash.WithdrawRetention `json:"retention"`
	Now          int64                     `json:"now"`
	Retained     bool                      `json:"retained"`
	BlocksDelete bool                      `json:"blocksHubDelete"`
}

// wdParseCase: an input read by the named nmilat function; Want is the
// parsed value, Error/Code/Detail/Row the refusal.
type wdParseCase struct {
	ID     string         `json:"id,omitempty"`
	Name   string         `json:"name"`
	Input  string         `json:"input"`
	Slice  any            `json:"slice,omitempty"`
	Want   map[string]any `json:"want,omitempty"`
	Error  string         `json:"error,omitempty"`
	Code   string         `json:"code,omitempty"`
	Detail string         `json:"detail,omitempty"`
}

// wdRowCase: CheckQuoteRequest / CheckWithdrawPayout on the facts given; the
// first refusing row in the spec's table order wins.
type wdRowCase struct {
	Name   string `json:"name"`
	Facts  any    `json:"facts"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
	Row    int    `json:"row,omitempty"`
}

type wdStateCase struct {
	Facts nipcash.PayoutFacts `json:"facts"`
	State string              `json:"state"`
}

func wdErr(err error) (code, detail string, row int) {
	var we *nipcash.WithdrawError
	if errors.As(err, &we) {
		return we.Code, string(we.Detail), we.Row
	}
	return "", "", 0
}

func signWith(priv string) func(*nip01.Event) error {
	return func(ev *nip01.Event) error { return ev.Sign(priv) }
}

func kwq1Fields() nipcash.QuoteFields {
	return nipcash.QuoteFields{Wallet: wdBill, IdentityValue: wdSlice, Address: kAddr1, AmountMillis: 21000000, NetworkFeeMillis: 1200000,
		HubFeeMillis: 542000, PayoutMillis: 19258000, SentBy: 1720003600, HoldsUntil: 870413}
}

func rawJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func buildWithdraw() (any, error) {
	f := withdrawFile{header: newHeader(
		"NIP-CASH on-chain withdrawal: the quote (kind 23187) and receipt (kind 23188) events, request_hash, the claim proof with q, the withdraw fee, witness addresses (segwit v0/v1+, network, script types, case), error details, quote validity, cancellation, re-mint expiry, record retention, verification costs, the Hub's quote and payout refusals in row order, cash_withdraw request refusals, payout states and replies, cancel request shapes, and cash_status' withdraw object.",
		"nipcash/withdraw*.go, nipcash/reuse.go; nipcash/withdraw_test.go, withdraw_address_test.go, claim_proof_test.go, reuse_test.go (K-WQ-1..3, K-WR-1..4, K-CLAIM-5, K-WFEE-1..6, K-ADDR-1..13, K-WDET-1..3, K-WHOLD-1, K-WCAN-1..6, K-WREM-1..4, K-WRET-1..3, K-VB-2)",
	), Inputs: map[string]string{"hub": wdHub, "hubSecret": wdPriv1, "wallet": wdBill, "slice": wdSlice, "sliceSecret": wdPriv3, "address": kAddr1, "requestId": vecRID, "connectionKey": wdCK1}}

	// Quotes.
	q1, err := nipcash.NewWithdrawQuoteEvent(kwq1Fields(), 1720000000, signWith(wdPriv1))
	if err != nil {
		return nil, err
	}
	addQuote := func(id string, ev *nip01.Event) {
		k := wdEventKAT{ID: id, Event: *ev}
		q, err := nipcash.ParseWithdrawQuote(rawJSON(ev))
		if err == nil {
			err = nipcash.VerifyWithdrawQuote(q, wdHub)
			k.FeeMillis = q.FeeMillis()
		}
		k.Verify = errString(err)
		f.Quotes = append(f.Quotes, k)
	}
	addQuote("K-WQ-1", q1)
	ck := kwq1Fields()
	ck.IdentityValue, ck.IAPubkey = wdCK1, wdSlice
	q2, err := nipcash.NewWithdrawQuoteEvent(ck, 1720000000, signWith(wdPriv1))
	if err != nil {
		return nil, err
	}
	addQuote("K-WQ-2", q2)
	q3 := q1.Copy()
	for i, j := 0, len(q3.Tags)-1; i < j; i, j = i+1, j-1 {
		q3.Tags[i], q3.Tags[j] = q3.Tags[j], q3.Tags[i]
	}
	if err := q3.Sign(wdPriv1); err != nil {
		return nil, err
	}
	addQuote("K-WQ-3", q3)

	// request_hash and receipts.
	did, _ := nipcash.DerivedRequestID(vecRID)
	raw16, _ := hex.DecodeString(vecRID)
	f.RequestHash = []wdHashCase{
		{ID: "K-WR-1", RequestID: vecRID, Hash: nipcash.RequestHash(vecRID)},
		{ID: "K-WR-3", RequestID: did, Note: "the derived id of a re-placed call (K-DID-1)", Hash: nipcash.RequestHash(did)},
		{ID: "K-WR-4", RequestID: vecRID, Note: "negative: over the 16 raw bytes", Hash: nipcash.RequestHash(string(raw16))},
	}
	expect := nipcash.ReceiptExpectation{HubXOnly: wdHub, Target: wdBill, QuoteID: kWQ1ID, RequestID: vecRID, Address: kAddr1, PayoutMillis: 19258000, SentBy: 1720003600}
	addReceipt := func(id, rid string, at int64) *nip01.Event {
		ev, err := nipcash.NewWithdrawReceiptEvent(nipcash.ReceiptFields{Wallet: wdBill, QuoteID: kWQ1ID, RequestID: rid, Address: kAddr1, PayoutMillis: 19258000, SentBy: 1720003600}, at, signWith(wdPriv1))
		if err != nil {
			panic(err)
		}
		e := expect
		e.RequestID = rid
		f.Receipts = append(f.Receipts, wdEventKAT{ID: id, Event: *ev, Verify: errString(nipcash.VerifyWithdrawReceipt(rawJSON(ev), e))})
		return ev
	}
	r2 := addReceipt("K-WR-2", vecRID, 1720000100)
	addReceipt("K-WR-3", did, 1720000200)
	ver := func(id, name string, mod func(*nipcash.ReceiptExpectation)) {
		e := expect
		mod(&e)
		err := nipcash.VerifyWithdrawReceipt(rawJSON(r2), e)
		f.Verify = append(f.Verify, wdParseCase{ID: id, Name: name, Input: rawJSON(r2), Want: map[string]any{"expectation": e}, Error: errString(err)})
	}
	ver("K-WR-2", "the receipt as expected", func(*nipcash.ReceiptExpectation) {})
	ver("K-WR-4", "request_hash over the raw bytes", func(e *nipcash.ReceiptExpectation) { e.RequestID = string(raw16) })
	ver("", "another quote", func(e *nipcash.ReceiptExpectation) { e.QuoteID = strings.Repeat("4", 64) })
	ver("", "another bill", func(e *nipcash.ReceiptExpectation) { e.Target = wdSlice })
	ver("", "another payout", func(e *nipcash.ReceiptExpectation) { e.PayoutMillis++ })
	ver("", "another sent_by", func(e *nipcash.ReceiptExpectation) { e.SentBy++ })
	ver("", "another author", func(e *nipcash.ReceiptExpectation) { e.HubXOnly = wdSlice })
	ver("", "a recovered call: no quote id", func(e *nipcash.ReceiptExpectation) { e.QuoteID = "" })

	for _, k := range claimKATs() {
		if k.ID == "K-CLAIM-5" {
			f.ClaimProof = k
		}
	}

	// Fees.
	rf := func(amount, base, ppm uint64) uint64 { fee, _, _ := nipcash.RedeemFee(amount, base, ppm); return fee }
	for _, c := range []wdFeeCase{
		{ID: "K-WFEE-1", Amount: 21000000, Network: 1200000, Base: 500000, Ppm: 2000, RedeemFee: rf(21000000, 0, 5000)},
		{ID: "K-WFEE-2", Amount: 21000000, Network: 1200001, Base: 500000, Ppm: 2000, RedeemFee: rf(21000000, 0, 5000)},
		{ID: "K-WFEE-3", Amount: 21000000, Network: 50000, Base: 0, Ppm: 0, RedeemFee: rf(21000000, 100000, 5000)},
		{ID: "K-WFEE-4", Amount: 1000000, Network: 1200000, Base: 500000, Ppm: 2000, RedeemFee: rf(1000000, 0, 5000)},
		{ID: "K-WFEE-5", Amount: 21000500, Network: 1200000, Base: 500000, Ppm: 2000, RedeemFee: rf(21000500, 0, 5000)},
		{ID: "K-WFEE-6", Amount: 21000000, Ppm: 1000001},
		{ID: "", Amount: 21000000, Ppm: 1000000},
		{ID: "", Amount: 10, Network: ^uint64(0), Base: 1},
	} {
		var err error
		c.Hub, c.Fee, c.Payout, err = nipcash.WithdrawFee(c.Amount, c.Network, c.Base, c.Ppm, c.RedeemFee)
		c.Error = errString(err)
		f.Fee = append(f.Fee, c)
	}

	// Addresses.
	pays := []nipcash.ScriptType{{Version: 0, ProgramLen: 20}, {Version: 0, ProgramLen: 32}, {Version: 1, ProgramLen: 32}}
	class := func(err error) string {
		switch {
		case err == nil:
			return ""
		case errors.Is(err, nipcash.ErrAddressMalformed):
			return "malformed"
		case errors.Is(err, nipcash.ErrAddressNetwork):
			return "network"
		case errors.Is(err, nipcash.ErrAddressNoWitness):
			return "script_type"
		}
		return "other"
	}
	addr := func(id, a, hrp string) {
		c := wdAddrCase{ID: id, Address: a, HRP: hrp}
		st, err := nipcash.ClassifyAddress(a, hrp)
		c.Error, c.Class = errString(err), class(err)
		if err == nil {
			c.ScriptType = &st
			p := nipcash.PaysScriptType(pays, st)
			c.Paid = &p
		}
		f.Address = append(f.Address, c)
	}
	addr("K-ADDR-1", kAddr1, "bc")
	addr("K-ADDR-2", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "bc")
	addr("K-ADDR-3", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc")
	addr("K-ADDR-4", "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "bc")
	addr("K-ADDR-5", "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kj9wkru", "bc")
	addr("K-ADDR-6", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "bc")
	addr("K-ADDR-7", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "bc")
	addr("K-ADDR-8", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "bc")
	addr("K-ADDR-9", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kqq7e2cw9", "bc")
	addr("K-ADDR-10", strings.ToUpper(kAddr1), "bc")
	addr("K-ADDR-11", "BC1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc")
	addr("K-ADDR-12", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc")
	addr("", "bc1"+strings.Repeat("q", 88), "bc")
	addr("", "bc1", "bc")
	addr("", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb", "bc")
	addr("", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "bc")
	addr("", kAddr1, "")
	for _, c := range [][2]string{{"K-ADDR-10", strings.ToUpper(kAddr1)}, {"K-ADDR-11", "BC1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}, {"", "  " + kAddr1 + "\t"}, {"", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}} {
		out, err := nipcash.NormalizeAddress(c[1])
		f.Normalize = append(f.Normalize, wdNormalizeCase{c[0], c[1], out, errString(err)})
	}
	among := []string{"bc", "tb", "bcrt"}
	for _, a := range []string{"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "zz1qw508d6qejxtdg4y5r3zarvary0c5xw7k3c49eg"} {
		c := wdAmongCase{ID: "K-ADDR-13", Address: a, HRPs: among}
		st, hrp, err := nipcash.ClassifyAddressAmong(a, among)
		c.HRP, c.Error, c.Class = hrp, errString(err), class(err)
		if err == nil {
			c.ScriptType = &st
		}
		f.Among = append(f.Among, c)
	}

	// Details.
	for _, c := range [][2]string{
		{"K-WDET-1", `{"code":"RESTRICTED","message":"x","detail":"own_address"}`},
		{"K-WDET-2", `{"code":"RESTRICTED","message":"x","detail":"fee_over_cap"}`},
		{"K-WDET-3", `{"code":"RESTRICTED","message":"x"}`},
		{"", `{"code":"RESTRICTED","message":"x","detail":"OWN_ADDRESS"}`},
	} {
		var re transport.ResultError
		_ = json.Unmarshal([]byte(c[1]), &re)
		f.Detail = append(f.Detail, wdDetailCase{c[0], c[1], string(nipcash.ParseDetail(re.Detail))})
	}
	for _, d := range []nipcash.Detail{nipcash.DetailNetwork, nipcash.DetailScriptType, nipcash.DetailBelowMin, nipcash.DetailTooSlow, nipcash.DetailQuoteInvalid, nipcash.DetailQuoteExpired, nipcash.DetailUnfinal, nipcash.DetailOwnAddress} {
		f.Detail = append(f.Detail, wdDetailCase{"", `{"code":"RESTRICTED","detail":"` + string(d) + `"}`, string(nipcash.ParseDetail(string(d)))})
	}

	for _, tip := range []int64{870413, 870414} {
		f.Holds = append(f.Holds, wdHoldCase{"K-WHOLD-1", 870413, tip, nipcash.QuoteValidAt(870413, tip)})
	}

	// Cancellation.
	const S = 1720003600
	steps := map[nipcash.CancelStep]string{nipcash.CancelNotDue: "not_due", nipcash.CancelNow: "cancel_now", nipcash.InvalidateThenCancel: "invalidate_then_cancel"}
	due := func(id string, fa nipcash.CancelFacts, now int64) {
		f.Cancel = append(f.Cancel, wdCancelCase{ID: id, Call: "CancelDue", AboutToSign: fa.AboutToSign, Broadcast: fa.Broadcast, State: string(fa.State), SentBy: fa.SentBy, Now: now, Step: steps[nipcash.CancelDue(fa, now)]})
	}
	answer := func(id string, fa nipcash.CancelFacts, now int64) {
		inv, err := nipcash.CancelRequestAnswer(fa, now)
		code, _, _ := wdErr(err)
		f.Cancel = append(f.Cancel, wdCancelCase{ID: id, Call: "CancelRequestAnswer", AboutToSign: fa.AboutToSign, Broadcast: fa.Broadcast, State: string(fa.State), SentBy: fa.SentBy, Now: now, Invalidate: inv, Code: code})
	}
	queued := nipcash.CancelFacts{State: nipcash.PayoutQueued, SentBy: S}
	due("K-WCAN-1", queued, 1720089999)
	due("K-WCAN-2", queued, 1720090000)
	sign := queued
	sign.AboutToSign = true
	due("K-WCAN-3", sign, 1720090000)
	for _, st := range []nipcash.PayoutState{nipcash.PayoutConfirmed, nipcash.PayoutFinal, nipcash.PayoutCancelled} {
		due("", nipcash.CancelFacts{State: st, SentBy: S}, 1720090000)
	}
	bc := nipcash.CancelFacts{AboutToSign: true, Broadcast: true, State: nipcash.PayoutBroadcast, SentBy: S}
	answer("K-WCAN-4", bc, 1720608399)
	answer("K-WCAN-5", bc, 1720608400)
	answer("K-WCAN-6", nipcash.CancelFacts{State: nipcash.PayoutConfirmed, SentBy: S}, 1720608400)
	answer("", nipcash.CancelFacts{State: nipcash.PayoutQueued, SentBy: S}, 1720608400)

	p := func(v int64) *int64 { return &v }
	for _, c := range []wdRemintCase{
		{ID: "K-WREM-1", Slice: p(1720086400), Cancel: 1720090000, Default: p(2592000)},
		{ID: "K-WREM-2", Slice: nil, Cancel: 1720090000, Default: p(2592000)},
		{ID: "K-WREM-3", Slice: p(1730000000), Cancel: 1720090000, Default: p(2592000)},
		{ID: "K-WREM-4", Slice: p(1720086400), Cancel: 1720090000, Default: nil},
	} {
		c.Expiry = nipcash.RemintExpiry(c.Slice, c.Cancel, c.Default)
		f.Remint = append(f.Remint, c)
	}

	ret := func(id string, r nipcash.WithdrawRetention, now int64) {
		f.Retention = append(f.Retention, wdRetentionCase{id, r, now, nipcash.WithdrawRecordRetained(r, now), nipcash.WithdrawBlocksHubDelete(r, now)})
	}
	r := nipcash.WithdrawRetention{Deadline: 1720000060, Horizon: 300, TombstoneWindow: 2592000}
	ret("K-WRET-1", r, 1720000000)
	ret("K-WRET-1", r, 1<<40)
	r.EndedAt = 1720100000
	ret("K-WRET-2", r, 1722692000)
	ret("K-WRET-2", r, 1722692001)
	r.RemintLive = true
	ret("K-WRET-3", r, 1<<40)
	ret("", nipcash.WithdrawRetention{Deadline: 1720000060, Horizon: 300, EndedAt: 1720000000}, 1720000360)
	ret("", nipcash.WithdrawRetention{Deadline: 1720000060, Horizon: 300, EndedAt: 1720000000}, 1720000361)

	for _, c := range costCases() {
		if c.ID == "K-VB-2" {
			f.Cost = append(f.Cost, c)
		}
	}

	// Quote parsing.
	mutate := func(fn func(*nip01.Event)) string {
		c := q1.Copy()
		fn(c)
		_ = c.Sign(wdPriv1)
		return rawJSON(c)
	}
	pq := func(name, raw string) {
		c := wdParseCase{Name: name, Input: raw}
		q, err := nipcash.ParseWithdrawQuote(raw)
		if err == nil {
			err = nipcash.VerifyWithdrawQuote(q, wdHub)
		}
		c.Error = errString(err)
		c.Code, c.Detail, _ = wdErr(err)
		f.ParseQuote = append(f.ParseQuote, c)
	}
	pq("K-WQ-1", rawJSON(q1))
	pq("an extra tag", mutate(func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"x", "1"}) }))
	pq("a repeated d", mutate(func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"d", wdBill}) }))
	pq("a leading zero", mutate(func(e *nip01.Event) { e.Tags[3][1] = "021000000" }))
	pq("content", mutate(func(e *nip01.Event) { e.Content = "x" }))
	pq("kind 23188", mutate(func(e *nip01.Event) { e.Kind = nipcash.KindWithdrawReceipt }))
	pq("no holds_until", mutate(func(e *nip01.Event) { e.Tags = e.Tags[:8] }))
	pq("i with four elements", mutate(func(e *nip01.Event) { e.Tags[1] = []string{"i", wdSlice, wdSlice, wdSlice} }))
	pq("signed by another key", func() string { c := q1.Copy(); _ = c.Sign(wdPriv3); return rawJSON(c) }())
	pq("not JSON", "{")

	// cash_withdraw_quote refusals (CheckQuoteRequest), row order.
	max, min := uint64(1000), uint64(100)
	payout := func(po, dust uint64) func(nipcash.ScriptType) (uint64, uint64, error) {
		return func(nipcash.ScriptType) (uint64, uint64, error) { return po, dust, nil }
	}
	type qfacts struct {
		Found        bool     `json:"found"`
		Address      string   `json:"address"`
		NetworkHRP   string   `json:"networkHrp"`
		Claimable    bool     `json:"claimable"`
		AmountMillis uint64   `json:"amountMillis"`
		MinMillis    uint64   `json:"minMillis"`
		MaxMillis    uint64   `json:"maxMillis"`
		Payout       uint64   `json:"payoutMillis"`
		Dust         uint64   `json:"dustMillis"`
		SendBefore   *int64   `json:"sendBefore"`
		Earliest     int64    `json:"earliestSentBy"`
		Pays         [][2]int `json:"pays"`
	}
	qrow := func(name string, fa qfacts) {
		c := nipcash.QuoteCheck{Found: fa.Found, Address: fa.Address, NetworkHRP: fa.NetworkHRP, Pays: pays, Claimable: fa.Claimable,
			AmountMillis: fa.AmountMillis, MinMillis: &min, MaxMillis: &max, PayoutFor: payout(fa.Payout, fa.Dust), SendBefore: fa.SendBefore, EarliestSentBy: fa.Earliest}
		code, det, row := wdErr(nipcash.CheckQuoteRequest(c))
		f.QuoteRefusals = append(f.QuoteRefusals, wdRowCase{name, fa, code, det, row})
	}
	base := qfacts{Found: true, Address: kAddr1, NetworkHRP: "bc", Claimable: true, AmountMillis: 500, MinMillis: 100, MaxMillis: 1000, Payout: 400000, Dust: 1, Earliest: 100, Pays: [][2]int{{0, 20}, {0, 32}, {1, 32}}}
	mod := func(fn func(*qfacts)) qfacts { c := base; fn(&c); return c }
	data, _ := bech32.ConvertBits(repeat(7, 16), 8, 5, true)
	tbV2, _ := bech32.EncodeM("tb", append([]byte{2}, data...))
	sb := int64(100)
	qrow("all clear", base)
	qrow("not found and malformed: row 1", mod(func(c *qfacts) { c.Found, c.Address = false, "x" }))
	qrow("malformed: row 2", mod(func(c *qfacts) { c.Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh" }))
	qrow("another network and not paid: row 3", mod(func(c *qfacts) { c.Address = tbV2 }))
	qrow("a testnet address: row 3", mod(func(c *qfacts) { c.Address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" }))
	qrow("not paid and claimed: row 4", mod(func(c *qfacts) { c.Address, c.Claimable = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", false }))
	qrow("no witness: row 4", mod(func(c *qfacts) { c.Address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" }))
	qrow("not claimable and above max: row 5", mod(func(c *qfacts) { c.Claimable, c.AmountMillis = false, 5000 }))
	qrow("above max and dust: row 6", mod(func(c *qfacts) { c.AmountMillis, c.Payout = 5000, 0 }))
	qrow("below min: row 7", mod(func(c *qfacts) { c.AmountMillis = 50 }))
	qrow("payout below dust: row 7", mod(func(c *qfacts) { c.Payout, c.Dust = 1000, 2000 }))
	qrow("send_before = earliest", mod(func(c *qfacts) { c.SendBefore = &sb }))
	qrow("too slow: row 8", mod(func(c *qfacts) { c.SendBefore, c.Earliest = &sb, 101 }))

	// cash_withdraw step 3 (CheckWithdrawPayout), row order.
	prow := func(name string, c nipcash.PayoutCheck) {
		code, det, row := wdErr(nipcash.CheckWithdrawPayout(c))
		f.PayoutRows = append(f.PayoutRows, wdRowCase{name, c, code, det, row})
	}
	prow("all clear", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true})
	prow("quote invalid", nipcash.PayoutCheck{AtUnconfirmedBound: true, OwnAddress: true})
	prow("quote expired, at the bound", nipcash.PayoutCheck{QuoteOK: true, AtUnconfirmedBound: true})
	prow("at the unconfirmed bound, no coins", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, AtUnconfirmedBound: true})
	prow("no coins, own address", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, OwnAddress: true})
	prow("unfinal kept, own address", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true, OrderedUnfinal: true, OwnAddress: true})
	prow("unfinal refused", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true, OrderedUnfinal: true, RefuseUnfinal: true, OwnAddress: true})
	prow("unfinal not refused", nipcash.PayoutCheck{QuoteOK: true, QuoteValid: true, CoinsSetAside: true, OrderedUnfinal: true})

	// cash_withdraw request refusals (before step 1).
	notify := strings.Repeat("0123456789abcdef", 4)
	qs := rawJSON(rawJSON(q1))
	call := func(extra string) string {
		return `{"quote":` + qs + `,"request_id":"` + vecRID + `","notify":"` + notify + `"` + extra + `}`
	}
	commit := strings.Repeat("11", 32)
	wr := func(name, raw string, s nipcash.WithdrawSlice) {
		c := wdParseCase{Name: name, Input: raw, Slice: s}
		req, err := nipcash.ParseCashWithdrawRequest(json.RawMessage(raw), s)
		c.Error = errString(err)
		c.Code, c.Detail, _ = wdErr(err)
		if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(req)), &c.Want)
		}
		f.CallRefusals = append(f.CallRefusals, c)
	}
	pk := nipcash.WithdrawSlice{}
	cash := nipcash.WithdrawSlice{CashMode: true, Commitment: commit}
	wr("the NIP example (pubkey slice)", call(`,"identity_type":"pubkey","identity_value":"`+wdSlice+`","identity_event":"{}"`), pk)
	wr("cash mode", call(`,"remint_commitment":"`+strings.Repeat("22", 32)+`","cash_secret":"`+strings.Repeat("ab", 32)+`"`), cash)
	wr("missing quote", `{"request_id":"`+vecRID+`","notify":"`+notify+`"}`, pk)
	wr("quote not a string", `{"quote":{},"request_id":"`+vecRID+`","notify":"`+notify+`"}`, pk)
	wr("malformed quote", `{"quote":"{}","request_id":"`+vecRID+`","notify":"`+notify+`"}`, pk)
	wr("missing request_id", `{"quote":`+qs+`,"notify":"`+notify+`"}`, pk)
	wr("invalid request_id", `{"quote":`+qs+`,"request_id":"XYZ","notify":"`+notify+`"}`, pk)
	wr("missing notify", `{"quote":`+qs+`,"request_id":"`+vecRID+`"}`, pk)
	wr("uppercase notify", `{"quote":`+qs+`,"request_id":"`+vecRID+`","notify":"`+strings.ToUpper(notify)+`"}`, pk)
	wr("cash mode without remint_commitment", call(`,"cash_secret":"`+strings.Repeat("ab", 32)+`"`), cash)
	wr("cash mode with remint_commitment equal to the slice's", call(`,"remint_commitment":"`+commit+`","cash_secret":"`+strings.Repeat("ab", 32)+`"`), cash)
	wr("remint_commitment on a pubkey slice", call(`,"remint_commitment":"`+strings.Repeat("22", 32)+`","identity_event":"{}"`), pk)

	// Payout states and replies.
	for _, fa := range []nipcash.PayoutFacts{
		{FinalDepth: 6}, {Broadcast: true, FinalDepth: 6}, {Broadcast: true, Depth: 1, FinalDepth: 6}, {Broadcast: true, Depth: 6, FinalDepth: 6},
		{Cancelled: true, Broadcast: true, Depth: 3, FinalDepth: 6}, {Broadcast: true, Depth: 0, FinalDepth: 6}, {Broadcast: true, FinalReached: true, FinalDepth: 6},
	} {
		f.States = append(f.States, wdStateCase{fa, string(nipcash.PayoutStateOf(fa))})
	}
	txid := strings.Repeat("ab", 32)
	po := func(state, extra string, signed bool) string {
		s := "false"
		if signed {
			s = "true"
		}
		return `{"state":"` + state + `","address":"` + kAddr1 + `","amount_millis":21000000,"fee_millis":1742000,"payout_millis":19258000,"sent_by":1720003600,"final_depth":6,"signed":` + s + `,"receipt":` + rawJSON(rawJSON(r2)) + extra + `}`
	}
	pp := func(name, raw string) {
		c := wdParseCase{Name: name, Input: raw}
		p, err := nipcash.ParsePayout([]byte(raw))
		c.Error = errString(err)
		var gone *nipcash.BillGone
		if errors.As(err, &gone) {
			c.Want = map[string]any{"gone": gone.Tombstone}
		} else if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(p)), &c.Want)
		}
		f.Payouts = append(f.Payouts, c)
	}
	pp("queued", po("queued", "", false))
	pp("queued, signed", po("queued", "", true))
	pp("broadcast", po("broadcast", `,"tx":"00","txid":"`+txid+`","vout":1,"depth":0`, true))
	pp("confirmed", po("confirmed", `,"txid":"`+txid+`","vout":1,"depth":2`, true))
	pp("final", po("final", `,"txid":"`+txid+`","vout":1,"depth":6`, true))
	pp("cancelled, re-minted", po("cancelled", `,"new_wallet_pubkey":"`+wdBill+`","new_wallet_token":"satscash1x"`, false))
	pp("cancelled, the re-minted bill already destroyed", po("cancelled", `,"new_wallet_pubkey":"`+wdBill+`","new_wallet_token":{"status":"spent","reason":"redeemed"}`, false))
	pp("a tombstone: the bill is gone", `{"status":"spent","withdraw_request_id":"`+vecRID+`"}`)
	pp("cancelled with a txid", po("cancelled", `,"txid":"`+txid+`","new_wallet_pubkey":"`+wdBill+`","new_wallet_token":"t"`, false))
	pp("no receipt", strings.Replace(po("queued", "", false), `,"receipt":`+rawJSON(rawJSON(r2)), "", 1))
	pp("unknown state", po("failed", "", false))
	pp("no signed", strings.Replace(po("queued", "", false), `"signed":false,`, "", 1))
	pp("queued with a txid", po("queued", `,"txid":"`+txid+`","vout":0,"depth":0`, false))
	pp("broadcast without txid", po("broadcast", "", true))
	pp("tx while unsigned", po("queued", `,"tx":"00"`, false))
	pp("re-mint fields while queued", po("queued", `,"new_wallet_pubkey":"`+wdBill+`"`, false))

	// Cancel request shapes.
	cs := func(name, raw string) {
		c := wdParseCase{Name: name, Input: raw}
		req, isCancel, err := nipcash.ParseWithdrawCancel(json.RawMessage(raw))
		c.Error = errString(err)
		c.Code, c.Detail, _ = wdErr(err)
		c.Want = map[string]any{"isCancel": isCancel}
		if req != nil {
			c.Want["request"] = req
		}
		f.CancelShapes = append(f.CancelShapes, c)
	}
	cs("cancel by request_id", `{"cancel":true,"request_id":"`+vecRID+`"}`)
	cs("bearer cancel", `{"cancel":true,"request_id":"`+vecRID+`","cash_secret":"`+strings.Repeat("ab", 32)+`"}`)
	cs("a call is not a cancel", `{"quote":"x"}`)
	cs("cancel false", `{"cancel":false,"request_id":"`+vecRID+`"}`)
	cs("cancel as a string", `{"cancel":"true","request_id":"`+vecRID+`"}`)
	cs("no request_id", `{"cancel":true}`)
	cs("another field", `{"cancel":true,"request_id":"`+vecRID+`","notify":"x"}`)
	cs("a bad cash_secret", `{"cancel":true,"request_id":"`+vecRID+`","cash_secret":"zz"}`)

	// cash_status' withdraw object.
	wt := func(name, raw string) {
		c := wdParseCase{Name: name, Input: raw}
		var w nipcash.WithdrawTerms
		err := json.Unmarshal([]byte(raw), &w)
		if err == nil {
			err = w.Validate()
		}
		c.Error = errString(err)
		if err == nil {
			c.Want = map[string]any{"terms": w, "scriptTypes": w.ScriptTypeList()}
		}
		f.Terms = append(f.Terms, c)
	}
	wt("the NIP example", `{"withdraw_fee_base":500000,"withdraw_fee_ppm":2000,"min_millis":10000000,"max_millis":1000000000,"script_types":[[0,20],[0,32],[1,32]],"final_depth":6}`)
	wt("no bounds", `{"withdraw_fee_base":0,"withdraw_fee_ppm":0,"script_types":[[0,20]],"final_depth":1}`)
	wt("ppm above 1000000", `{"withdraw_fee_base":0,"withdraw_fee_ppm":1000001,"script_types":[[0,20]],"final_depth":1}`)
	wt("no script type", `{"withdraw_fee_base":0,"withdraw_fee_ppm":0,"script_types":[],"final_depth":1}`)
	wt("an invalid script type", `{"withdraw_fee_base":0,"withdraw_fee_ppm":0,"script_types":[[0,21]],"final_depth":1}`)
	wt("final_depth 0", `{"withdraw_fee_base":0,"withdraw_fee_ppm":0,"script_types":[[0,20]],"final_depth":0}`)
	wt("min above max", `{"withdraw_fee_base":0,"withdraw_fee_ppm":0,"min_millis":2000,"max_millis":1000,"script_types":[[0,20]],"final_depth":1}`)
	return f, nil
}
