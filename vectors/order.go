package vectors

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

// ---- order.json (NIP-CO)

type orderFile struct {
	header
	GetInfo   []orderInfoCase    `json:"getInfo"`
	BuyerKey  []buyerKeyCase     `json:"buyerKey"`
	Fee       []orderFeeCase     `json:"orderFee"`
	Tiers     []tierCase         `json:"confirmations"`
	Split     []splitCaseO       `json:"mintSplit"`
	Notice    orderNoticeCase    `json:"notice"`
	Requests  []wdParseCase      `json:"requests"`
	Refusals  []orderRefusalCase `json:"requestRefusals"`
	Placement []placementCase    `json:"placement"`
	Replies   []orderReplyCase   `json:"replies"`
	States    []orderStateCase   `json:"states"`
	Retention []orderRetainCase  `json:"retention"`
}

// orderInfoCase: get_info read for an order connection: ParseOrderInfo,
// SellsNothing, and the online check fields pubkey/network/chain.
type orderInfoCase struct {
	Name         string         `json:"name"`
	GetInfo      string         `json:"getInfo"`
	Error        string         `json:"error,omitempty"`
	Terms        map[string]any `json:"terms,omitempty"`
	SellsNothing bool           `json:"sellsNothing"`
	Validate     string         `json:"validate,omitempty"`
}

type buyerKeyCase struct {
	ID         string `json:"id,omitempty"`
	CashSecret string `json:"cashSecret"`
	Commitment string `json:"commitment,omitempty"`
	BuyerSK    string `json:"buyerSk,omitempty"`
	BuyerPK    string `json:"buyerPk,omitempty"`
	Error      string `json:"error,omitempty"`
}

type orderFeeCase struct {
	ID      string `json:"id,omitempty"`
	Payment string `json:"payment"`
	FeeBase uint64 `json:"feeBase"`
	FeePpm  uint64 `json:"feePpm"`
	Amount  uint64 `json:"amountMillis"`
	Fee     uint64 `json:"feeMillis"`
	Pay     uint64 `json:"payMillis"`
	Error   string `json:"error,omitempty"`
}

type tierCase struct {
	ID    string       `json:"id,omitempty"`
	Tiers []nipCO.Tier `json:"tiers"`
	Value uint64       `json:"valueMillis"`
	N     uint32       `json:"n"`
	Error string       `json:"error,omitempty"`
}

type splitCaseO struct {
	ID       string   `json:"id,omitempty"`
	Received uint64   `json:"receivedMillis"`
	Fee      uint64   `json:"feeMillis"`
	Max      uint64   `json:"maxMillis"`
	Bills    []uint64 `json:"bills"`
}

type orderNoticeCase struct {
	ID       string                    `json:"id"`
	Notify   string                    `json:"notify"`
	Filter   *nip01.SubscriptionFilter `json:"filter"`
	Tags     [][]string                `json:"noticeTags"`
	Kind     int                       `json:"noticeKind"`
	Content  string                    `json:"noticeContent"`
	IsNotice []isNoticeCase            `json:"isOrderNotice"`
}

type isNoticeCase struct {
	Name   string      `json:"name"`
	Event  nip01.Event `json:"event"`
	Notify string      `json:"notify"`
	Notice bool        `json:"notice"`
}

type orderRefusalCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
	Code  string `json:"code,omitempty"`
	Step  int    `json:"step,omitempty"`
	Error string `json:"error,omitempty"`
}

type placementCase struct {
	Name  string         `json:"name"`
	Input string         `json:"request"`
	Facts map[string]any `json:"facts"`
	Code  string         `json:"code,omitempty"`
	Step  int            `json:"step,omitempty"`
}

type orderReplyCase struct {
	Name    string         `json:"name"`
	Payment string         `json:"payment"`
	Lookup  bool           `json:"lookup"`
	Reply   string         `json:"reply"`
	Error   string         `json:"error,omitempty"`
	Want    map[string]any `json:"want,omitempty"`
}

type orderStateCase struct {
	Facts nipCO.OrderFacts `json:"facts"`
	Now   int64            `json:"now"`
	State string           `json:"state"`
}

type orderRetainCase struct {
	Name         string                 `json:"name"`
	Retention    nipCO.OrderRetention   `json:"retention"`
	Unminted     nipCO.UnmintedPayments `json:"unminted"`
	Now          int64                  `json:"now"`
	Retained     bool                   `json:"retained"`
	BlocksDelete bool                   `json:"blocksHubDelete"`
}

const orderNotify = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const orderGetInfo = `{"methods":["get_info"],"private_methods":["cash_lookup","cash_order"],"pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","network":"mainnet","chain":"bitcoin","cash_order":{"lightning":{"min_millis":1000000,"max_millis":1000000000,"fee_base":1000,"fee_ppm":1000,"window":3600},"onchain":{"min_millis":10000000,"max_millis":1000000000,"fee_base":21000,"fee_ppm":2000,"window":86400,"confirmations":[{"up_to_millis":100000000,"n":1},{"up_to_millis":1000000000,"n":3},{"n":6}]},"bill":{"redeem_fee_base":0,"redeem_fee_ppm":5000,"min_transfer_millis":1000}}}`

func orderErr(err error) (string, int) {
	var oe *nipCO.OrderError
	if errors.As(err, &oe) {
		return oe.Code, oe.Step
	}
	return "", 0
}

func buildOrder() (any, error) {
	f := orderFile{header: newHeader(
		"NIP-CO cash orders: get_info's cash_order terms (with pubkey, network and chain; a retired connection's \"cash_order\": {}), the buyer key derived from the cash secret, the order fee, confirmation tiers, the mint split, the order notice (kind 23189), cash_order requests and their refusals in step order, placement checks, order replies and lookup done results, order states and retention.",
		"nipCO/*.go; nipCO/terms_test.go, order_test.go, request_test.go (K-BK-1, K-OFEE-1..3, K-TIER-1..3, K-SPLIT-1, K-OMINT-1..5, K-ON-1)",
	)}
	info := func(name, raw string) {
		c := orderInfoCase{Name: name, GetInfo: raw}
		t, err := nipCO.ParseOrderInfo(json.RawMessage(raw))
		c.Error = errString(err)
		if err == nil {
			_ = json.Unmarshal([]byte(rawJSON(t)), &c.Terms)
			c.SellsNothing = t.SellsNothing()
			c.Validate = errString(t.Validate(1_000_000_000))
		}
		f.GetInfo = append(f.GetInfo, c)
	}
	info("the NIP-CO example", orderGetInfo)
	info("a retired connection: cash_order {}", `{"methods":["get_info"],"pubkey":"`+wdHub+`","network":"mainnet","chain":"bitcoin","cash_order":{}}`)
	info("no cash_order", `{"methods":["get_info"]}`)
	info("only bill terms", `{"cash_order":{"bill":{}}}`)
	info("on-chain only", `{"cash_order":{"onchain":{"min_millis":1,"max_millis":2,"fee_base":0,"fee_ppm":0,"window":1,"confirmations":[{"n":1}]}}}`)
	for _, v := range []string{`1.5`, `"1000"`, `1e3`, `-1`} {
		info("min_millis "+v, `{"cash_order":{"lightning":{"min_millis":`+v+`,"max_millis":2,"fee_base":0,"fee_ppm":0,"window":1}}}`)
	}
	info("above the per-wallet ceiling", strings.Replace(orderGetInfo, `"max_millis":1000000000,"fee_base":1000`, `"max_millis":1000000001,"fee_base":1000`, 1))
	info("tiers descending", strings.Replace(orderGetInfo, `[{"up_to_millis":100000000,"n":1},{"up_to_millis":1000000000,"n":3},{"n":6}]`, `[{"up_to_millis":1000000000,"n":1},{"up_to_millis":100000000,"n":3},{"n":6}]`, 1))
	info("last tier closed", strings.Replace(orderGetInfo, `{"n":6}`, `{"up_to_millis":5000000000,"n":6}`, 1))
	info("window 0", strings.Replace(orderGetInfo, `"window":3600`, `"window":0`, 1))
	info("not an object", `[]`)

	for _, s := range []string{hex.EncodeToString(seq(0)), strings.Repeat("ab", 32), "XYZ"} {
		c := buyerKeyCase{CashSecret: s}
		if s == hex.EncodeToString(seq(0)) {
			c.ID = "K-BK-1"
		}
		c.Commitment, _ = nipcash.CashCommitment(s)
		var err error
		c.BuyerSK, c.BuyerPK, err = nipCO.BuyerKeyFromSecret(s)
		c.Error = errString(err)
		f.BuyerKey = append(f.BuyerKey, c)
	}

	for _, c := range []orderFeeCase{
		{ID: "K-OFEE-1", Payment: nipCO.PaymentLightning, FeeBase: 1000, FeePpm: 1000, Amount: 21_000_000},
		{ID: "K-OFEE-2", Payment: nipCO.PaymentOnchain, FeeBase: 21000, FeePpm: 2000, Amount: 21_000_000},
		{ID: "K-OFEE-3", Payment: nipCO.PaymentOnchain, FeeBase: 21000, FeePpm: 2001, Amount: 21_000_000},
		{Payment: nipCO.PaymentOnchain, FeeBase: 0, FeePpm: 0, Amount: 21_000_500},
		{Payment: nipCO.PaymentLightning, FeeBase: 1, FeePpm: 0, Amount: ^uint64(0)},
		{Payment: "card", FeeBase: 0, FeePpm: 0, Amount: 1000},
	} {
		var err error
		c.Fee, c.Pay, err = nipCO.OrderFee(c.Payment, nipCO.KindTerms{FeeBase: c.FeeBase, FeePpm: c.FeePpm}, c.Amount)
		c.Error = errString(err)
		f.Fee = append(f.Fee, c)
	}

	u := func(v uint64) *uint64 { return &v }
	tiers := []nipCO.Tier{{UpToMillis: u(100_000_000), N: 1}, {UpToMillis: u(1_000_000_000), N: 3}, {N: 6}}
	for _, c := range []struct {
		id string
		v  uint64
	}{{"K-TIER-1", 21_063_000}, {"K-TIER-2", 500_000_000}, {"K-TIER-3", 2_000_000_000}, {"", 100_000_000}, {"", 100_000_001}} {
		n, err := nipCO.ConfirmationsFor(tiers, c.v)
		f.Tiers = append(f.Tiers, tierCase{c.id, tiers, c.v, n, errString(err)})
	}
	n, err := nipCO.ConfirmationsFor(nil, 1)
	f.Tiers = append(f.Tiers, tierCase{"", []nipCO.Tier{}, 1, n, errString(err)})

	for _, c := range []struct {
		id       string
		received uint64
	}{{"K-SPLIT-1", 2_500_063_000}, {"K-OMINT-1", 21_063_000}, {"K-OMINT-2", 20_000_000}, {"K-OMINT-3", 25_000_000}, {"K-OMINT-4", 10_000_000}, {"K-OMINT-5", 50_000}, {"", 63_000}, {"", 63_001}, {"", 1_000_063_000}} {
		b := nipCO.MintSplit(c.received, 63_000, 1_000_000_000)
		if b == nil {
			b = []uint64{}
		}
		f.Split = append(f.Split, splitCaseO{c.id, c.received, 63_000, 1_000_000_000, b})
	}

	notice, err := nipCO.NewOrderNotice(orderNotify)
	if err != nil {
		return nil, err
	}
	filter := nipCO.OrderNoticeFilter(orderNotify)
	f.Notice = orderNoticeCase{ID: "K-ON-1", Notify: orderNotify, Filter: &filter, Tags: notice.Tags, Kind: notice.Kind, Content: notice.Content}
	isn := func(name string, ev nip01.Event, notify string) {
		f.Notice.IsNotice = append(f.Notice.IsNotice, isNoticeCase{name, ev, notify, nipCO.IsOrderNotice(&ev, notify)})
	}
	mk := func(kind int, content string, tags ...[]string) nip01.Event {
		ev := nip01.Event{Kind: kind, CreatedAt: 1720000000, Content: content, Tags: tags}
		if err := ev.Sign(strings.Repeat("0e", 32)); err != nil {
			panic(err)
		}
		return ev
	}
	isn("the notice", mk(nipCO.KindOrderNotice, "", []string{"p", orderNotify}), orderNotify)
	isn("another notify", mk(nipCO.KindOrderNotice, "", []string{"p", orderNotify}), strings.Repeat("f", 64))
	isn("content", mk(nipCO.KindOrderNotice, "x", []string{"p", orderNotify}), orderNotify)
	isn("an extra tag", mk(nipCO.KindOrderNotice, "", []string{"p", orderNotify}, []string{"e", orderNotify}), orderNotify)
	isn("another kind", mk(1, "", []string{"p", orderNotify}), orderNotify)
	bad := mk(nipCO.KindOrderNotice, "", []string{"p", orderNotify})
	bad.Sig = flipHex(bad.Sig)
	isn("a bad signature", bad, orderNotify)

	// Requests the client builds.
	target := must(nipcash.CashTargetFromSecret(hex.EncodeToString(seq(0))))
	req := func(name string, p nipCO.CashOrderParams) {
		c := wdParseCase{Name: name}
		r, err := p.Request()
		c.Error = errString(err)
		if err == nil {
			c.Input = rawJSON(r)
		}
		f.Requests = append(f.Requests, c)
	}
	base := nipCO.CashOrderParams{Recipient: target, AmountMillis: 21_000_000, Payment: nipCO.PaymentLightning, Notify: orderNotify, RequestID: vecRID}
	with := func(fn func(*nipCO.CashOrderParams)) nipCO.CashOrderParams { p := base; fn(&p); return p }
	req("cash recipient, Lightning (the NIP example)", base)
	req("pubkey recipient, on-chain", with(func(p *nipCO.CashOrderParams) { p.Recipient, p.Payment = nipcash.Pubkey(wdSlice), nipCO.PaymentOnchain }))
	req("connection_key recipient", with(func(p *nipCO.CashOrderParams) {
		p.Recipient = must(nipcash.ConnectionKey("discord", "80351110224678912", wdHub))
	}))
	req("amount 0", with(func(p *nipCO.CashOrderParams) { p.AmountMillis = 0 }))
	req("on-chain 21,000,500", with(func(p *nipCO.CashOrderParams) { p.Payment, p.AmountMillis = nipCO.PaymentOnchain, 21_000_500 }))
	req("payment bitcoin", with(func(p *nipCO.CashOrderParams) { p.Payment = "bitcoin" }))
	req("notify uppercase", with(func(p *nipCO.CashOrderParams) { p.Notify = strings.ToUpper(orderNotify) }))
	req("no recipient", with(func(p *nipCO.CashOrderParams) { p.Recipient = nil }))

	// cash_order request refusals (ParseCashOrderRequest, step 3).
	spec := `{"recipient":{"identity_type":"cash","identity_value":"630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"},"amount_millis":21000000,"payment":"lightning","notify":"` + orderNotify + `","request_id":"` + vecRID + `"}`
	set := func(key, val string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(spec), &m)
		m[key] = json.RawMessage(val)
		return rawJSON(m)
	}
	ref := func(name, raw string) {
		_, err := nipCO.ParseCashOrderRequest(json.RawMessage(raw))
		code, step := orderErr(err)
		f.Refusals = append(f.Refusals, orderRefusalCase{name, raw, code, step, errString(err)})
	}
	ref("the NIP example", spec)
	ref("recipients", set("recipients", `[]`))
	ref("expiry", set("expiry", `60`))
	ref("cash_secret", set("cash_secret", `"`+hex.EncodeToString(seq(0))+`"`))
	ref("on-chain 21000500", strings.Replace(set("payment", `"onchain"`), "21000000", "21000500", 1))
	ref("notify uppercase", set("notify", `"`+strings.ToUpper(orderNotify)+`"`))
	ref("payment card", set("payment", `"card"`))
	ref("recipient bearer", set("recipient", `{"identity_type":"bearer","identity_value":"`+strings.Repeat("ab", 32)+`"}`))
	ref("connection_key without ia", set("recipient", `{"identity_type":"connection_key","identity_value":"`+strings.Repeat("ab", 32)+`"}`))
	ref("cash with ia", set("recipient", `{"identity_type":"cash","identity_value":"`+strings.Repeat("ab", 32)+`","ia_pubkey":"`+strings.Repeat("ab", 32)+`"}`))
	ref("amount 1.5", set("amount_millis", `1.5`))
	ref("amount 0", set("amount_millis", `0`))
	ref("bad request_id", set("request_id", `"xyz"`))
	ref("not an object", `[1]`)
	ref("payment not a string", set("payment", `5`))

	// Placement, NIP-CO step order.
	terms := must(nipCO.ParseOrderInfo(json.RawMessage(orderGetInfo)))
	in := nipCO.PlacementInput{Terms: *terms, IATrusted: true, OpenCeiling: 5_000_000_000, OpenOnchainCeiling: 3, LightningReceivable: true}
	parse := func(raw string) *nipCO.CashOrderRequest {
		r, _ := nipCO.ParseCashOrderRequest(json.RawMessage(raw))
		return r
	}
	amount := func(a string) string { return strings.Replace(spec, "21000000", a, 1) }
	onchain := func(a string) string { return strings.Replace(amount(a), `"lightning"`, `"onchain"`, 1) }
	defect := strings.Replace(spec, orderNotify, strings.ToUpper(orderNotify), 1)
	place := func(name, raw string, fn func(*nipCO.PlacementInput)) {
		x := in
		x.Terms = *terms
		if fn != nil {
			fn(&x)
		}
		code, step := orderErr(nipCO.CheckPlacement(parse(raw), x))
		facts := map[string]any{"retired": x.Retired, "iaTrusted": x.IATrusted, "openMillis": x.OpenMillis, "openCeiling": x.OpenCeiling,
			"openOnchainCount": x.OpenOnchainCount, "openOnchainCeiling": x.OpenOnchainCeiling, "lightningReceivable": x.LightningReceivable,
			"lightningOffered": x.Terms.Lightning != nil}
		f.Placement = append(f.Placement, placementCase{name, raw, facts, code, step})
	}
	place("ok", spec, nil)
	place("retired and over max", amount("2000000000"), func(p *nipCO.PlacementInput) { p.Retired = true })
	place("kind not offered", spec, func(p *nipCO.PlacementInput) { p.Terms.Lightning = nil })
	place("defect on a retired connection", defect, func(p *nipCO.PlacementInput) { p.Retired = true })
	place("min - 1", amount("999999"), nil)
	place("max + 1", amount("1000000001"), nil)
	place("defect and untrusted IA", defect, func(p *nipCO.PlacementInput) { p.IATrusted = false })
	place("untrusted IA and over max", amount("2000000000"), func(p *nipCO.PlacementInput) { p.IATrusted = false })
	place("open = ceiling", spec, func(p *nipCO.PlacementInput) { p.OpenMillis = in.OpenCeiling - 21_000_000 })
	place("ceiling + 1", spec, func(p *nipCO.PlacementInput) { p.OpenMillis = in.OpenCeiling - 21_000_000 + 1 })
	place("on-chain count = ceiling", onchain("21000000"), func(p *nipCO.PlacementInput) { p.OpenOnchainCount = 3 })
	place("on-chain, no count bound", onchain("21000000"), func(p *nipCO.PlacementInput) { p.OpenOnchainCount, p.OpenOnchainCeiling = 99, 0 })
	place("Lightning ignores the count", spec, func(p *nipCO.PlacementInput) { p.OpenOnchainCount = 99 })
	place("Lightning not receivable", spec, func(p *nipCO.PlacementInput) { p.LightningReceivable = false })
	place("on-chain ignores receivable", onchain("21000000"), func(p *nipCO.PlacementInput) { p.LightningReceivable = false })
	place("out of bounds and over the ceiling", amount("1000000001"), func(p *nipCO.PlacementInput) { p.OpenMillis = in.OpenCeiling })

	// Replies and lookup done results.
	sign, err := nipcash.LocalMintSigner(connKey1, "satscash")
	if err != nil {
		return nil, err
	}
	amt := uint64(21_000_000)
	bill := nipcash.Token{HRP: "satscash", WalletPubkey: wdBill, Secret: strings.Repeat("ce", 32), RelayURLs: []string{specRelay1}, AttestedAmountMillis: &amt}
	bill, err = nipcash.SignToken(bill, nipcash.SchemeMintV1, nil, wdHub, sign)
	if err != nil {
		return nil, err
	}
	tok := must(nipcash.Encode(bill))
	reply := func(name, payment, raw string) {
		p := base
		p.Payment = payment
		for _, lookup := range []bool{false, true} {
			c := orderReplyCase{Name: name, Payment: payment, Lookup: lookup, Reply: raw}
			var o *nipCO.Order
			var err error
			if lookup {
				o, err = p.ParseLookupResult([]byte(raw))
			} else {
				o, err = p.ParseResult([]byte(raw))
			}
			c.Error = errString(err)
			if err == nil {
				_ = json.Unmarshal([]byte(rawJSON(o)), &c.Want)
			}
			f.Replies = append(f.Replies, c)
		}
	}
	ln := `{"state":"open","payment":"lightning","amount_millis":21000000,"fee_millis":22000,"pay_millis":21022000,"invoice":"lnbc210220n1...","pay_by":1720003600,"bills":[]}`
	reply("Lightning, open", nipCO.PaymentLightning, ln)
	billJSON := func(token string) string {
		return `{"wallet_pubkey":"` + wdBill + `","cash_token":` + token + `,"amount_millis":21000000,"paid_millis":21063000,"outpoint":"` + strings.Repeat("ab", 32) + `:0"}`
	}
	on := `{"state":"minted","payment":"onchain","amount_millis":21000000,"fee_millis":63000,"pay_millis":21063000,"address":"` + kAddr1 + `","confirmations":1,"pay_by":1720003600,"bills":[` + billJSON(`"`+tok+`"`) + `]}`
	reply("on-chain, minted (a lookup's done result)", nipCO.PaymentOnchain, on)
	reply("on-chain, open", nipCO.PaymentOnchain, `{"state":"open","payment":"onchain","amount_millis":21000000,"fee_millis":63000,"pay_millis":21063000,"address":"`+kAddr1+`","confirmations":1,"pay_by":1720003600,"bills":[]}`)
	reply("a minted bill already destroyed", nipCO.PaymentOnchain, strings.Replace(on, `"`+tok+`"`, `{"status":"spent","reason":"redeemed","retained_until":1720000000}`, 1))
	reply("invoice and address", nipCO.PaymentOnchain, strings.Replace(on, `"address"`, `"invoice":"lnbc1","address"`, 1))
	reply("unknown state", nipCO.PaymentOnchain, strings.Replace(on, `"minted"`, `"unknown"`, 1))
	reply("pay_millis mismatch", nipCO.PaymentOnchain, strings.Replace(on, `21063000,"address"`, `21063001,"address"`, 1))
	reply("no confirmations", nipCO.PaymentOnchain, strings.Replace(on, `"confirmations":1,`, ``, 1))
	reply("a cash_secret", nipCO.PaymentOnchain, strings.Replace(on, `"state"`, `"cash_secret":"`+hex.EncodeToString(seq(0))+`","state"`, 1))
	reply("a bad token", nipCO.PaymentOnchain, strings.Replace(on, `"`+tok+`"`, `"satscash1xyz"`, 1))
	reply("no outpoint", nipCO.PaymentOnchain, strings.Replace(on, `,"outpoint":"`+strings.Repeat("ab", 32)+`:0"`, ``, 1))

	for _, c := range []struct {
		payment  string
		now      int64
		seen     bool
		unminted int
		minted   int
	}{
		{nipCO.PaymentLightning, 1000, false, 0, 0}, {nipCO.PaymentLightning, 1000, true, 1, 0}, {nipCO.PaymentLightning, 1000, true, 0, 1},
		{nipCO.PaymentOnchain, 1000, false, 0, 0}, {nipCO.PaymentOnchain, 1000, true, 1, 0}, {nipCO.PaymentOnchain, 1000, true, 0, 1}, {nipCO.PaymentOnchain, 1000, true, 1, 1},
		{nipCO.PaymentLightning, 1001, false, 0, 0}, {nipCO.PaymentLightning, 1001, true, 1, 0}, {nipCO.PaymentLightning, 1001, true, 0, 1},
		{nipCO.PaymentOnchain, 1001, false, 0, 0}, {nipCO.PaymentOnchain, 1001, true, 1, 0}, {nipCO.PaymentOnchain, 1001, true, 0, 1},
	} {
		fa := nipCO.OrderFacts{Payment: c.payment, PayBy: 1000, Seen: c.seen, Unminted: c.unminted, Minted: c.minted}
		f.States = append(f.States, orderStateCase{fa, c.now, string(nipCO.OrderStateAt(fa, c.now))})
	}

	const P, D, H = 1000, 900, 300
	ret := func(name string, r nipCO.OrderRetention, u nipCO.UnmintedPayments, now int64) {
		f.Retention = append(f.Retention, orderRetainCase{name, r, u, now, nipCO.OrderRetained(r, now), nipCO.OrderBlocksHubDelete(r, u, now)})
	}
	lnR := nipCO.OrderRetention{Payment: nipCO.PaymentLightning, PayBy: P, Deadline: D, Horizon: H}
	onR := nipCO.OrderRetention{Payment: nipCO.PaymentOnchain, PayBy: P, Deadline: D, Horizon: H, Seen: true, Watched: true}
	none := nipCO.UnmintedPayments{}
	ret("Lightning, open", lnR, none, P)
	ret("Lightning at D+H", lnR, none, D+H)
	ret("unpaid Lightning past both", lnR, none, D+H+1)
	live := lnR
	live.BillLiveOrTombstoned = true
	ret("Lightning, a bill live", live, none, 1e9)
	ret("on-chain seen and watched, late", onR, none, D+H+1)
	unw := onR
	unw.Watched = false
	ret("on-chain seen, unwatched", unw, none, 1e9)
	uc := nipCO.UnmintedPayments{Unconfirmed: 1, LastSeenAt: 5000, MaxWait: 100}
	ret("an unconfirmed payment within the wait", onR, uc, 5100)
	ret("an unconfirmed payment past the wait", onR, uc, 5101)
	ret("a confirmed payment not minted", onR, nipCO.UnmintedPayments{Confirmed: 1}, 1e12)
	return f, nil
}
