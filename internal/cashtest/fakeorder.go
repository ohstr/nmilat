package cashtest

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/wire"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// OrderPrivateMethods are what an Order connection's get_info lists as served
// over the private transport.
var OrderPrivateMethods = []string{"cash_lookup", "cash_order"}

// FakeAddressHRP is the segwit HRP of the fake's network and chain (regtest
// bitcoin).
const FakeAddressHRP = "bcrt"

// The fake payer's coins: how many are funded at a time, and their value.
const (
	payerCoins    = 64
	payerCoinSats = 100_000_000
	payerFeeSats  = 500
)

// OrderBook is the fake Hub's NIP-CO side: Order connections (one at first,
// more with AddConnection, each retirable), their get_info terms on the
// kind-23194 connection, cash_order and its lookups on the private transport,
// decided through nipCO's Hub helpers, and a payer paying the orders.
//
// Payments arrive as they would at a real Hub. PayInvoice settles an order's
// invoice; PayAddress broadcasts a transaction paying an order's address on the
// book's Chain (the bill ledger's when ServeWithdrawals ran first, else its
// own), which Mine, Reorg and Evict then drive. The Hub mints on its own, on
// every Tick: after each payment, block, reorganisation and eviction, each
// Advance, and when BreakSigner clears; never inside a call. A Lightning
// payment mints at once; an on-chain output once it has the confirmations of
// the tier its own value falls in, before or after pay_by; each payment once
// (by payment hash or outpoint), received − fee_millis split at max_millis. A
// broken signer leaves the payment unminted (the order paid) until it clears.
// With a bill ledger (ServeWithdrawals) the bills are ledger bills whose slice
// is ordered, never expires and carries the terms' bill object; without one
// they are bare tokens.
//
// At pay_by an on-chain order that saw a payment is kept and its address
// watched; one that saw nothing is deleted at max(pay_by, deadline + H), and a
// later payment to it is kept by the Hub. Every change of an order's state or
// bills publishes an order notice on the relay the order arrived on.
//
// Order records and the used request_id marks are persisted at each change;
// Restart drops everything else and reloads them, as a Hub process restart
// would.
type OrderBook struct {
	h     *FakeHub
	chain *Chain

	mu    sync.Mutex
	conns []*orderConn
	terms json.RawMessage
	// infoPubkey and infoChain, when set, replace get_info's pubkey and chain.
	infoPubkey, infoChain string
	// openCeiling is the open-order ceiling per kind (default 10^12 millis);
	// onchainCeiling the open on-chain order count bound (0: none).
	openCeiling, onchainCeiling uint64
	// beforeReply runs after an order is checked and before its reply is built.
	beforeReply  func()
	address      string
	nwcCalls     map[string]int
	skew         time.Duration
	signerBroken bool

	orders map[string]*orderRecord
	used   map[string]bool
	// store is what survives Restart: each order record, as JSON, by request_id.
	store map[string][]byte

	// outputs index what the payer sent to order addresses (the chain's side).
	outputs     []chainOutput
	payerCoins  []wire.OutPoint
	payerScript []byte
}

type orderConn struct {
	priv, xonly, secret, appPub string
	retired                     bool
}

type chainOutput struct {
	op     wire.OutPoint
	script string
	millis uint64
}

// orderRecord is one order as the Hub persists it.
type orderRecord struct {
	RID       string                 `json:"rid"`
	Conn      string                 `json:"conn"`
	Relay     string                 `json:"relay"`
	Order     nipCO.Order            `json:"order"`
	Recipient nipcash.RecipientParam `json:"recipient"`
	BuyerPub  string                 `json:"buyer_pub"`
	Notify    string                 `json:"notify"`
	Deadline  int64                  `json:"deadline"`
	Terms     nipCO.Terms            `json:"terms"`
	PayHash   string                 `json:"pay_hash,omitempty"`
	Script    string                 `json:"script,omitempty"`
	// Payments are the payments seen, by payment hash or outpoint.
	Payments map[string]*orderPayment `json:"payments"`
	// Decided is set at pay_by for an on-chain order: Watched when a payment
	// was seen, else the order goes at DeleteAt.
	Decided  bool   `json:"decided"`
	Watched  bool   `json:"watched"`
	DeleteAt int64  `json:"delete_at"`
	Notified string `json:"notified"`
}

type orderPayment struct {
	Millis uint64 `json:"millis"`
	SeenAt int64  `json:"seen_at"`
	Depth  uint32 `json:"depth"`
	Minted bool   `json:"minted"`
	Bills  int    `json:"bills"`
}

// ServeOrders gives the Hub an Order connection selling under terms (a get_info
// cash_order object) and returns its book. Call ServeWithdrawals first for the
// orders to mint ledger bills and share the ledger's chain and clock.
func (h *FakeHub) ServeOrders(t testing.TB, terms string) *OrderBook {
	t.Helper()
	b := &OrderBook{h: h, terms: json.RawMessage(terms), openCeiling: 1_000_000_000_000,
		used: map[string]bool{}, orders: map[string]*orderRecord{}, store: map[string][]byte{}, nwcCalls: map[string]int{}}
	b.newConnLocked()
	if l := b.ledger(); l != nil {
		b.chain = l.Chain()
	} else {
		b.chain = NewChain()
	}
	prog, _ := hex.DecodeString(randHex(20))
	b.payerScript = nipcash.WitnessScript(0, prog)
	b.fundPayer()
	b.chain.OnChange(b.Tick)
	prev := h.Decide
	h.Decide = func(c ItemCtx) *transport.Result {
		if conn := b.conn(c.Item.Target); conn != nil {
			return b.decide(c, conn)
		}
		if prev == nil {
			return nil
		}
		return prev(c)
	}
	for _, r := range h.Relays {
		r.OnEvent(b.onEvent)
	}
	return b
}

func (b *OrderBook) newConnLocked() *orderConn {
	c := &orderConn{}
	c.priv, c.xonly = mustKeypair()
	c.secret, c.appPub = mustKeypair()
	b.conns = append(b.conns, c)
	return c
}

func (b *OrderBook) conn(xonly string) *orderConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		if c.xonly == xonly {
			return c
		}
	}
	return nil
}

func (b *OrderBook) ledger() *WithdrawLedger {
	b.h.mu.Lock()
	defer b.h.mu.Unlock()
	return b.h.ledger
}

func (b *OrderBook) fundPayer() {
	var coins []wire.OutPoint
	for range payerCoins {
		coins = append(coins, b.chain.Fund(b.payerScript, payerCoinSats))
	}
	b.mu.Lock()
	b.payerCoins = append(b.payerCoins, coins...)
	b.mu.Unlock()
}

// Chain is the chain the book's on-chain orders are paid on.
func (b *OrderBook) Chain() *Chain { return b.chain }

func (b *OrderBook) signed(t testing.TB, c *orderConn) nipCO.OrderConnection {
	t.Helper()
	sign, err := nipcash.LocalChainSigner(b.h.NodePriv, FakeChain)
	if err != nil {
		t.Fatal(err)
	}
	oc, err := nipCO.SignOrderConnection(nipCO.OrderConnection{Pubkey: c.xonly, Relays: b.h.RelayURLs(),
		Secret: c.secret, Label: "fake counter", HasLabel: true, HubIdentity: b.h.nodeXOnly, Chain: FakeChain},
		sign, b.h.nodeXOnly)
	if err != nil {
		t.Fatal(err)
	}
	return oc
}

func (b *OrderBook) encode(t testing.TB, c *orderConn) string {
	t.Helper()
	s, err := nipCO.EncodeOrderConnection(b.signed(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// SignedOrderConnection is the book's first Order connection record, signed by
// the node identity: what the Hub lists (a listing is built from records, never
// from a string).
func (b *OrderBook) SignedOrderConnection(t testing.TB) nipCO.OrderConnection {
	t.Helper()
	b.mu.Lock()
	c := b.conns[0]
	b.mu.Unlock()
	return b.signed(t, c)
}

// OrderConnection is the book's first cashorder1 string, signed by the node
// identity.
func (b *OrderBook) OrderConnection(t testing.TB) string {
	t.Helper()
	b.mu.Lock()
	c := b.conns[0]
	b.mu.Unlock()
	return b.encode(t, c)
}

// AddConnection gives the Hub another Order connection selling under the same
// terms and returns its cashorder1 string.
func (b *OrderBook) AddConnection(t testing.TB) string {
	t.Helper()
	b.mu.Lock()
	c := b.newConnLocked()
	b.mu.Unlock()
	return b.encode(t, c)
}

// SetTerms replaces the get_info cash_order object.
func (b *OrderBook) SetTerms(terms string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.terms = json.RawMessage(terms)
}

// Retire retires the first connection: get_info answers "cash_order": {} at
// once and new orders are refused RESTRICTED; lookups are still served and
// payments still minted.
func (b *OrderBook) Retire() { b.mu.Lock(); b.conns[0].retired = true; b.mu.Unlock() }

// RetireConnection retires the connection whose key is pubkey (x-only), as
// Retire does.
func (b *OrderBook) RetireConnection(pubkey string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		if c.xonly == pubkey {
			c.retired = true
		}
	}
}

// SetInfoIdentity makes get_info report pubkey and chain instead of the node's
// (online-check cases).
func (b *OrderBook) SetInfoIdentity(pubkey, chain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.infoPubkey, b.infoChain = pubkey, chain
}

// SetOpenCeiling sets the open-order ceiling per kind.
func (b *OrderBook) SetOpenCeiling(millis uint64) { b.mu.Lock(); b.openCeiling = millis; b.mu.Unlock() }

// SetOpenOnchainCeiling bounds the number of open on-chain orders (0: none).
func (b *OrderBook) SetOpenOnchainCeiling(n uint64) { b.mu.Lock(); b.onchainCeiling = n; b.mu.Unlock() }

// BeforeReply runs f while an accepted order is being placed, before its reply
// is built: a test changes the terms there.
func (b *OrderBook) BeforeReply(f func()) { b.mu.Lock(); b.beforeReply = f; b.mu.Unlock() }

// SetAddress makes every new on-chain order reply carry addr (invalid-reply
// cases); "" restores fresh addresses.
func (b *OrderBook) SetAddress(addr string) { b.mu.Lock(); b.address = addr; b.mu.Unlock() }

// BreakSigner breaks the node signer at settlement while on: payments wait
// unminted, their orders paid. Clearing it mints them.
func (b *OrderBook) BreakSigner(on bool) {
	b.mu.Lock()
	b.signerBroken = on
	b.mu.Unlock()
	if !on {
		b.Tick()
	}
}

// Now is the book's clock: the bill ledger's when there is one, else the Hub's
// plus what Advance added.
func (b *OrderBook) Now() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nowTimeLocked()
}

func (b *OrderBook) nowTimeLocked() time.Time {
	if l := b.ledger(); l != nil {
		return l.Now()
	}
	return b.h.Clock.Now().Add(b.skew)
}

func (b *OrderBook) nowLocked() int64 { return b.nowTimeLocked().Unix() }

// Advance moves the book's clock (the ledger's, when there is one) forward by
// d, then ticks: pay_by passes, reservations are released, unpaid on-chain
// orders are deleted.
func (b *OrderBook) Advance(d time.Duration) {
	if l := b.ledger(); l != nil {
		l.Advance(d)
	} else {
		b.mu.Lock()
		b.skew += d
		b.mu.Unlock()
	}
	b.Tick()
}

// Mine mines n blocks on the book's chain.
func (b *OrderBook) Mine(n int) { b.chain.Mine(n) }

// Reorg replaces the depth best blocks with empty ones.
func (b *OrderBook) Reorg(depth int) { b.chain.Reorg(depth) }

// Evict drops the unconfirmed payment outpoint (txid:vout) from the mempool.
func (b *OrderBook) Evict(outpoint string) {
	txid, _, _ := strings.Cut(outpoint, ":")
	b.chain.Evict(txid)
}

// Restart is a Hub process restart: everything not persisted is dropped, and
// the order records are reloaded as last committed.
func (b *OrderBook) Restart() {
	b.mu.Lock()
	b.orders = map[string]*orderRecord{}
	for rid, raw := range b.store {
		var r orderRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			panic("cashtest: a persisted order does not decode: " + err.Error())
		}
		b.orders[rid] = &r
	}
	b.mu.Unlock()
	b.Tick()
}

func (b *OrderBook) persistLocked(r *orderRecord) {
	raw, err := json.Marshal(r)
	if err != nil {
		panic("cashtest: persist an order: " + err.Error())
	}
	b.store[r.RID] = raw
}

// NWCCalls counts the kind-23194 requests the Order connections got, by method.
func (b *OrderBook) NWCCalls(method string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nwcCalls[method]
}

// Order returns the order placed under requestID as it stands now.
func (b *OrderBook) Order(requestID string) (nipCO.Order, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.orders[requestID]
	if !ok {
		return nipCO.Order{}, false
	}
	return b.currentLocked(r, b.nowLocked()), true
}

// Orders counts the orders the Hub keeps.
func (b *OrderBook) Orders() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.orders) }

func (b *OrderBook) onEvent(r *Relay, ev *nip01.Event) {
	if ev.Kind != kindNWCRequest {
		return
	}
	b.mu.Lock()
	var conn *orderConn
	for _, c := range b.conns {
		if taggedP(ev, c.xonly) && ev.PubKey == c.appPub {
			conn = c
		}
	}
	b.mu.Unlock()
	if conn == nil {
		return
	}
	req, err := nip47.ParseRequestEvent(ev, conn.priv)
	if err != nil {
		return
	}
	encryption := nip47.EncryptionNIP04 // legacy-check: NIP-47's reading of a request with no encryption tag
	if enc, err := utils.FindUniqueEventTagValue(ev.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}
	b.mu.Lock()
	b.nwcCalls[req.Method]++
	terms := b.terms
	if conn.retired {
		terms = json.RawMessage(`{}`)
	}
	pubkey, chain := b.h.nodeXOnly, FakeChain
	if b.infoPubkey != "" || b.infoChain != "" {
		pubkey, chain = b.infoPubkey, b.infoChain
	}
	b.mu.Unlock()
	var resp *nip01.Event
	if req.Method == "get_info" {
		resp, err = nip47.NewResponseEvent(conn.priv, ev.PubKey, req.Method, map[string]any{
			"methods": []string{"get_info"}, "private_methods": OrderPrivateMethods,
			"pubkey": pubkey, "network": FakeNetwork, "chain": chain, "cash_order": terms,
		}, ev, encryption)
	} else {
		resp, err = nip47.NewErrorResponseEvent(conn.priv, ev.PubKey, req.Method, nip47.Error{
			Code: "NOT_IMPLEMENTED", Message: req.Method + " is not served on an Order connection",
		}, ev, encryption)
	}
	if err != nil {
		b.h.t.Errorf("cashtest: order nwc response: %v", err)
		return
	}
	if err := resp.Sign(conn.priv); err != nil {
		b.h.t.Errorf("cashtest: sign order nwc response: %v", err)
		return
	}
	r.Publish(resp)
}

func coded(code, msg string) *transport.Result {
	return &transport.Result{Error: &transport.ResultError{Code: code, Message: msg}}
}

// decide serves one item targeting an Order connection: I8, steps 1 to 8 of
// NIP-CO §Processing Algorithm, and cash_lookup. A bill proof not signed by the
// connection secret is omitted (I2).
func (b *OrderBook) decide(c ItemCtx, conn *orderConn) *transport.Result {
	hash, err := transport.CanonicalParamsHash(c.Item.Params)
	if err != nil {
		return coded(nipcash.ErrCodeBadRequest, "params")
	}
	binding := transport.ProofBinding{Target: c.Item.Target, HubXOnly: b.h.nodeXOnly, Method: c.Item.Method,
		ParamsHash: hash, Nonce: c.Envelope.Nonce, NotAfter: c.Envelope.NotAfter}
	if signer, err := transport.VerifyBillProof(c.Item.BillProof, binding, c.Now); err != nil || signer != conn.appPub {
		return nil
	}
	if len(c.Item.Proof) == 0 {
		return coded(nipcash.ErrCodeBadRequest, "an order item carries a proof")
	}
	signer, proofErr := transport.VerifyItemProof(c.Item.Proof, binding, c.Now)
	switch c.Item.Method {
	case nipcash.MethodCashOrder:
		return b.place(c, conn, signer, proofErr)
	case nipcash.MethodCashLookup:
		return b.lookup(c, conn, signer, proofErr)
	}
	return coded(nipcash.ErrCodeNotImplemented, c.Item.Method+" is not served on an Order connection")
}

// state is r's state at now.
func (r *orderRecord) state(now int64) nipCO.OrderState {
	f := nipCO.OrderFacts{Payment: r.Order.Payment, PayBy: r.Order.PayBy, Seen: len(r.Payments) > 0}
	for _, p := range r.Payments {
		switch {
		case !p.Minted:
			f.Unminted++
		case p.Bills > 0:
			f.Minted++
		}
	}
	return nipCO.OrderStateAt(f, now)
}

func (b *OrderBook) place(c ItemCtx, conn *orderConn, signer string, proofErr error) *transport.Result {
	req, perr := nipCO.ParseCashOrderRequest(c.Item.Params)
	if req == nil || !nipcash.ValidRequestID(req.RequestID) {
		return coded(nipcash.ErrCodeBadRequest, "request_id")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used[req.RequestID] {
		return coded(nipcash.ErrCodeRequestReused, "request_id used")
	}
	if proofErr != nil {
		return coded(nipcash.ErrCodeUnauthorized, "item proof")
	}
	b.used[req.RequestID] = true
	_ = perr // reported by CheckPlacement in step order
	terms, err := nipCO.ParseOrderInfo(b.terms)
	if err != nil {
		return coded(nipcash.ErrCodeInternal, "terms")
	}
	trusted := true
	if req.Recipient.IAPubkey != "" {
		b.h.mu.Lock()
		trusted = b.h.TrustedIAs[req.Recipient.IAPubkey]
		b.h.mu.Unlock()
	}
	now := b.nowLocked()
	// The reservation: an order counts against the ceiling while open or paid;
	// minted, expired or closed (the clock passing pay_by) releases it.
	var open, onchainOpen uint64
	for _, r := range b.orders {
		if st := r.state(now); r.Order.Payment == req.Payment && (st == nipCO.OrderOpen || st == nipCO.OrderPaid) {
			open += r.Order.AmountMillis
			if r.Order.Payment == nipCO.PaymentOnchain {
				onchainOpen++
			}
		}
	}
	if err := nipCO.CheckPlacement(req, nipCO.PlacementInput{Terms: *terms, Retired: conn.retired, IATrusted: trusted,
		OpenMillis: open, OpenCeiling: b.openCeiling, OpenOnchainCount: onchainOpen, OpenOnchainCeiling: b.onchainCeiling,
		LightningReceivable: true}); err != nil {
		oe := err.(*nipCO.OrderError)
		return coded(oe.Code, oe.Reason)
	}
	k := terms.Kind(req.Payment)
	fee, pay, err := nipCO.OrderFee(req.Payment, *k, req.AmountMillis)
	if err != nil {
		return coded(nipcash.ErrCodeBadRequest, err.Error())
	}
	if f := b.beforeReply; f != nil {
		b.mu.Unlock()
		f()
		b.mu.Lock()
		if t2, err := nipCO.ParseOrderInfo(b.terms); err == nil && t2.Kind(req.Payment) != nil {
			terms, k = t2, t2.Kind(req.Payment)
		}
	}
	r := &orderRecord{RID: req.RequestID, Conn: conn.xonly, Recipient: req.Recipient, BuyerPub: signer,
		Notify: req.Notify, Deadline: c.Envelope.NotAfter, Terms: *terms, Payments: map[string]*orderPayment{}}
	r.Recipient.AmountMillis = 0
	if c.Relay != nil {
		r.Relay = c.Relay.URL()
	}
	o := nipCO.Order{State: nipCO.OrderOpen, Payment: req.Payment, AmountMillis: req.AmountMillis, FeeMillis: fee,
		PayMillis: pay, PayBy: now + int64(k.Window)}
	if req.Payment == nipCO.PaymentLightning {
		// A signed BOLT11 invoice for exactly pay_millis, expiring at pay_by
		// (NIP-CO §Response).
		r.PayHash = randHex(32)
		hash, _ := hex.DecodeString(r.PayHash)
		inv, err := nip57test.SignedBolt11(nip57test.Invoice{Currency: "bcrt", AmountMillis: pay, PaymentHash: hash,
			Timestamp: now, Expiry: int64(k.Window), NodePriv: b.h.NodePriv})
		if err != nil {
			return coded(nipcash.ErrCodeInternal, "invoice")
		}
		o.Invoice = inv
	} else {
		n, err := nipCO.ConfirmationsFor(k.Confirmations, pay)
		if err != nil {
			return coded(nipcash.ErrCodeInternal, "tiers")
		}
		// A fresh address, never given out before or again.
		prog, _ := hex.DecodeString(randHex(20))
		o.Address, o.Confirmations = segwitAddress(0, prog), n
		r.Script = hex.EncodeToString(nipcash.WitnessScript(0, prog))
		if b.address != "" {
			o.Address = b.address
		}
	}
	if !nipcash.CommitAllowed(c.Envelope.NotAfter, c.Now.Unix()) {
		return nil
	}
	r.Order, r.Notified = o, noticeKey(o.State, 0)
	b.orders[req.RequestID] = r
	b.persistLocked(r)
	raw, _ := json.Marshal(o)
	return &transport.Result{Result: raw}
}

func noticeKey(st nipCO.OrderState, bills int) string { return string(st) + ":" + strconv.Itoa(bills) }

// currentLocked is r as it stands at now: its state, and each bill's token, or
// its tombstone once the ledger destroyed it.
func (b *OrderBook) currentLocked(r *orderRecord, now int64) nipCO.Order {
	cur := r.Order
	cur.State = r.state(now)
	cur.Bills = slices.Clone(r.Order.Bills)
	if l := b.ledger(); l != nil {
		l.mu.Lock()
		for i, bill := range cur.Bills {
			if lb := l.bills[bill.WalletPubkey]; lb != nil && lb.destroyed {
				ts := l.tombstoneLocked(lb, "")
				cur.Bills[i].Token = nipcash.TokenOrTombstone{Tombstone: &ts}
			}
		}
		l.mu.Unlock()
	}
	return cur
}

func (b *OrderBook) lookup(c ItemCtx, conn *orderConn, signer string, proofErr error) *transport.Result {
	var lr nipcash.CashLookupRequest
	if err := json.Unmarshal(c.Item.Params, &lr); err != nil || lr.Validate() != nil || lr.RequestID == "" {
		return coded(nipcash.ErrCodeBadRequest, "lookup")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.nowLocked()
	r, ok := b.orders[lr.RequestID]
	if !ok || r.Conn != conn.xonly {
		d := nipcash.DecideLookup(nipcash.LookupInput{Now: now, Deadline: lr.Deadline, Horizon: b.h.Limits.MaxRequestAgeSeconds})
		out := map[string]any{"status": d.Status}
		if d.Status == nipcash.LookupPending {
			out["retry_after"] = d.RetryAfter
		}
		raw, _ := json.Marshal(out)
		return &transport.Result{Result: raw}
	}
	if proofErr != nil || signer != r.BuyerPub {
		return coded(nipcash.ErrCodeUnauthorized, "not the order's buyer key")
	}
	raw, _ := json.Marshal(b.currentLocked(r, now))
	out, _ := json.Marshal(map[string]any{"status": "done", "result": json.RawMessage(raw)})
	return &transport.Result{Result: out}
}

// findLocked is the order placed under ref, or carrying ref as its invoice or
// address.
func (b *OrderBook) findLocked(ref string) *orderRecord {
	if r, ok := b.orders[ref]; ok {
		return r
	}
	for _, r := range b.orders {
		if r.Order.Invoice == ref || (r.Order.Address != "" && strings.EqualFold(r.Order.Address, ref)) {
			return r
		}
	}
	return nil
}

// PayInvoice pays the invoice of a Lightning order, named by its request_id or
// its invoice, with millis (more or less than asked). An invoice past pay_by has
// expired and cannot be paid, and an invoice is paid once; either is logged and
// nothing happens. The payment mints at once unless the signer is broken.
func (b *OrderBook) PayInvoice(t testing.TB, ref string, millis uint64) {
	t.Helper()
	b.Tick()
	b.mu.Lock()
	r := b.findLocked(ref)
	switch {
	case r == nil || r.Order.Payment != nipCO.PaymentLightning:
		b.mu.Unlock()
		t.Fatalf("cashtest: no Lightning order %s", ref)
	case b.nowLocked() > r.Order.PayBy:
		b.mu.Unlock()
		t.Logf("cashtest: the invoice of %s expired at pay_by; the payment fails", r.RID)
		return
	case len(r.Payments) > 0:
		b.mu.Unlock()
		t.Logf("cashtest: the invoice of %s is already paid", r.RID)
		return
	}
	r.Payments[r.PayHash] = &orderPayment{Millis: millis, SeenAt: b.nowLocked()}
	b.persistLocked(r)
	b.mu.Unlock()
	b.Tick()
}

// PayAddress pays an on-chain order, named by its request_id or its address,
// with one output of millis (a multiple of 1000) in a transaction broadcast to
// the mempool, and returns the output's outpoint (txid:vout). It is minted once
// mined to its tier (Mine).
func (b *OrderBook) PayAddress(t testing.TB, ref string, millis uint64) string {
	t.Helper()
	if millis%1000 != 0 || millis/1000 > payerCoinSats-payerFeeSats {
		t.Fatalf("cashtest: cannot pay %d millis on chain", millis)
	}
	b.Tick()
	b.mu.Lock()
	var script []byte
	if r := b.findLocked(ref); r != nil && r.Script != "" {
		script, _ = hex.DecodeString(r.Script)
	} else if v, prog, err := nipcash.DecodeWitnessAddress(ref, FakeAddressHRP); err == nil {
		script = nipcash.WitnessScript(v, prog) // an address whose order the Hub deleted
	} else {
		b.mu.Unlock()
		t.Fatalf("cashtest: no on-chain order %s", ref)
	}
	empty := len(b.payerCoins) == 0
	b.mu.Unlock()
	if empty {
		b.fundPayer()
	}
	b.mu.Lock()
	coin := b.payerCoins[0]
	b.payerCoins = b.payerCoins[1:]
	b.mu.Unlock()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: coin, Sequence: 0xffffffff})
	tx.AddTxOut(wire.NewTxOut(int64(millis/1000), script))
	tx.AddTxOut(wire.NewTxOut(int64(payerCoinSats-payerFeeSats-millis/1000), b.payerScript))
	if err := b.chain.Broadcast(tx); err != nil {
		t.Fatalf("cashtest: broadcast a payment: %v", err)
	}
	op := wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	b.mu.Lock()
	b.outputs = append(b.outputs, chainOutput{op: op, script: hex.EncodeToString(script), millis: millis})
	b.mu.Unlock()
	b.Tick()
	return op.String()
}

type orderNotice struct{ relay, notify string }

// Tick is the Hub's order engine: it reads the chain, decides each on-chain
// order at pay_by, deletes the unpaid ones when due, mints what is ready, and
// publishes a notice for every order whose state or bills changed.
func (b *OrderBook) Tick() {
	b.mu.Lock()
	now := b.nowLocked()
	var notices []orderNotice
	for _, rid := range slices.Sorted(maps.Keys(b.orders)) {
		r := b.orders[rid]
		if r.Order.Payment == nipCO.PaymentOnchain {
			if !r.Decided && now > r.Order.PayBy {
				r.Decided, r.Watched = true, len(r.Payments) > 0
				if !r.Watched {
					r.DeleteAt = nipCO.UnpaidOnchainDeleteAt(r.Order.PayBy, r.Deadline, b.h.Limits.MaxRequestAgeSeconds)
				}
			}
			if r.Decided && !r.Watched {
				if now >= r.DeleteAt {
					delete(b.orders, rid)
					delete(b.store, rid)
					continue
				}
			} else {
				b.scanLocked(r, now)
			}
		}
		b.mintLocked(r)
		if key := noticeKey(r.state(now), len(r.Order.Bills)); key != r.Notified {
			r.Notified = key
			notices = append(notices, orderNotice{r.Relay, r.Notify})
		}
		b.persistLocked(r)
	}
	b.mu.Unlock()
	for _, n := range notices {
		b.publishNotice(n)
	}
}

// scanLocked reads the outputs paying r's address: a new one is a payment seen;
// one no longer in the mempool nor in a block, and not minted, is forgotten.
func (b *OrderBook) scanLocked(r *orderRecord, now int64) {
	for _, out := range b.outputs {
		if out.script != r.Script {
			continue
		}
		key := out.op.String()
		p := r.Payments[key]
		if p != nil && p.Minted {
			continue
		}
		depth := b.chain.Depth(out.op.Hash)
		if depth == 0 && !b.chain.InMempool(out.op.Hash) {
			delete(r.Payments, key)
			continue
		}
		if p == nil {
			p = &orderPayment{Millis: out.millis, SeenAt: now}
			r.Payments[key] = p
		}
		p.Depth = depth
	}
}

// mintLocked mints r's ready payments, each once.
func (b *OrderBook) mintLocked(r *orderRecord) {
	if b.signerBroken {
		return
	}
	keys := slices.SortedFunc(maps.Keys(r.Payments), func(x, y string) int {
		return cmp.Or(cmp.Compare(r.Payments[x].SeenAt, r.Payments[y].SeenAt), strings.Compare(x, y))
	})
	var maxMillis uint64
	if k := r.Terms.Kind(r.Order.Payment); k != nil {
		maxMillis = k.MaxMillis
	}
	for _, key := range keys {
		p := r.Payments[key]
		if p.Minted {
			continue
		}
		outpoint := ""
		if r.Order.Payment == nipCO.PaymentOnchain {
			n, err := nipCO.ConfirmationsFor(r.Terms.Onchain.Confirmations, p.Millis)
			if err != nil || p.Depth < max(n, 1) {
				continue
			}
			outpoint = key
		}
		var bills []nipCO.OrderBill
		for _, amount := range nipCO.MintSplit(p.Millis, r.Order.FeeMillis, maxMillis) {
			wallet, token, err := b.mintBill(r, amount)
			if err != nil {
				return // the order stays paid; the next tick retries
			}
			bills = append(bills, nipCO.OrderBill{WalletPubkey: wallet, Token: nipcash.TokenOrTombstone{Token: token},
				AmountMillis: amount, PaidMillis: p.Millis, Outpoint: outpoint})
		}
		p.Minted, p.Bills = true, len(bills)
		r.Order.Bills = append(r.Order.Bills, bills...)
	}
}

// mintBill builds one bill of amount for r's recipient: an ordered ledger
// slice with no expiry and the terms' bill object when the Hub has a ledger,
// else a bare token.
func (b *OrderBook) mintBill(r *orderRecord, amount uint64) (wallet, token string, err error) {
	l := b.ledger()
	if l == nil {
		return b.h.newToken(amount)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rp := r.Recipient
	rp.AmountMillis = amount
	bill, err := l.newBillLocked([]nipcash.RecipientParam{rp}, nil, nil)
	if err != nil {
		return "", "", err
	}
	s := bill.slices[0]
	s.ordered = true
	if bt := r.Terms.Bill; bt != (nipCO.BillTerms{}) {
		s.redeemBase, s.redeemPpm, s.minTransfer = bt.RedeemFeeBase, bt.RedeemFeePpm, bt.MinTransferMillis
	}
	return bill.wallet, bill.token, nil
}

// publishNotice publishes an order notice on the relay the order arrived on,
// or on every relay for an order handed to Serve.
func (b *OrderBook) publishNotice(n orderNotice) {
	ev, err := nipCO.NewOrderNotice(n.notify)
	if err != nil {
		return
	}
	for _, r := range b.h.Relays {
		if n.relay == "" || r.URL() == n.relay {
			r.Publish(ev)
		}
	}
}

// newToken is a bill token of amount signed by the node identity under
// cash-mint:v1, for a fresh wallet.
func (h *FakeHub) newToken(amount uint64) (wallet, token string, err error) {
	_, wallet = mustKeypair()
	secret, _ := mustKeypair()
	sign, err := nipcash.LocalMintSigner(h.NodePriv, "satscash")
	if err != nil {
		return "", "", err
	}
	tok, err := nipcash.SignToken(nipcash.Token{HRP: "satscash", WalletPubkey: wallet, Secret: secret,
		RelayURLs: h.RelayURLs(), AttestedAmountMillis: &amount}, nipcash.SchemeMintV1, nil, h.nodeXOnly, sign)
	if err != nil {
		return "", "", err
	}
	s, err := nipcash.Encode(tok)
	return wallet, s, err
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cashtest: %v", err))
	}
	return hex.EncodeToString(b)
}
