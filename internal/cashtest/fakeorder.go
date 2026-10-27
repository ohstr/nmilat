package cashtest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

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

// OrderBook is the fake Hub's NIP-CO side: one Order connection, its get_info
// terms on the kind-23194 connection, cash_order and its lookups on the private
// transport, decided through nipCO's Hub helpers. Payments are made by the test
// (PayInvoice, PayAddress); each mints its bills at once and publishes an order
// notice.
type OrderBook struct {
	h *FakeHub

	connPriv, connXOnly string
	connSecret          string

	mu    sync.Mutex
	terms json.RawMessage
	// Retired answers get_info with "cash_order": {} and refuses new orders.
	retired bool
	// InfoPubkey and InfoChain, when set, replace get_info's pubkey and chain.
	infoPubkey, infoChain string
	// OpenCeiling is the open-order ceiling per kind (default 10^12 millis).
	openCeiling uint64
	// beforeReply runs after an order is checked and before its reply is built.
	beforeReply func()
	address     string
	used        map[string]bool
	orders      map[string]*fakeOrder
	nwcCalls    map[string]int
}

type fakeOrder struct {
	order    nipCO.Order
	buyerPub string
	notify   string
	deadline int64
	seen     bool
	minted   int
}

// ServeOrders gives the Hub an Order connection selling under terms (a get_info
// cash_order object) and returns its book.
func (h *FakeHub) ServeOrders(t testing.TB, terms string) *OrderBook {
	t.Helper()
	b := &OrderBook{h: h, terms: json.RawMessage(terms), openCeiling: 1_000_000_000_000,
		used: map[string]bool{}, orders: map[string]*fakeOrder{}, nwcCalls: map[string]int{}}
	b.connPriv, b.connXOnly = Keypair(t)
	b.connSecret, _ = Keypair(t)
	prev := h.Decide
	h.Decide = func(c ItemCtx) *transport.Result {
		if c.Item.Target == b.connXOnly {
			return b.decide(c)
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

// SignedOrderConnection is the book's Order connection record, signed by the
// node identity: what the Hub lists (a listing is built from records, never
// from a string).
func (b *OrderBook) SignedOrderConnection(t testing.TB) nipCO.OrderConnection {
	t.Helper()
	sign, err := nipcash.LocalChainSigner(b.h.NodePriv, FakeChain)
	if err != nil {
		t.Fatal(err)
	}
	c, err := nipCO.SignOrderConnection(nipCO.OrderConnection{Pubkey: b.connXOnly, Relays: b.h.RelayURLs(),
		Secret: b.connSecret, Label: "fake counter", HasLabel: true, HubIdentity: b.h.nodeXOnly, Chain: FakeChain},
		sign, b.h.nodeXOnly)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// OrderConnection is the book's cashorder1 string, signed by the node identity.
func (b *OrderBook) OrderConnection(t testing.TB) string {
	t.Helper()
	s, err := nipCO.EncodeOrderConnection(b.SignedOrderConnection(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// SetTerms replaces the get_info cash_order object.
func (b *OrderBook) SetTerms(terms string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.terms = json.RawMessage(terms)
}

// Retire retires the connection: get_info answers "cash_order": {} at once and
// new orders are refused RESTRICTED; lookups are still served.
func (b *OrderBook) Retire() { b.mu.Lock(); b.retired = true; b.mu.Unlock() }

// SetInfoIdentity makes get_info report pubkey and chain instead of the node's
// (online-check cases).
func (b *OrderBook) SetInfoIdentity(pubkey, chain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.infoPubkey, b.infoChain = pubkey, chain
}

// SetOpenCeiling sets the open-order ceiling per kind.
func (b *OrderBook) SetOpenCeiling(millis uint64) { b.mu.Lock(); b.openCeiling = millis; b.mu.Unlock() }

// BeforeReply runs f while an accepted order is being placed, before its reply
// is built: a test changes the terms there.
func (b *OrderBook) BeforeReply(f func()) { b.mu.Lock(); b.beforeReply = f; b.mu.Unlock() }

// SetAddress makes every new on-chain order reply carry addr (invalid-reply
// cases); "" restores fresh addresses.
func (b *OrderBook) SetAddress(addr string) { b.mu.Lock(); b.address = addr; b.mu.Unlock() }

// NWCCalls counts the kind-23194 requests the Order connection got, by method.
func (b *OrderBook) NWCCalls(method string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nwcCalls[method]
}

// Order returns the order placed under requestID.
func (b *OrderBook) Order(requestID string) (nipCO.Order, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.orders[requestID]
	if !ok {
		return nipCO.Order{}, false
	}
	return o.order, true
}

// Orders counts the orders placed.
func (b *OrderBook) Orders() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.orders) }

func (b *OrderBook) onEvent(r *Relay, ev *nip01.Event) {
	if ev.Kind != kindNWCRequest || !taggedP(ev, b.connXOnly) {
		return
	}
	appXOnly, err := utils.GetPublicKey(b.connSecret)
	if err != nil || ev.PubKey != appXOnly {
		return
	}
	req, err := nip47.ParseRequestEvent(ev, b.connPriv)
	if err != nil {
		return
	}
	encryption := nip47.EncryptionNIP04
	if enc, err := utils.FindUniqueEventTagValue(ev.Tags, "encryption"); err == nil && enc != "" {
		encryption = enc
	}
	b.mu.Lock()
	b.nwcCalls[req.Method]++
	terms := b.terms
	if b.retired {
		terms = json.RawMessage(`{}`)
	}
	pubkey, chain := b.h.nodeXOnly, FakeChain
	if b.infoPubkey != "" || b.infoChain != "" {
		pubkey, chain = b.infoPubkey, b.infoChain
	}
	b.mu.Unlock()
	var resp *nip01.Event
	if req.Method == "get_info" {
		resp, err = nip47.NewResponseEvent(b.connPriv, ev.PubKey, req.Method, map[string]any{
			"methods": []string{"get_info"}, "private_methods": OrderPrivateMethods,
			"pubkey": pubkey, "network": FakeNetwork, "chain": chain, "cash_order": terms,
		}, ev, encryption)
	} else {
		resp, err = nip47.NewErrorResponseEvent(b.connPriv, ev.PubKey, req.Method, nip47.Error{
			Code: "NOT_IMPLEMENTED", Message: req.Method + " is not served on an Order connection",
		}, ev, encryption)
	}
	if err != nil {
		b.h.t.Errorf("cashtest: order nwc response: %v", err)
		return
	}
	if err := resp.Sign(b.connPriv); err != nil {
		b.h.t.Errorf("cashtest: sign order nwc response: %v", err)
		return
	}
	r.Publish(resp)
}

func coded(code, msg string) *transport.Result {
	return &transport.Result{Error: &transport.ResultError{Code: code, Message: msg}}
}

// decide serves one item targeting the Order connection: I8, steps 1 to 8 of
// NIP-CO §Processing Algorithm, and cash_lookup. A bill proof not signed by the
// connection secret is omitted (I2).
func (b *OrderBook) decide(c ItemCtx) *transport.Result {
	hash, err := transport.CanonicalParamsHash(c.Item.Params)
	if err != nil {
		return coded(nipcash.ErrCodeBadRequest, "params")
	}
	binding := transport.ProofBinding{Target: c.Item.Target, HubXOnly: b.h.nodeXOnly, Method: c.Item.Method,
		ParamsHash: hash, Nonce: c.Envelope.Nonce, NotAfter: c.Envelope.NotAfter}
	connPub, _ := utils.GetPublicKey(b.connSecret)
	if signer, err := transport.VerifyBillProof(c.Item.BillProof, binding, c.Now); err != nil || signer != connPub {
		return nil
	}
	if len(c.Item.Proof) == 0 {
		return coded(nipcash.ErrCodeBadRequest, "an order item carries a proof")
	}
	signer, proofErr := transport.VerifyItemProof(c.Item.Proof, binding, c.Now)
	switch c.Item.Method {
	case nipcash.MethodCashOrder:
		return b.place(c, signer, proofErr)
	case nipcash.MethodCashLookup:
		return b.lookup(c, signer, proofErr)
	}
	return coded(nipcash.ErrCodeNotImplemented, c.Item.Method+" is not served on an Order connection")
}

func (b *OrderBook) place(c ItemCtx, signer string, proofErr error) *transport.Result {
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
	var open uint64
	for _, o := range b.orders {
		if o.order.Payment == req.Payment && o.minted == 0 && c.Now.Unix() <= o.order.PayBy {
			open += o.order.AmountMillis
		}
	}
	if err := nipCO.CheckPlacement(req, nipCO.PlacementInput{Terms: *terms, Retired: b.retired, IATrusted: trusted,
		OpenMillis: open, OpenCeiling: b.openCeiling, LightningReceivable: true}); err != nil {
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
			k = t2.Kind(req.Payment)
		}
	}
	o := nipCO.Order{State: nipCO.OrderOpen, Payment: req.Payment, AmountMillis: req.AmountMillis, FeeMillis: fee,
		PayMillis: pay, PayBy: c.Now.Unix() + int64(k.Window)}
	if req.Payment == nipCO.PaymentLightning {
		// A signed BOLT11 invoice for exactly pay_millis, expiring at pay_by
		// (NIP-CO §Response).
		hash, _ := hex.DecodeString(randHex(32))
		inv, err := nip57test.SignedBolt11(nip57test.Invoice{Currency: "bcrt", AmountMillis: pay, PaymentHash: hash,
			Timestamp: c.Now.Unix(), Expiry: int64(k.Window), NodePriv: b.h.NodePriv})
		if err != nil {
			return coded(nipcash.ErrCodeInternal, "invoice")
		}
		o.Invoice = inv
	} else {
		n, err := nipCO.ConfirmationsFor(k.Confirmations, pay)
		if err != nil {
			return coded(nipcash.ErrCodeInternal, "tiers")
		}
		o.Address, o.Confirmations = fakeAddress(), n
		if b.address != "" {
			o.Address = b.address
		}
	}
	if !nipcash.CommitAllowed(c.Envelope.NotAfter, c.Now.Unix()) {
		return nil
	}
	b.orders[req.RequestID] = &fakeOrder{order: o, buyerPub: signer, notify: req.Notify, deadline: c.Envelope.NotAfter}
	raw, _ := json.Marshal(o)
	return &transport.Result{Result: raw}
}

func (b *OrderBook) lookup(c ItemCtx, signer string, proofErr error) *transport.Result {
	var lr nipcash.CashLookupRequest
	if err := json.Unmarshal(c.Item.Params, &lr); err != nil || lr.Validate() != nil || lr.RequestID == "" {
		return coded(nipcash.ErrCodeBadRequest, "lookup")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.orders[lr.RequestID]
	if !ok {
		return &transport.Result{Result: json.RawMessage(`{"status":"unknown"}`)}
	}
	if proofErr != nil || signer != o.buyerPub {
		return coded(nipcash.ErrCodeUnauthorized, "not the order's buyer key")
	}
	cur := o.order
	cur.State = nipCO.OrderStateAt(nipCO.OrderFacts{Payment: cur.Payment, PayBy: cur.PayBy, Seen: o.seen,
		Minted: o.minted}, c.Now.Unix())
	raw, _ := json.Marshal(cur)
	out, _ := json.Marshal(map[string]any{"status": "done", "result": json.RawMessage(raw)})
	return &transport.Result{Result: out}
}

// PayInvoice pays the Lightning order placed under requestID with millis:
// minted at once (received − fee, split at max_millis), and a notice published.
func (b *OrderBook) PayInvoice(t testing.TB, requestID string, millis uint64) {
	t.Helper()
	b.pay(t, requestID, millis, "")
}

// PayAddress pays the on-chain order placed under requestID with one output of
// millis, minted at once, and returns its outpoint.
func (b *OrderBook) PayAddress(t testing.TB, requestID string, millis uint64) string {
	t.Helper()
	outpoint := randHex(32) + ":0"
	b.pay(t, requestID, millis, outpoint)
	return outpoint
}

func (b *OrderBook) pay(t testing.TB, requestID string, millis uint64, outpoint string) {
	b.mu.Lock()
	o, ok := b.orders[requestID]
	if !ok {
		b.mu.Unlock()
		t.Fatalf("cashtest: no order %s", requestID)
	}
	terms, err := nipCO.ParseOrderInfo(b.terms)
	if err != nil {
		b.mu.Unlock()
		t.Fatal(err)
	}
	maxMillis := uint64(0)
	if k := terms.Kind(o.order.Payment); k != nil {
		maxMillis = k.MaxMillis
	}
	o.seen = true
	for _, amount := range nipCO.MintSplit(millis, o.order.FeeMillis, maxMillis) {
		wallet, token := b.h.mintToken(t, amount)
		o.order.Bills = append(o.order.Bills, nipCO.OrderBill{WalletPubkey: wallet,
			Token: nipcash.TokenOrTombstone{Token: token}, AmountMillis: amount, PaidMillis: millis, Outpoint: outpoint})
		o.minted++
	}
	notify := o.notify
	b.mu.Unlock()
	ev, err := nipCO.NewOrderNotice(notify)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.h.Relays {
		r.Publish(ev)
	}
}

// mintToken is a bill token signed by the node identity under cash-mint:v1.
func (h *FakeHub) mintToken(t testing.TB, amount uint64) (wallet, token string) {
	_, wallet = Keypair(t)
	secret, _ := Keypair(t)
	sign, err := nipcash.LocalMintSigner(h.NodePriv, "satscash")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := nipcash.SignToken(nipcash.Token{HRP: "satscash", WalletPubkey: wallet, Secret: secret,
		RelayURLs: h.RelayURLs(), AttestedAmountMillis: &amount}, nipcash.SchemeMintV1, nil, h.nodeXOnly, sign)
	if err != nil {
		t.Fatal(err)
	}
	s, err := nipcash.Encode(tok)
	if err != nil {
		t.Fatal(err)
	}
	return wallet, s
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cashtest: %v", err))
	}
	return hex.EncodeToString(b)
}

// fakeAddress is a fresh P2WPKH address under FakeAddressHRP.
func fakeAddress() string {
	prog := make([]byte, 20)
	if _, err := rand.Read(prog); err != nil {
		panic(fmt.Sprintf("cashtest: %v", err))
	}
	conv, err := bech32.ConvertBits(prog, 8, 5, true)
	if err != nil {
		panic(err)
	}
	s, err := bech32.Encode(FakeAddressHRP, append([]byte{0}, conv...))
	if err != nil {
		panic(err)
	}
	return s
}
