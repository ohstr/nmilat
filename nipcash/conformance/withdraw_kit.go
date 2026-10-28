package conformance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcash/transport"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

// The withdrawal cases' kit: bills minted over the Hub's Cash Hub connection,
// and quotes, calls, lookups and cancel requests sent through the SDK's batch
// session (which runs none of the client's local checks) or hand-built.

// memJournal is an in-memory client.Journal.
type memJournal struct {
	mu    sync.Mutex
	calls map[string]nipcash.PendingCall
}

func newMemJournal() *memJournal { return &memJournal{calls: map[string]nipcash.PendingCall{}} }

func (j *memJournal) WriteAhead(_ context.Context, calls []nipcash.PendingCall) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range calls {
		j.calls[c.RequestID] = c
	}
	return nil
}
func (j *memJournal) RecordDerived(context.Context, string, int64) error  { return nil }
func (j *memJournal) DerivedPlaced(context.Context, string) (bool, error) { return false, nil }

func (j *memJournal) call(rid string) (nipcash.PendingCall, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	c, ok := j.calls[rid]
	return c, ok
}

func ctx15() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// wdState is the suite's withdrawal state, built once.
type wdState struct {
	once    sync.Once
	err     error
	hub     *client.HubClient
	session *client.BatchSession

	offerOnce sync.Once
	offerErr  error
	offered   bool
	why       string               // why the suite reads no offer
	billInfo  *nip47.GetInfoResult // get_info on the probe bill's own connection
}

// withdrawals skips a case unless the Hub offers withdrawals, and returns its
// batch session.
func (s *suite) withdrawals(t *testing.T) *client.BatchSession {
	t.Helper()
	if !s.offersWithdrawals(t) {
		t.Skip("the Hub does not offer on-chain withdrawals: " + s.wd.why)
	}
	return s.wdSession(t)
}

// offersWithdrawals reports whether the Hub offers on-chain withdrawals, read
// once. cash_withdraw_quote and cash_withdraw are methods of a Cash Wallet
// connection under its cash_redeem scope (NIP-CASH §Methods), and a Hub SHOULD
// derive private_methods from what each connection was granted (§Scope
// Surface): a Hub offering them lists them on its bills' connections, not
// necessarily on the Cash Hub connection, whose only scope is cash_hub. So a
// Cash Hub connection listing them is read as the offer, and otherwise the
// suite mints a probe bill and reads its own get_info.
func (s *suite) offersWithdrawals(t *testing.T) bool {
	t.Helper()
	s.wd.offerOnce.Do(func() {
		if slices.Contains(s.info.PrivateMethods, nipcash.MethodCashWithdrawQuote) {
			s.wd.offered = true
			return
		}
		if !slices.Contains(s.info.Methods, nipcash.MethodMintCash) {
			s.wd.why = "the Cash Hub connection lists no withdrawal method and does not serve mint_cash, so the suite cannot read a bill's get_info"
			return
		}
		s.wd.billInfo, s.wd.offerErr = s.probeBillInfo(t)
		if s.wd.offerErr != nil {
			return
		}
		s.wd.offered = slices.Contains(s.wd.billInfo.PrivateMethods, nipcash.MethodCashWithdrawQuote)
		if !s.wd.offered {
			s.wd.why = "neither the Cash Hub connection's nor a bill's get_info lists cash_withdraw_quote"
		}
	})
	if s.wd.offerErr != nil {
		t.Fatalf("withdrawal offer: %v", s.wd.offerErr)
	}
	return s.wd.offered
}

// probeBillInfo mints a one-slice bill and returns get_info on its own
// connection. With a Payee it then redeems the bill, so that no live bill of
// the suite's own outlasts a case that ends the Hub (CT-WD-24); otherwise a
// short expiry hands its value back soon.
func (s *suite) probeBillInfo(t *testing.T) (*nip47.GetInfoResult, error) {
	t.Helper()
	s.wdSession(t)
	ctx, cancel := ctx15()
	defer cancel()
	priv, pub := keypair(t)
	res, err := s.wd.hub.MintCash(ctx, nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(pub), wdAmount)}, Expiry: time.Hour},
		newMemJournal(), "conformance")
	if err != nil {
		return nil, fmt.Errorf("mint_cash for a probe bill: %w", err)
	}
	tok, err := nipcash.Decode(res.CashToken)
	if err != nil {
		return nil, fmt.Errorf("probe bill token: %w", err)
	}
	gi, err := s.billGetInfo(tok)
	if err != nil {
		return nil, err
	}
	if payee, ok := s.h.(Payee); ok {
		h := s.holderOf(t, tok)
		h.priv, h.cred, h.amount = priv, nipcash.BySigning(priv), wdAmount
		net := s.status(t, h, nipcash.ScopeMine).Recipients[0].NetRedeemableMillis
		rctx, rcancel := ctx15()
		defer rcancel()
		outs, err := s.wd.session.RedeemMany(rctx, []client.BatchRedeem{{ID: "1", Bill: h.bill,
			Params: nipcash.CashRedeemParams{Invoice: payee.Invoice(t, net), Credential: h.cred}}})
		if err != nil || len(outs) != 1 || outs[0].Result == nil {
			t.Logf("the probe bill was not redeemed (%v %+v); it expires in an hour", err, outs)
		}
	}
	return gi, nil
}

// billGetInfo is get_info on a bill's own Cash Wallet connection.
func (s *suite) billGetInfo(tok nipcash.Token) (*nip47.GetInfoResult, error) {
	ctx, cancel := ctx15()
	defer cancel()
	nwc, err := relayclient.NewNWCClient(ctx, &nip47.PairingInfo{WalletPubkey: tok.WalletPubkey, RelayURLs: tok.RelayURLs, Secret: tok.Secret},
		nip47.EncryptionNIP44V2)
	if err != nil {
		return nil, fmt.Errorf("open the bill's connection: %w", err)
	}
	defer nwc.Close()
	gi, err := nwc.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("get_info on the bill's connection: %w", err)
	}
	return gi, nil
}

func (s *suite) wdSession(t *testing.T) *client.BatchSession {
	t.Helper()
	s.wd.once.Do(func() {
		ctx, cancel := ctx15()
		defer cancel()
		s.wd.hub, s.wd.err = client.ConnectCashHub(context.Background(), s.h.CashHubConnection())
		if s.wd.err != nil {
			return
		}
		s.wd.session, s.wd.err = client.OpenBatchSession(ctx, s.nodeXOnly, s.relays)
	})
	if s.wd.err != nil {
		t.Fatalf("withdrawal kit: %v", s.wd.err)
	}
	return s.wd.session
}

// holder is one slice of a minted bill and how to prove it.
type holder struct {
	tok    nipcash.Token
	bill   client.Bill
	priv   string // the slice key (pubkey, or the attestation's p)
	secret string // a cash-mode slice's secret
	att    *nipIC.Attestation
	iaPriv string
	cred   nipcash.Credential
	amount uint64
}

// mint mints a bill over the Cash Hub connection and returns its token. It
// skips when the connection does not serve mint_cash.
func (s *suite) mint(t *testing.T, expiry time.Duration, allocs ...nipcash.Allocation) nipcash.Token {
	t.Helper()
	s.wdSession(t)
	if !slices.Contains(s.info.Methods, nipcash.MethodMintCash) {
		t.Skip("the Cash Hub connection does not serve mint_cash, so the suite cannot make a bill")
	}
	ctx, cancel := ctx15()
	defer cancel()
	res, err := s.wd.hub.MintCash(ctx, nipcash.MintCashParams{Recipients: allocs, Expiry: expiry}, newMemJournal(), "conformance")
	if err != nil {
		t.Fatalf("mint_cash: %v", err)
	}
	tok, err := nipcash.Decode(res.CashToken)
	if err != nil {
		t.Fatalf("minted token: %v", err)
	}
	return tok
}

func (s *suite) holderOf(t *testing.T, tok nipcash.Token) holder {
	t.Helper()
	b, err := client.BillFor(tok)
	if err != nil {
		t.Fatal(err)
	}
	return holder{tok: tok, bill: b}
}

// pubkeyBill mints a one-slice pubkey bill of amount.
func (s *suite) pubkeyBill(t *testing.T, amount uint64, expiry time.Duration) holder {
	t.Helper()
	priv, pub := keypair(t)
	h := s.holderOf(t, s.mint(t, expiry, nipcash.Send(nipcash.Pubkey(pub), amount)))
	h.priv, h.cred, h.amount = priv, nipcash.BySigning(priv), amount
	return h
}

// pubkeyPair mints a bill of two pubkey slices, a and b.
func (s *suite) pubkeyPair(t *testing.T, amount uint64) (holder, holder) {
	t.Helper()
	pa, xa := keypair(t)
	pb, xb := keypair(t)
	tok := s.mint(t, 0, nipcash.Send(nipcash.Pubkey(xa), amount), nipcash.Send(nipcash.Pubkey(xb), amount))
	a, b := s.holderOf(t, tok), s.holderOf(t, tok)
	a.priv, a.cred, a.amount = pa, nipcash.BySigning(pa), amount
	b.priv, b.cred, b.amount = pb, nipcash.BySigning(pb), amount
	return a, b
}

// cashBill mints a cash-mode bill of amount.
func (s *suite) cashBill(t *testing.T, amount uint64) holder {
	t.Helper()
	target, err := nipcash.NewCashTarget()
	if err != nil {
		t.Fatal(err)
	}
	h := s.holderOf(t, s.mint(t, 0, nipcash.Send(target, amount)))
	h.secret, h.cred, h.amount = target.Secret(), nipcash.BySecret(target.Secret()), amount
	return h
}

// ckBill mints a connection_key bill of amount, its IA trusted.
func (s *suite) ckBill(t *testing.T, amount uint64) holder {
	t.Helper()
	iaPriv, iaPub := keypair(t)
	priv, pub := keypair(t)
	s.h.TrustIA(t, iaPub, true)
	key, err := nipIC.NewConnectionKey("discord", "12345")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{PrivateKey: iaPriv, ConnectionKey: key, UserPubkey: pub,
		Platform: "discord", ExpirationDays: 30, AuthType: "email_code", Evidence: nipIC.Evidence{Platform: "discord", UserID: "12345"}})
	if err != nil {
		t.Fatal(err)
	}
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	id, err := nipcash.ConnectionKeyFromAttestation(att)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := nipcash.BySigningConnectionKey(priv, att)
	if err != nil {
		t.Fatal(err)
	}
	h := s.holderOf(t, s.mint(t, 0, nipcash.Send(id, amount)))
	h.priv, h.att, h.iaPriv, h.cred, h.amount = priv, att, iaPriv, cred, amount
	return h
}

// wdTerms reads the Hub's withdrawal terms with h's cash_status.
func (s *suite) wdTerms(t *testing.T, h holder) *nipcash.WithdrawTerms {
	t.Helper()
	st := s.status(t, h, nipcash.ScopeMine)
	if st.Withdraw == nil {
		t.Fatalf("cash_status carries no withdraw object while the Hub lists the withdrawal methods")
	}
	return st.Withdraw
}

// status is h's cash_status under scope.
func (s *suite) status(t *testing.T, h holder, scope string) *nipcash.CashStatusResult {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	cred := h.cred
	if h.secret != "" {
		cred = nipcash.BySecret(h.secret)
	}
	outs, err := s.wd.session.StatusMany(ctx, []client.BatchStatus{{ID: "1", Bill: h.bill, Credential: cred, Scope: scope}})
	if err != nil || len(outs) != 1 || outs[0].Result == nil {
		t.Fatalf("cash_status: %v %+v", err, outs)
	}
	return outs[0].Result
}

// hrp is the witness HRP of the Hub's network.
func (s *suite) hrp(t *testing.T) string {
	t.Helper()
	hrps, ok := nipcash.WithdrawHRPs(s.info.Chain)
	if !ok || len(hrps) < 3 {
		t.Skipf("no address table for chain %q", s.info.Chain)
	}
	switch s.info.Network {
	case "mainnet":
		return hrps[0]
	case "testnet":
		return hrps[1]
	case "regtest":
		return hrps[2]
	}
	t.Skipf("no witness HRP known for network %q", s.info.Network)
	return ""
}

// otherHRP is a witness HRP of another network of the same coin.
func (s *suite) otherHRP(t *testing.T) string {
	t.Helper()
	own := s.hrp(t)
	hrps, _ := nipcash.WithdrawHRPs(s.info.Chain)
	for _, h := range hrps {
		if h != own {
			return h
		}
	}
	t.Skip("the coin has one network")
	return ""
}

// address is an address of script type st on the Hub's network that the Hub
// does not control.
func (s *suite) address(t *testing.T, st nipcash.ScriptType) string {
	t.Helper()
	if c, ok := s.h.(WithdrawChain); ok {
		return c.ExternalAddress(t, st)
	}
	return witnessAddress(t, s.hrp(t), st)
}

func witnessAddress(t *testing.T, hrp string, st nipcash.ScriptType) string {
	t.Helper()
	prog, err := hex.DecodeString(mustKey(t)[:2*int(st.ProgramLen)])
	if err != nil || int(st.ProgramLen) > 32 {
		t.Fatalf("program of %d bytes", st.ProgramLen)
	}
	conv, err := bech32.ConvertBits(prog, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte{st.Version}, conv...)
	var addr string
	if st.Version == 0 {
		addr, err = bech32.Encode(hrp, data)
	} else {
		addr, err = bech32.EncodeM(hrp, data)
	}
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

var p2wpkh = nipcash.ScriptType{Version: 0, ProgramLen: 20}

// quote sends one cash_withdraw_quote for h and returns its outcome.
func (s *suite) quote(t *testing.T, h holder, addr string, sendBefore *int64) client.WithdrawQuoteOutcome {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wd.session.WithdrawQuoteMany(ctx, []client.BatchWithdrawQuote{{ID: "1", Bill: h.bill,
		Params: nipcash.CashWithdrawQuoteParams{Address: addr, SendBefore: sendBefore, Credential: h.cred}}})
	if err != nil || len(outs) != 1 {
		t.Fatalf("cash_withdraw_quote: %v %+v", err, outs)
	}
	return outs[0]
}

// quoteOK quotes h to addr and checks the answer as a client must.
func (s *suite) quoteOK(t *testing.T, h holder, addr string) *nipcash.WithdrawQuote {
	t.Helper()
	o := s.quote(t, h, addr, nil)
	if o.Result == nil {
		t.Fatalf("quote refused: %+v %+v", o.Error, o.Gone)
	}
	identity, ia, err := nipcash.SliceIdentity(h.cred)
	if err != nil {
		t.Fatal(err)
	}
	q, err := nipcash.VerifyQuoteAnswer(*o.Result, nipcash.QuoteExpectation{HubXOnly: s.nodeXOnly, Wallet: h.tok.WalletPubkey,
		IdentityValue: identity, IAPubkey: ia, Address: addr, AmountMillis: h.amount})
	if err != nil {
		t.Fatalf("quote answer: %v", err)
	}
	return q
}

// withdraw places one cash_withdraw of q for h and returns its outcome and the
// call written ahead.
func (s *suite) withdraw(t *testing.T, h holder, q *nipcash.WithdrawQuote) (client.WithdrawOutcome, nipcash.PendingCall) {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	j := newMemJournal()
	rid, err := nipcash.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	outs, err := s.wd.session.WithdrawMany(ctx, []client.BatchWithdraw{{ID: "1", Bill: h.bill,
		Params: nipcash.CashWithdrawParams{Quote: q, Credential: h.cred, RequestID: rid}}}, j, "conformance")
	if len(outs) != 1 {
		t.Fatalf("cash_withdraw: %v", err)
	}
	pc, _ := j.call(rid)
	return outs[0], pc
}

// withdrawOK quotes and withdraws h to addr, and returns the queued payout and
// the call.
func (s *suite) withdrawOK(t *testing.T, h holder, addr string) (*nipcash.Payout, nipcash.PendingCall) {
	t.Helper()
	q := s.quoteOK(t, h, addr)
	o, pc := s.withdraw(t, h, q)
	if o.Result == nil {
		t.Fatalf("cash_withdraw refused: %+v (%v)", o.Error, o.ReceiptErr)
	}
	return o.Result, pc
}

// lookup looks pc up with h's credential.
func (s *suite) lookup(t *testing.T, h holder, pc nipcash.PendingCall, secret string) client.LookupOutcome {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wd.session.LookupWithdrawMany(ctx, []client.BatchWithdrawLookup{{ID: "1", Bill: h.bill, Call: pc,
		Credential: h.lookupCred(), CashSecret: secret}})
	if err != nil || len(outs) != 1 {
		t.Fatalf("cash_lookup: %v", err)
	}
	return outs[0]
}

// lookupCred is the credential a lookup's item proof uses: the slice key, or
// none for a cash-mode call.
func (h holder) lookupCred() nipcash.Credential {
	if h.secret != "" {
		return nipcash.BySecret(h.secret)
	}
	return nipcash.BySigning(h.priv)
}

// payoutNow looks pc up and returns the payout it is done with.
func (s *suite) payoutNow(t *testing.T, h holder, pc nipcash.PendingCall) *nipcash.Payout {
	t.Helper()
	lo := s.lookup(t, h, pc, pc.SourceSecret)
	if lo.Status != nipcash.LookupDone {
		t.Fatalf("lookup: %+v", lo)
	}
	p, err := nipcash.CashWithdrawParams{Credential: h.cred}.ParseLookupResult(lo.Result)
	if err != nil {
		t.Fatalf("lookup done: %v (%s)", err, lo.Result)
	}
	if err := nipcash.VerifyWithdrawReceipt(p.Receipt, nipcash.ReceiptExpectation{HubXOnly: s.nodeXOnly, Target: h.tok.WalletPubkey,
		RequestID: pc.RequestID, Address: p.Address, PayoutMillis: p.PayoutMillis, SentBy: p.SentBy}); err != nil {
		t.Errorf("the receipt of a lookup done does not verify: %v", err)
	}
	return p
}

// cancel sends a cancel request for pc.
func (s *suite) cancel(t *testing.T, h holder, pc nipcash.PendingCall) client.WithdrawCancelOutcome {
	t.Helper()
	ctx, cancel := ctx15()
	defer cancel()
	outs, err := s.wd.session.WithdrawCancelMany(ctx, []client.BatchWithdrawCancel{{ID: "1", Bill: h.bill, Call: pc, Credential: h.lookupCred()}})
	if err != nil || len(outs) != 1 {
		t.Fatalf("cancel request: %v", err)
	}
	return outs[0]
}

// raw sends one hand-built item on h's bill: params as given, the item proof by
// signer ("" for none), the bill proof by the bill's secret.
func (s *suite) raw(t *testing.T, h holder, method string, params any, signer string) map[string]json.RawMessage {
	t.Helper()
	return s.sendOne(t, func(nonce string, notAfter int64) transport.Item {
		return s.rawItem(t, h, "1", method, params, signer, nonce, notAfter)
	})
}

func (s *suite) rawItem(t *testing.T, h holder, id, method string, params any, signer, nonce string, notAfter int64) transport.Item {
	t.Helper()
	cred := nipcash.BySecret(mustKey(t))
	if signer != "" {
		cred = nipcash.BySigning(signer)
	}
	it, err := nipcash.BuildItem(id, h.tok.WalletPubkey, h.tok.Secret, method, params, cred,
		nipcash.ItemBinding{HubXOnly: s.nodeXOnly, Nonce: nonce, NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// withdrawParams is a well-formed cash_withdraw request for h and q, as a map a
// case can spoil.
func withdrawParams(t *testing.T, h holder, q *nipcash.WithdrawQuote, remint *nipcash.CashTarget) map[string]any {
	t.Helper()
	rid, _ := nipcash.NewRequestID()
	notify := mustKey(t)
	if h.secret != "" && remint == nil {
		var err error
		if remint, err = nipcash.NewCashTarget(); err != nil {
			t.Fatal(err)
		}
	}
	req, err := nipcash.CashWithdrawParams{Quote: q, Credential: h.cred, RequestID: rid, Notify: notify, Remint: remint}.Request(h.tok.WalletPubkey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(req)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func resultDetail(res map[string]json.RawMessage) string {
	var e struct {
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(res["error"], &e)
	return e.Detail
}

func codeOf(o client.ItemOutcome) (string, string) {
	if o.Error == nil {
		return "", ""
	}
	return o.Error.Code, o.Error.Detail
}

// signQuote signs a quote event with priv (another Hub's key, for refusals).
func signQuote(t *testing.T, f nipcash.QuoteFields, priv string) *nipcash.WithdrawQuote {
	t.Helper()
	ev, err := nipcash.NewWithdrawQuoteEvent(f, time.Now().Unix(), func(ev *nip01.Event) error { return ev.Sign(priv) })
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev)
	q, err := nipcash.ParseWithdrawQuote(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// chain is the Hub as a WithdrawChain; the case needs it.
func (s *suite) chain() WithdrawChain { return s.h.(WithdrawChain) }

// advance moves the Hub's clock; the case needs Clocked.
func (s *suite) advance(t *testing.T, d time.Duration) { s.h.(Clocked).Advance(t, d) }
