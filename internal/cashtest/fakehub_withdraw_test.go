package cashtest_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/flokiorg/go-flokicoin/chaincfg/chainhash"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/client"
	relayclient "github.com/ohstr/nmilat/relay/client"
	"github.com/ohstr/nmilat/utils"
)

type journal struct {
	mu    sync.Mutex
	calls []nipcash.PendingCall
}

func (j *journal) WriteAhead(_ context.Context, calls []nipcash.PendingCall) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls = append(j.calls, calls...)
	return nil
}
func (j *journal) RecordDerived(context.Context, string, int64) error  { return nil }
func (j *journal) DerivedPlaced(context.Context, string) (bool, error) { return false, nil }

func (j *journal) last() nipcash.PendingCall {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.calls[len(j.calls)-1]
}

// wdEnv is a fake Hub with a ledger, and a batch session to it.
type wdEnv struct {
	h *cashtest.FakeHub
	l *cashtest.WithdrawLedger
	s *client.BatchSession
}

func newWDEnv(t *testing.T) *wdEnv {
	t.Helper()
	h := cashtest.NewFakeHub(t)
	l := h.ServeWithdrawals(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := client.OpenBatchSession(ctx, h.NodeXOnly(), h.RelayURLs())
	if err != nil {
		t.Fatal(err)
	}
	return &wdEnv{h: h, l: l, s: s}
}

// slice is one pubkey slice of a ledger bill.
type slice struct {
	bill client.Bill
	cred nipcash.Credential
	priv string
}

func (e *wdEnv) bill(t *testing.T, amount uint64) slice {
	t.Helper()
	priv, pub := cashtest.Keypair(t)
	tok, err := nipcash.Decode(e.l.MintBill(t, 0, nipcash.RecipientParam{IdentityType: "pubkey", IdentityValue: pub, AmountMillis: amount}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.BillFor(tok)
	if err != nil {
		t.Fatal(err)
	}
	return slice{bill: b, cred: nipcash.BySigning(priv), priv: priv}
}

// withdraw quotes and withdraws sl to an external P2WPKH address.
func (e *wdEnv) withdraw(t *testing.T, sl slice) nipcash.PendingCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr := cashtest.ExternalAddress(nipcash.ScriptType{Version: 0, ProgramLen: 20})
	qo, err := e.s.WithdrawQuoteMany(ctx, []client.BatchWithdrawQuote{{Bill: sl.bill, Params: nipcash.CashWithdrawQuoteParams{Address: addr, Credential: sl.cred}}})
	if err != nil || len(qo) != 1 || qo[0].Result == nil {
		t.Fatalf("quote: %v %+v", err, qo)
	}
	pub, _ := utils.GetPublicKey(sl.priv)
	q, err := nipcash.VerifyQuoteAnswer(*qo[0].Result, nipcash.QuoteExpectation{HubXOnly: e.h.NodeXOnly(), Wallet: sl.bill.Target(),
		IdentityValue: pub, Address: addr, AmountMillis: qo[0].Result.AmountMillis})
	if err != nil {
		t.Fatal(err)
	}
	j := &journal{}
	wo, err := e.s.WithdrawMany(ctx, []client.BatchWithdraw{{Bill: sl.bill, Params: nipcash.CashWithdrawParams{Quote: q, Credential: sl.cred}}}, j, "dev")
	if err != nil || len(wo) != 1 || wo[0].Result == nil {
		t.Fatalf("withdraw: %v %+v", err, wo)
	}
	return j.last()
}

func (e *wdEnv) payout(t *testing.T, rid string) nipcash.Payout {
	t.Helper()
	p, ok := e.l.Payout(rid)
	if !ok {
		t.Fatalf("no payout %s", rid)
	}
	return p
}

func mustHash(t *testing.T, txid string) chainhash.Hash {
	t.Helper()
	h, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		t.Fatal(err)
	}
	return *h
}

// confirmedVersions counts rid's versions the chain confirms.
func (e *wdEnv) confirmedVersions(t *testing.T, rid string) int {
	t.Helper()
	n := 0
	for _, v := range e.l.Versions(rid) {
		if e.l.Chain().Depth(mustHash(t, v)) > 0 {
			n++
		}
	}
	if inv := e.l.Invalidation(rid); inv != "" && e.l.Chain().Depth(mustHash(t, inv)) > 0 && n > 0 {
		t.Fatalf("%s: a version and its invalidation both confirmed", rid)
	}
	return n
}

// T02-11: under random sequences of blocks, reorganisations, evictions and
// withheld versions, the payout engine never lets two versions of a payout
// confirm, and every payout still ends final.
func TestT02_11_AtMostOneVersionConfirms(t *testing.T) {
	e := newWDEnv(t)
	payouts, rounds := 40, 5
	if testing.Short() {
		payouts = 8
	}
	rng := rand.New(rand.NewPCG(7, 11))
	chain := e.l.Chain()
	for range payouts {
		rid := e.withdraw(t, e.bill(t, 21_000_000)).RequestID
		for range rounds {
			for range 10 {
				switch vs := e.l.Versions(rid); rng.IntN(5) {
				case 0, 1:
					chain.Mine(1 + rng.IntN(3))
				case 2:
					chain.Reorg(1 + rng.IntN(2))
				case 3:
					if len(vs) > 0 {
						chain.Evict(vs[rng.IntN(len(vs))])
					}
				case 4:
					if len(vs) > 0 {
						chain.Withhold(vs[rng.IntN(len(vs))], rng.IntN(2) == 0)
					}
				}
				if n := e.confirmedVersions(t, rid); n > 1 {
					t.Fatalf("%s: %d versions confirmed", rid, n)
				}
			}
		}
		for _, v := range e.l.Versions(rid) {
			chain.Withhold(v, false)
		}
		chain.Mine(20)
		if p := e.payout(t, rid); p.State != nipcash.PayoutFinal {
			t.Fatalf("%s ended %s, want final", rid, p.State)
		}
		if n := e.confirmedVersions(t, rid); n != 1 {
			t.Fatalf("%s: %d versions confirmed at final", rid, n)
		}
	}
}

// T02-12: with withdrawals off, get_info lists neither method, cash_status has
// no withdraw object and both methods are NOT_IMPLEMENTED; mint_cash is served
// and listed while the ledger exists.
func TestT02_12_WithdrawalsOff(t *testing.T) {
	e := newWDEnv(t)
	sl := e.bill(t, 21_000_000)
	e.l.SetOffered(false)
	conn, err := nipcash.DecodeCashHubConnection(e.h.CashHubConnection())
	if err != nil {
		t.Fatal(err)
	}
	nwc, err := relayclient.NewNWCClient(context.Background(), &nip47.PairingInfo{WalletPubkey: conn.Pubkey, RelayURLs: conn.Relays, Secret: conn.Secret},
		nip47.EncryptionNIP44V2)
	if err != nil {
		t.Fatal(err)
	}
	defer nwc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	info, err := nwc.GetInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(info.PrivateMethods, nipcash.MethodCashWithdraw) || !slices.Contains(info.Methods, nipcash.MethodMintCash) {
		t.Errorf("get_info off: methods %v private %v", info.Methods, info.PrivateMethods)
	}
	so, err := e.s.StatusMany(ctx, []client.BatchStatus{{Bill: sl.bill, Credential: sl.cred}})
	if err != nil || so[0].Result == nil || so[0].Result.Withdraw != nil {
		t.Errorf("cash_status off: %v %+v", err, so)
	}
	qo, _ := e.s.WithdrawQuoteMany(ctx, []client.BatchWithdrawQuote{{Bill: sl.bill, Params: nipcash.CashWithdrawQuoteParams{
		Address: cashtest.ExternalAddress(nipcash.ScriptType{Version: 0, ProgramLen: 20}), Credential: sl.cred}}})
	if len(qo) != 1 || qo[0].Error == nil || qo[0].Error.Code != nipcash.ErrCodeNotImplemented {
		t.Errorf("quote off: %+v", qo)
	}
	e.l.SetOffered(true)
	e.withdraw(t, sl)
}

// CT-WD-20's variant: a version signed and stored but never broadcast by the
// Hub confirms anyway (someone relayed it): the payout is paid, never
// invalidated or cancelled.
func TestLedger_StoredVersionMinedFirst(t *testing.T) {
	e := newWDEnv(t)
	e.l.InjectFault(cashtest.FaultCrashAfterSign)
	pc := e.withdraw(t, e.bill(t, 21_000_000))
	e.l.Tick()
	vs := e.l.Versions(pc.RequestID)
	if p := e.payout(t, pc.RequestID); len(vs) != 1 || !p.Signed || p.State != nipcash.PayoutQueued {
		t.Fatalf("crashed after signing: %d versions, %+v", len(vs), p)
	}
	raw, _, _ := e.l.Chain().Raw(vs[0])
	if raw != "" {
		t.Fatalf("the Hub broadcast a version it should have held")
	}
	tx := decodeTxHex(t, e.payout(t, pc.RequestID).Tx)
	if err := e.l.Chain().Broadcast(tx); err != nil {
		t.Fatal(err)
	}
	e.l.Chain().Mine(1)
	e.l.Advance(3 * 24 * time.Hour)
	e.l.Chain().Mine(6)
	p := e.payout(t, pc.RequestID)
	if p.State != nipcash.PayoutFinal || e.l.Invalidation(pc.RequestID) != "" {
		t.Fatalf("a stored version mined first: %s, invalidation %q; want final, none", p.State, e.l.Invalidation(pc.RequestID))
	}
}

// CT-WD-26's variant: while the invalidation of a version that confirmed once
// is pending, the old version confirms again first: the payout is final and
// nothing is re-minted.
func TestLedger_OldVersionBeatsInvalidation(t *testing.T) {
	e := newWDEnv(t)
	sl := e.bill(t, 21_000_000)
	pc := e.withdraw(t, sl)
	chain := e.l.Chain()
	chain.Mine(2)
	v := e.l.Versions(pc.RequestID)[0]
	if p := e.payout(t, pc.RequestID); p.State != nipcash.PayoutConfirmed || p.Txid != v {
		t.Fatalf("payout %+v", p)
	}
	chain.Withhold(v, true)
	chain.Reorg(1)
	e.l.Advance(8 * 24 * time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	co, err := e.s.WithdrawCancelMany(ctx, []client.BatchWithdrawCancel{{Bill: sl.bill, Call: pc, Credential: sl.cred}})
	if err != nil || len(co) != 1 || co[0].Result == nil || co[0].Result.State != nipcash.PayoutBroadcast {
		t.Fatalf("cancel request: %v %+v", err, co)
	}
	inv := e.l.Invalidation(pc.RequestID)
	if inv == "" {
		t.Fatal("no invalidation broadcast")
	}
	chain.Withhold(inv, true)
	chain.Withhold(v, false)
	if err := chain.Broadcast(decodeTxHex(t, e.payout(t, pc.RequestID).Tx)); err != nil {
		t.Fatal(err)
	}
	chain.Mine(7)
	p := e.payout(t, pc.RequestID)
	if p.State != nipcash.PayoutFinal || p.Txid != v || p.NewWalletPubkey != "" {
		t.Fatalf("the old version confirmed first: %+v, want final under %s, no re-mint", p, v)
	}
	if facts := e.l.Archive(pc.RequestID); len(facts) < 3 || facts[0].State != nipcash.PayoutQueued || facts[len(facts)-1].State != nipcash.PayoutFinal ||
		facts[len(facts)-1].Txid != v || facts[len(facts)-1].MinerFeeSat <= 0 {
		t.Errorf("archive facts %+v", facts)
	}
}

// The ledger's own knobs: a quote RATE_LIMITED while set, and the Cash Hub
// delete refused while a payout is open or its record kept.
func TestLedger_RateLimitAndDelete(t *testing.T) {
	e := newWDEnv(t)
	if err := e.l.DeleteHub(); err != nil {
		t.Fatalf("delete with no payout: %v", err)
	}
	sl := e.bill(t, 21_000_000)
	e.l.SetQuoteRateLimited(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qo, _ := e.s.WithdrawQuoteMany(ctx, []client.BatchWithdrawQuote{{Bill: sl.bill, Params: nipcash.CashWithdrawQuoteParams{
		Address: cashtest.ExternalAddress(nipcash.ScriptType{Version: 1, ProgramLen: 32}), Credential: sl.cred}}})
	if len(qo) != 1 || qo[0].Error == nil || qo[0].Error.Code != nipcash.ErrCodeRateLimited {
		t.Fatalf("quote while rate limited: %+v", qo)
	}
	e.l.SetQuoteRateLimited(false)
	pc := e.withdraw(t, sl)
	if !errors.Is(e.l.DeleteHub(), cashtest.ErrHubDeleteRefused) {
		t.Error("delete allowed with a payout queued")
	}
	e.l.Chain().Mine(8)
	if p := e.payout(t, pc.RequestID); p.State != nipcash.PayoutFinal {
		t.Fatalf("payout %s", p.State)
	}
	if !errors.Is(e.l.DeleteHub(), cashtest.ErrHubDeleteRefused) {
		t.Error("delete allowed while a record is kept")
	}
	e.l.Advance(cashtest.DefaultTombstoneWindow + time.Hour)
	if err := e.l.DeleteHub(); err != nil {
		t.Errorf("delete after the record ended: %v", err)
	}
	if e.l.Now().Before(time.Now().Add(cashtest.DefaultTombstoneWindow)) {
		t.Error("Now did not move with Advance")
	}
}
