package conformance_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/conformance"
)

// TestAgainstFakeHub runs the whole suite against nmilat's own fake Hub (T02-05).
func TestAgainstFakeHub(t *testing.T) {
	conformance.Run(t, cashtest.NewFakeHub(t), conformance.Options{})
}

const fakeOrderTerms = `{"lightning": {"min_millis": 1000000, "max_millis": 1000000000, "fee_base": 1000, "fee_ppm": 1000, "window": 3600},
  "onchain": {"min_millis": 10000000, "max_millis": 1000000000, "fee_base": 21000, "fee_ppm": 2000, "window": 86400,
    "confirmations": [{"up_to_millis": 100000000, "n": 1}, {"n": 3}]}}`

// orderHub is the fake Hub with an Order connection, as an OrderPayer. Its
// payments are driven through the fake's own book, so the payer methods that
// need a real invoice or chain skip.
type orderHub struct {
	*cashtest.FakeHub
	book *cashtest.OrderBook
}

func (h orderHub) OrderConnection(t testing.TB) string { return h.book.OrderConnection(t) }
func (h orderHub) PayInvoice(t testing.TB, _ string, _ uint64) {
	t.Skip("the fake pays by request_id")
}
func (h orderHub) PayAddress(t testing.TB, _ string, _ uint64) string {
	t.Skip("the fake has no chain")
	return ""
}
func (h orderHub) Mine(t testing.TB, _ int)                     { t.Skip("the fake has no chain") }
func (h orderHub) Reorg(t testing.TB, _ int)                    { t.Skip("the fake has no chain") }
func (h orderHub) Evict(t testing.TB, _ string)                 { t.Skip("the fake has no chain") }
func (h orderHub) RetireOrderConnection(_ testing.TB, _ string) { h.book.Retire() }

// TestAgainstFakeWithdrawHub runs the withdrawal cases against a fake Hub that
// offers withdrawals.
func TestAgainstFakeWithdrawHub(t *testing.T) {
	conformance.Run(t, cashtest.NewFakeHub(t, cashtest.WithWithdrawals()), conformance.Options{Only: []string{"CT-WD-01", "CT-SCOPE-05"}})
}

// listHub is the fake Hub with an Order connection, a circle and their
// listings, as a Lister.
type listHub struct {
	orderHub
	*cashtest.Lister
}

// TestAgainstFakeListingHub runs the CT-LIST cases against the fake's listings
// (T02-13).
func TestAgainstFakeListingHub(t *testing.T) {
	hub := cashtest.NewFakeHub(t, cashtest.WithCircleHub())
	book := hub.ServeOrders(t, fakeOrderTerms)
	h := listHub{orderHub: orderHub{FakeHub: hub, book: book}, Lister: hub.ServeListings(t, book)}
	var only []string
	for _, id := range conformance.IDs() {
		if strings.HasPrefix(id, "CT-LIST") {
			only = append(only, id)
		}
	}
	conformance.Run(t, h, conformance.Options{Only: only})
}

// ledgerHub is the fake Hub with a bill ledger offering withdrawals, as a
// WithdrawChain, WithdrawToggle, Clocked, Faulty, HubDeleter, Payee, Admin and
// SliceRemover.
type ledgerHub struct {
	*cashtest.FakeHub
	l     *cashtest.WithdrawLedger
	fault *atomic.Pointer[cashtest.Fault]
}

func (h ledgerHub) Invoice(_ testing.TB, millis uint64) string { return h.l.Invoice(millis) }

// ledgerHub's Admin: the owner's delete and the Hub's balance; the circle and
// wallet-cap hooks skip, the fake ledger having none.
func (h ledgerHub) DeleteBill(_ testing.TB, wallet string) { _ = h.l.DeleteBill(wallet) }
func (h ledgerHub) Balance(testing.TB) uint64              { return h.l.Balance() }
func (h ledgerHub) Rotate(t testing.TB, _ *nip01.Event)    { t.Skip("the fake ledger has no circle") }
func (h ledgerHub) SetAccepting(t testing.TB, _ bool)      { t.Skip("the fake ledger has no circle") }
func (h ledgerHub) AddCircleConnection(t testing.TB) string {
	t.Skip("the fake ledger has no circle")
	return ""
}
func (h ledgerHub) RevokeCircleConnection(t testing.TB, _ string) {
	t.Skip("the fake ledger has no circle")
}
func (h ledgerHub) SetLiveWalletCap(t testing.TB, _ int) { t.Skip("the fake ledger has no wallet cap") }
func (h ledgerHub) SetSpinOffRate(t testing.TB, _ int, _ time.Duration) {
	t.Skip("the fake ledger has no spin-off rate")
}
func (h ledgerHub) DropArchive(t testing.TB, _ string) {
	t.Skip("the fake ledger keeps no bill archive")
}

// RemoveSlice is the owner's removal (SliceRemover).
func (h ledgerHub) RemoveSlice(_ testing.TB, wallet, identityType, identityValue string) error {
	return h.l.RemoveSlice(wallet, identityType, identityValue)
}

var (
	_ conformance.Admin        = ledgerHub{}
	_ conformance.SliceRemover = ledgerHub{}
	_ conformance.Payee        = ledgerHub{}
)

func newLedgerHub(t *testing.T, terms *nipcash.WithdrawTerms) ledgerHub {
	fault := &atomic.Pointer[cashtest.Fault]{}
	fault.Store(&cashtest.FaultNone)
	hub := cashtest.NewFakeHub(t, cashtest.WithFault(func(cashtest.ItemCtx) cashtest.Fault { return *fault.Load() }))
	return ledgerHub{FakeHub: hub, l: hub.ServeWithdrawals(t, terms), fault: fault}
}

func (h ledgerHub) Tip(testing.TB) int64                  { return h.l.Chain().Tip() }
func (h ledgerHub) Mine(_ testing.TB, n int)              { h.l.Chain().Mine(n) }
func (h ledgerHub) Reorg(_ testing.TB, depth int)         { h.l.Chain().Reorg(depth) }
func (h ledgerHub) EvictTx(_ testing.TB, txid string)     { h.l.Chain().Evict(txid) }
func (h ledgerHub) HubOwnAddress(testing.TB) string       { return h.l.HubOwnAddress() }
func (h ledgerHub) StarveCoins(_ testing.TB, on bool)     { h.l.StarveCoins(on) }
func (h ledgerHub) SetWithdrawals(_ testing.TB, on bool)  { h.l.SetOffered(on) }
func (h ledgerHub) Advance(_ testing.TB, d time.Duration) { h.l.Advance(d) }
func (h ledgerHub) Withhold(_ testing.TB, txid string, on bool) {
	h.l.Chain().Withhold(txid, on)
}
func (h ledgerHub) SetUnconfirmedBound(_ testing.TB, millis uint64) { h.l.SetUnconfirmedBound(millis) }
func (h ledgerHub) ExternalAddress(_ testing.TB, st nipcash.ScriptType) string {
	return cashtest.ExternalAddress(st)
}
func (h ledgerHub) Tx(t testing.TB, txid string) (string, uint32) {
	raw, depth, ok := h.l.Chain().Raw(txid)
	if !ok {
		t.Fatalf("the fake chain does not know %s", txid)
	}
	return raw, depth
}
func (h ledgerHub) DeleteHub(testing.TB, bool) error { return h.l.DeleteHub() }
func (h ledgerHub) InjectFault(t testing.TB, f conformance.Fault) {
	switch f {
	case conformance.FaultNone:
		if h.fault.Load().Is(cashtest.FaultStallCommit) {
			// The suite waited out a stall on the wall clock; a real Hub's clock
			// kept running meanwhile, so the fake's catches up before the commit
			// resumes.
			if c, ok := h.Clock.(*cashtest.ManualClock); ok && c.Now().Before(time.Now()) {
				c.Set(time.Now())
			}
		}
		h.fault.Store(&cashtest.FaultNone)
		h.l.InjectFault(cashtest.FaultNone)
	case conformance.FaultStallCommit:
		h.fault.Store(&cashtest.FaultStallCommit)
	case conformance.FaultBreakSigner:
		h.fault.Store(&cashtest.FaultBreakSigner)
	case conformance.FaultHoldSign:
		h.l.InjectFault(cashtest.FaultHoldSign)
	case conformance.FaultCrashAfterSign:
		h.l.InjectFault(cashtest.FaultCrashAfterSign)
	case conformance.FaultHoldBroadcast:
		h.l.InjectFault(cashtest.FaultHoldBroadcast)
	default:
		t.Skipf("the fake ledger has no fault %d", f)
	}
}

// TestAgainstFakeWithdrawLedger runs the withdrawal cases against the fake's
// bill ledger and chain (T02-11, T02-12 at the wire).
func TestAgainstFakeWithdrawLedger(t *testing.T) {
	var only []string
	for _, id := range conformance.IDs() {
		if strings.HasPrefix(id, "CT-WD") || id == "CT-STAT-13" || id == "CT-ENV-16" || id == "CT-SCOPE-05" {
			only = append(only, id)
		}
	}
	conformance.Run(t, newLedgerHub(t, nil), conformance.Options{Only: only})
}

// TestAgainstFakeWithdrawLedgerUnbounded runs the cases reading the terms
// against a ledger with no withdrawal minimum or maximum.
func TestAgainstFakeWithdrawLedgerUnbounded(t *testing.T) {
	terms := cashtest.DefaultWithdrawTerms()
	terms.MinMillis, terms.MaxMillis = nil, nil
	conformance.Run(t, newLedgerHub(t, &terms), conformance.Options{Only: []string{"CT-STAT-13", "CT-WD-02", "CT-WD-03"}})
}
