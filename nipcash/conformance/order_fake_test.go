package conformance_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash/conformance"
)

// specOrderTerms are NIP-CO §Terms' example terms.
const specOrderTerms = `{
  "lightning": {"min_millis": 1000000, "max_millis": 1000000000, "fee_base": 1000, "fee_ppm": 1000, "window": 3600},
  "onchain": {"min_millis": 10000000, "max_millis": 1000000000, "fee_base": 21000, "fee_ppm": 2000, "window": 86400,
    "confirmations": [{"up_to_millis": 100000000, "n": 1}, {"up_to_millis": 1000000000, "n": 3}, {"n": 6}]},
  "bill": {"redeem_fee_base": 0, "redeem_fee_ppm": 5000, "min_transfer_millis": 1000}
}`

// orderLedgerHub is the fake Hub selling cash over its bill ledger and chain:
// an OrderPayer (with OrderConnectionAdder and Restarter) on top of the
// ledger's Clocked, Faulty, Admin and SliceRemover. The book shares the
// ledger's chain and clock, so Mine and Reorg are the ledger's.
type orderLedgerHub struct {
	ledgerHub
	book *cashtest.OrderBook
}

var (
	_ conformance.OrderPayer           = orderLedgerHub{}
	_ conformance.OrderConnectionAdder = orderLedgerHub{}
	_ conformance.Restarter            = orderLedgerHub{}
)

func (h orderLedgerHub) OrderConnection(t testing.TB) string { return h.book.OrderConnection(t) }
func (h orderLedgerHub) PayInvoice(t testing.TB, bolt11 string, millis uint64) {
	h.book.PayInvoice(t, bolt11, millis)
}
func (h orderLedgerHub) PayAddress(t testing.TB, address string, millis uint64) string {
	return h.book.PayAddress(t, address, millis)
}
func (h orderLedgerHub) Evict(_ testing.TB, outpoint string) { h.book.Evict(outpoint) }
func (h orderLedgerHub) RetireOrderConnection(_ testing.TB, pubkey string) {
	h.book.RetireConnection(pubkey)
}
func (h orderLedgerHub) AddOrderConnection(t testing.TB) string { return h.book.AddConnection(t) }
func (h orderLedgerHub) Restart(testing.TB)                     { h.book.Restart() }
func (h orderLedgerHub) Advance(_ testing.TB, d time.Duration)  { h.book.Advance(d) }

// InjectFault breaks the signer at settlement only, so the orders' lookups
// are still served while their payments wait.
func (h orderLedgerHub) InjectFault(t testing.TB, f conformance.Fault) {
	switch f {
	case conformance.FaultBreakSigner:
		h.book.BreakSigner(true)
	case conformance.FaultNone:
		h.book.BreakSigner(false)
		h.ledgerHub.InjectFault(t, f)
	default:
		h.ledgerHub.InjectFault(t, f)
	}
}

func newOrderLedgerHub(t *testing.T) orderLedgerHub {
	lh := newLedgerHub(t, nil)
	book := lh.ServeOrders(t, specOrderTerms)
	// A ceiling CT-ORD-06 can fill: five orders of max_millis per kind.
	book.SetOpenCeiling(5_000_000_000)
	return orderLedgerHub{ledgerHub: lh, book: book}
}

// TestAgainstFakeOrderHub runs the NIP-CO cases, CT-LK-14 and the ordered
// slice cases against the fake's Order connections, chain and ledger.
func TestAgainstFakeOrderHub(t *testing.T) {
	var only []string
	for _, id := range conformance.IDs() {
		if strings.HasPrefix(id, "CT-ORD") || strings.HasPrefix(id, "CT-OSL") || id == "CT-LK-14" {
			only = append(only, id)
		}
	}
	conformance.Run(t, newOrderLedgerHub(t), conformance.Options{Only: only})
}
