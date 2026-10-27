package conformance_test

import (
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
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

// TestAgainstFakeOrderHub runs the NIP-CO cases against the fake's Order
// connection.
func TestAgainstFakeOrderHub(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	h := orderHub{FakeHub: hub, book: hub.ServeOrders(t, fakeOrderTerms)}
	var only []string
	for _, id := range conformance.IDs() {
		if strings.HasPrefix(id, "CT-ORD") {
			only = append(only, id)
		}
	}
	conformance.Run(t, h, conformance.Options{Only: only})
}
