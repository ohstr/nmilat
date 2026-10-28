package client

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// A redeem answered with a tombstone closes not applied as *nipcash.BillGone,
// carrying the reason, as a transfer or consolidate does; never a WalletError
// whose message holds it.
func TestCashRedeem_TombstoneIsBillGone(t *testing.T) {
	c, cred, n := redeemCountHub(t, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method,
			Result: []byte(`{"status":"spent","reason":"expired","retained_until":2000000000}`)}
	})
	ctx, cancel := e2eContext(t)
	defer cancel()
	_, err := c.CashRedeem(ctx, nipcash.CashRedeemParams{Invoice: redeemInvoice, Credential: cred})
	var gone *nipcash.BillGone
	if !errors.As(err, &gone) {
		t.Fatalf("err = %v (%T), want *nipcash.BillGone", err, err)
	}
	if gone.Method != nipcash.MethodCashRedeem || gone.Tombstone.Reason != nipcash.ReasonExpired {
		t.Errorf("BillGone = %+v, want cash_redeem / expired", gone)
	}
	if errors.Is(err, ErrNeedsStatus) {
		t.Error("a tombstone needs no status read")
	}
	if n.Load() != 1 {
		t.Errorf("the Hub saw %d redeems, want 1", n.Load())
	}
}
