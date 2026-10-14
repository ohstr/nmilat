package client

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// A success the client cannot decode is not a refusal: the hub ran the item, so
// resending it could spend twice. SafeToResend must say no.
func TestTransferMany_UndecodableSuccessIsNotSafeToResend(t *testing.T) {
	// new_wallet_token must be a string; a number makes the body undecodable.
	body := json.RawMessage(`{"amount_millis":7000,"new_wallet_token":5}`)
	hub := newLyingHub(t, 1, 1, func(item transport.Item) *transport.Result {
		return &transport.Result{ID: item.ID, ResultType: item.Method, Result: body}
	})
	relay := startLyingHub(t, hub)
	_, target := sessionKeypair(t)
	c := clientOnLyingHub(t, hub, relay, target)
	bill, err := BillFromParts(target, connSecretFor(target))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := c.session.TransferMany(ctx, []BatchTransfer{{ID: "1", Bill: bill,
		Params: nipcash.CashTransferParams{To: nipcash.Pubkey(target), Credential: nipcash.BySecret(connSecretFor(target)), CurrentAmount: 7000}}})
	if err != nil {
		t.Fatalf("TransferMany: %v", err)
	}
	if len(out) != 1 || out[0].State != OutcomeError || !out[0].Undecodable {
		t.Fatalf("outcome = %+v, want an undecodable OutcomeError", out)
	}
	if out[0].SafeToResend() {
		t.Fatal("an undecodable success reported SafeToResend")
	}
}

func TestSafeToResend(t *testing.T) {
	for _, tc := range []struct {
		o    ItemOutcome
		want bool
	}{
		{ItemOutcome{State: OutcomeError}, true},
		{ItemOutcome{State: OutcomeError, Undecodable: true}, false},
		{ItemOutcome{State: OutcomeNotServed}, false},
		{ItemOutcome{State: OutcomeResult}, false},
	} {
		if got := tc.o.SafeToResend(); got != tc.want {
			t.Errorf("%+v: SafeToResend = %v, want %v", tc.o, got, tc.want)
		}
	}
}
