package client

import (
	"context"
	"errors"

	"github.com/ohstr/nmilat/nipcash"
)

// BillState is what a caller actually wants to know about a bill, with the
// ambiguity NIP-CASH warns about made explicit rather than left to each client
// to rediscover.
type BillState int

const (
	// BillIndeterminate is the zero value on purpose: a caller that ignores
	// the error and reads the state gets "I don't know", never "spent".
	BillIndeterminate BillState = iota
	// BillAvailable — the bill exists and its roster came back.
	BillAvailable
	// BillSpent — the Hub said so explicitly. Definitive.
	BillSpent
)

func (s BillState) String() string {
	switch s {
	case BillAvailable:
		return "available"
	case BillSpent:
		return "spent"
	default:
		return "indeterminate"
	}
}

// State asks a bill what it is and collapses the answer into one of three
// outcomes, implementing NIP-CASH's client rule in one place:
//
//	roster returned              -> BillAvailable
//	"spent" + retained_until     -> BillSpent, with result.RetainedUntil set
//	no answer (timeout, or past  -> BillIndeterminate
//	the Hub's retention window)
//
// **A timeout is never BillSpent.** Silence is indeterminate by construction —
// a spent bill, a Hub that is down, a wrong relay and a request that was simply
// dropped all look identical from here. A client that reports "spent" on a
// timeout will tell someone their money is gone during an ordinary outage, and
// that mistake is why this helper exists rather than leaving every client to
// interpret a bare error.
//
// The error is returned alongside the state so a caller can log or retry on it;
// it must not be used to infer that the bill is gone.
func (c *Client) State(ctx context.Context) (BillState, *nipcash.CashStatusResult, error) {
	return classify(c.CashStatus(ctx))
}

// classify is State's decision, separated from the round trip that feeds it.
// The interpretation is the part that carries the safety property, and it is
// the part worth testing exhaustively — the transport is not mockable here, so
// keeping these apart is what makes the rule above verifiable at all. Its
// signature matches CashStatus's return so State can forward directly.
func classify(result *nipcash.CashStatusResult, err error) (BillState, *nipcash.CashStatusResult, error) {
	if err != nil {
		// Includes context deadline exceeded, which is the ordinary shape of
		// "the Hub said nothing" — see the note above on why that is not spent.
		return BillIndeterminate, nil, err
	}
	if result == nil {
		return BillIndeterminate, nil, errors.New("cash_status returned no result")
	}
	if result.IsSpent() {
		return BillSpent, result, nil
	}
	return BillAvailable, result, nil
}
