package client

import (
	"context"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// T11-31.
// NIP-CASH §Batching Across Bills: a Hub answers a bill it does not hold with
// silence, so a client SHOULD refuse locally to send a bill minted by another node.
func TestStatusMany_RefusesABillFromAnotherNode(t *testing.T) {
	tok := signedKATToken(t)
	bill, err := BillFor(tok)
	if err != nil {
		t.Fatal(err)
	}
	items := []BatchStatus{{ID: "1", Bill: bill, Credential: nipcash.BySecret(tok.Secret)}}

	foreign := hostileSession(transport.DefaultLimits(), strings.Repeat("b", 64)) // hub "aaaa…"
	_, err = foreign.StatusMany(context.Background(), items)
	if err == nil || !strings.Contains(err.Error(), "minted by node") {
		t.Fatalf("bill from node %s sent to hub %s: err = %v, want a local refusal", katMinter, foreign.HubIdentity(), err)
	}

	// The same bill on its own node's session gets past the check (and then fails
	// for want of relays, which is this fixture's limit, not the check's).
	own := hostileSession(transport.DefaultLimits(), strings.Repeat("b", 64))
	own.hubXOnly = katMinter[2:]
	if _, err := own.StatusMany(context.Background(), items); err != nil && strings.Contains(err.Error(), "minted by node") {
		t.Fatalf("bill refused by its own node's session: %v", err)
	}
}

// A bill without verifiable provenance cannot be judged, so it is not refused.
func TestBillFor_NoProvenanceIsNotJudged(t *testing.T) {
	tok := signedKATToken(t)
	tok.MintSignature, tok.AttestedAmountMillis = nil, nil
	bill, err := BillFor(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := bill.check("1", strings.Repeat("a", 64)); err != nil {
		t.Fatalf("provenance-less bill refused: %v", err)
	}
}
