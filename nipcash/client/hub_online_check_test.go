package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/utils"
)

// resignedConnection re-signs connection s for chain with priv as its identity, so it verifies on its own.
func resignedConnection(t *testing.T, s, priv, chain string) string {
	t.Helper()
	c, err := nipcash.DecodeCashHubConnection(s)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := nipcash.LocalChainSigner(priv, chain)
	if err != nil {
		t.Fatal(err)
	}
	if c.HubIdentity, err = utils.GetPublicKey(priv); err != nil {
		t.Fatal(err)
	}
	c.Chain = chain
	signed, err := nipcash.SignCashHubConnection(c, sign, c.HubIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Verify(); err != nil {
		t.Fatalf("the re-signed string must verify: %v", err)
	}
	out, err := nipcash.EncodeCashHubConnection(signed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// NIP-CASH §Connection Signatures, the online check: a signed cashhub1 string whose TLV 4 or TLV 6 the Hub's
// get_info does not confirm is never minted over, and nothing is written ahead. One the Hub signed for its own
// identity and chain reaches the Hub.
func TestHubClient_MintRefusedWhenGetInfoDisagrees(t *testing.T) {
	hub := cashtest.NewFakeHub(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	for _, c := range []struct {
		name string
		s    string
		want error // nil = the online check passes and the mint goes out
	}{
		{"as issued", hub.CashHubConnection(), nil},
		{"re-signed by the Hub for its own chain", resignedConnection(t, hub.CashHubConnection(), hub.NodePriv, cashtest.FakeChain), nil},
		{"another identity, validly signed", resignedConnection(t, hub.CashHubConnection(), strings.Repeat("07", 32), cashtest.FakeChain), nipcash.ErrHubIdentityMismatch},
		{"another chain, signed by the Hub", resignedConnection(t, hub.CashHubConnection(), hub.NodePriv, "flokicoin"), nipcash.ErrChainMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, err := ConnectCashHub(ctx, c.s)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			j := newTestJournal()
			_, err = h.MintCash(ctx, nipcash.MintCashParams{Recipients: []nipcash.Allocation{nipcash.Send(mustCashTarget(t), 1000)}}, j, "dev")
			if c.want == nil {
				// The fake Hub serves no mint_cash; reaching it is the point.
				var ie *IndeterminateError
				if !errors.As(err, &ie) || len(j.all()) != 1 {
					t.Fatalf("err = %v, %d written; want the mint sent and written ahead", err, len(j.all()))
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if n := len(j.all()); n != 0 {
				t.Fatalf("%d calls written ahead for a connection that failed the online check", n)
			}
		})
	}
}
