package client

import (
	"errors"
	"strings"
	"testing"
)

// A minted token must verify against the connection's Hub identity (TLV 4)
// and name the wallet the result names; anything else is not reported as a
// finished mint.
func TestMintedByHub_ChecksProvenance(t *testing.T) {
	e := newMintEnv(t)
	ctx, cancel := e2eContext(t)
	defer cancel()
	p, _ := mintParams(t)
	res, err := e.h.MintCash(ctx, p, newTestJournal(), "dev")
	if err != nil {
		t.Fatalf("MintCash: %v", err)
	}
	if err := mintedByHub(res, e.h.conn.HubIdentity); err != nil {
		t.Fatalf("the Hub's own mint: %v", err)
	}
	if err := mintedByHub(res, e.h.conn.Pubkey); !errors.Is(err, errMintNotHubs) {
		t.Fatalf("another Hub's identity: %v, want errMintNotHubs", err)
	}
	moved := *res
	moved.WalletPubkey = strings.Repeat("ab", 32)
	if err := mintedByHub(&moved, e.h.conn.HubIdentity); !errors.Is(err, errMintNotHubs) {
		t.Fatalf("another wallet: %v, want errMintNotHubs", err)
	}
}
