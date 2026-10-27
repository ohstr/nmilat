package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
)

// T20-29: an order's on-chain address.
func TestT20_29_CheckOrderAddress(t *testing.T) {
	const (
		p2wpkh  = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		p2tr    = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
		regtest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
	)
	for _, ok := range []struct{ addr, network string }{
		{p2wpkh, "mainnet"}, {p2tr, "mainnet"}, {strings.ToUpper(p2wpkh), "mainnet"}, {regtest, "regtest"},
	} {
		got, err := orderAddress(ok.addr, "bitcoin", ok.network)
		if err != nil || got != strings.ToLower(ok.addr) {
			t.Errorf("%s: %q %v", ok.addr, got, err)
		}
	}
	mixed := "bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	for _, bad := range []struct{ addr, network string }{
		{p2wpkh, "regtest"}, // another network
		{mixed, "mainnet"},  // mixed case
		{"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "mainnet"},                             // not segwit
		{"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "mainnet"},                     // checksum
		{"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "mainnet"}, // v1 in bech32
	} {
		if _, err := orderAddress(bad.addr, "bitcoin", bad.network); !errors.Is(err, ErrOrderReplyInvalid) {
			t.Errorf("%s on %s: %v", bad.addr, bad.network, err)
		}
	}
	// A network with no known HRP: any of the chain's; an unknown chain: any HRP.
	if _, err := orderAddress(regtest, "bitcoin", "othernet"); err != nil {
		t.Errorf("chain HRPs: %v", err)
	}
	const zz = "zz1qw508d6qejxtdg4y5r3zarvary0c5xw7k3c49eg"
	if _, err := orderAddress(zz, "bitcoin", "othernet"); !errors.Is(err, ErrOrderReplyInvalid) {
		t.Errorf("zz on bitcoin: %v", err)
	}
	if _, err := orderAddress(zz, "othercoin", "mainnet"); err != nil {
		t.Errorf("zz on an unknown chain: %v", err)
	}
	if _, err := orderAddress(" "+p2wpkh, "bitcoin", "mainnet"); !errors.Is(err, ErrOrderReplyInvalid) {
		t.Error("a padded address accepted")
	}
}

// T20-20: Finished.
func TestT20_20_Finished(t *testing.T) {
	for _, c := range []struct {
		payment string
		state   nipCO.OrderState
		want    bool
	}{
		{nipCO.PaymentLightning, nipCO.OrderOpen, false}, {nipCO.PaymentLightning, nipCO.OrderPaid, false},
		{nipCO.PaymentLightning, nipCO.OrderMinted, true}, {nipCO.PaymentLightning, nipCO.OrderExpired, true},
		{nipCO.PaymentOnchain, nipCO.OrderOpen, false}, {nipCO.PaymentOnchain, nipCO.OrderPaid, false},
		{nipCO.PaymentOnchain, nipCO.OrderMinted, false}, {nipCO.PaymentOnchain, nipCO.OrderExpired, true},
		{nipCO.PaymentOnchain, nipCO.OrderClosed, true},
	} {
		if got := Finished(&nipCO.Order{Payment: c.payment, State: c.state}); got != c.want {
			t.Errorf("%s %s: %v", c.payment, c.state, got)
		}
	}
	if Finished(nil) {
		t.Error("nil finished")
	}
}

// T20-21: EndedUnpaid.
func TestT20_21_EndedUnpaid(t *testing.T) {
	o := &nipCO.Order{Payment: nipCO.PaymentOnchain, State: nipCO.OrderOpen, PayBy: 1000}
	if !EndedUnpaid(o, false, 1001) {
		t.Error("after pay_by, nothing seen")
	}
	expired := *o
	expired.State = nipCO.OrderExpired
	if !EndedUnpaid(&expired, false, 1001) {
		t.Error("expired whatever the lookup said")
	}
	if EndedUnpaid(o, true, 1001) {
		t.Error("saw progress")
	}
	if EndedUnpaid(o, false, 1000) {
		t.Error("before pay_by")
	}
	billed := *o
	billed.Bills = []nipCO.OrderBill{{AmountMillis: 1}}
	if EndedUnpaid(&billed, false, 1001) {
		t.Error("a bill")
	}
}

// T20-17: an announcement that does not exist for TLV 4 refuses the string.
func TestConnect_AnnouncementOfAnotherKey(t *testing.T) {
	_, book := orderHub(t)
	ctx, cancel := testContext(t)
	defer cancel()
	conn, err := nipCO.DecodeOrderConnection(book.OrderConnection(t))
	if err != nil {
		t.Fatal(err)
	}
	priv, other := cashtest.Keypair(t)
	sign, _ := nipcash.LocalChainSigner(priv, cashtest.FakeChain)
	conn.HubIdentity = other
	conn, err = nipCO.SignOrderConnection(conn, sign, other)
	if err != nil {
		t.Fatal(err)
	}
	s, err := nipCO.EncodeOrderConnection(conn)
	if err != nil {
		t.Fatal(err)
	}
	book.SetInfoIdentity(other, cashtest.FakeChain)
	if c, err := Connect(ctx, s, Options{}); err == nil {
		c.Close()
		t.Fatal("connected without an announcement by TLV 4")
	}
}
