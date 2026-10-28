package cashtest_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/flokiorg/go-flokicoin/wire"

	"github.com/ohstr/nmilat/internal/cashtest"
)

func spend(from wire.OutPoint, value int64, tag byte) *wire.MsgTx {
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: from, Witness: wire.TxWitness{{tag}}})
	tx.AddTxOut(wire.NewTxOut(value, []byte{0x51, tag}))
	return tx
}

// The fake chain: one spend per output, replacement in the mempool, withheld
// transactions left out of blocks, reorganisations dropping what they
// disconnect, evictions with descendants.
func TestChain(t *testing.T) {
	c := cashtest.NewChain()
	var changes int
	c.OnChange(func() { changes++ })
	coin := c.Fund([]byte{0x51}, 1000)
	if c.Tip() != cashtest.ChainBaseHeight+1 || c.Depth(coin.Hash) != 1 {
		t.Fatalf("tip %d, funding depth %d", c.Tip(), c.Depth(coin.Hash))
	}
	a, b := spend(coin, 900, 1), spend(coin, 800, 2)
	if err := c.Broadcast(a); err != nil {
		t.Fatal(err)
	}
	if err := c.Broadcast(b); err != nil || c.InMempool(a.TxHash()) || !c.InMempool(b.TxHash()) {
		t.Fatalf("b did not replace a: %v", err)
	}
	child := spend(wire.OutPoint{Hash: b.TxHash()}, 700, 3)
	if err := c.Broadcast(child); err != nil {
		t.Fatal(err)
	}
	c.Withhold(b.TxHash().String(), true)
	c.Mine(2)
	if c.Depth(b.TxHash()) != 0 || c.Depth(child.TxHash()) != 0 {
		t.Fatalf("a withheld transaction, or its child, confirmed")
	}
	c.Withhold(b.TxHash().String(), false)
	c.Mine(1)
	if c.Depth(b.TxHash()) != 1 || c.Depth(child.TxHash()) != 1 {
		t.Fatalf("depths %d %d, want 1 1 (a child mines in its parent's block)", c.Depth(b.TxHash()), c.Depth(child.TxHash()))
	}
	if err := c.Broadcast(a); !errors.Is(err, cashtest.ErrTxInvalid) || c.Spendable(a) {
		t.Fatalf("a double spend of a confirmed output: %v", err)
	}
	tip := c.Tip()
	c.Reorg(1)
	if c.Tip() != tip || c.Depth(b.TxHash()) != 0 || c.InMempool(b.TxHash()) {
		t.Fatalf("after a reorganisation: tip %d, b depth %d, in mempool %v", c.Tip(), c.Depth(b.TxHash()), c.InMempool(b.TxHash()))
	}
	if !c.Spendable(a) {
		t.Fatalf("the disconnected spend still holds the coin")
	}
	if err := c.Broadcast(b); err != nil {
		t.Fatal(err)
	}
	if err := c.Broadcast(child); err != nil {
		t.Fatal(err)
	}
	c.Evict(b.TxHash().String())
	if c.InMempool(b.TxHash()) || c.InMempool(child.TxHash()) {
		t.Fatalf("an eviction left the transaction or its child")
	}
	if raw, depth, ok := c.Raw(b.TxHash().String()); !ok || raw != cashtest.TxHex(b) || depth != 0 {
		t.Fatalf("Raw: %v %d", ok, depth)
	}
	if _, _, ok := c.Raw("zz"); ok {
		t.Fatal("Raw of a malformed txid")
	}
	if err := c.Broadcast(spend(wire.OutPoint{Index: 7}, 1, 9)); !errors.Is(err, cashtest.ErrTxInvalid) {
		t.Fatalf("an unknown parent: %v", err)
	}
	if changes == 0 {
		t.Fatal("no change notified")
	}
}

func decodeTxHex(t *testing.T, s string) *wire.MsgTx {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return &tx
}
