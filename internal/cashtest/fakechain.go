package cashtest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/flokiorg/go-flokicoin/chaincfg/chainhash"
	"github.com/flokiorg/go-flokicoin/wire"
)

// ChainBaseHeight is the height of the fake chain's first block.
const ChainBaseHeight = 870400

// Chain is the fake Hub's chain: blocks of real transactions, a mempool,
// reorganisations and evictions, driven by the test.
//
// It checks only what decides which transactions can confirm together: an
// output is spent once, by the first transaction a block includes; a mempool
// transaction conflicting with a newly broadcast one is replaced by it (every
// replacement is accepted). Scripts and signatures are not checked.
//
// A reorganisation disconnects blocks and drops their transactions: nothing
// goes back to the mempool, so whoever wants one confirmed again must
// rebroadcast it.
type Chain struct {
	mu sync.Mutex
	// blocks[i] is the block at height ChainBaseHeight + i.
	blocks   [][]chainhash.Hash
	txs      map[chainhash.Hash]*wire.MsgTx
	height   map[chainhash.Hash]int64 // confirmed transactions only
	spentBy  map[wire.OutPoint]chainhash.Hash
	mempool  []chainhash.Hash
	withheld map[chainhash.Hash]bool
	// listeners run after each block, reorganisation and eviction, outside the
	// chain's lock.
	listeners []func()
}

// NewChain returns a chain whose tip is ChainBaseHeight, with an empty block.
func NewChain() *Chain {
	return &Chain{
		blocks:   [][]chainhash.Hash{nil},
		txs:      map[chainhash.Hash]*wire.MsgTx{},
		height:   map[chainhash.Hash]int64{},
		spentBy:  map[wire.OutPoint]chainhash.Hash{},
		withheld: map[chainhash.Hash]bool{},
	}
}

// OnChange registers f to run after every block mined, every reorganisation and
// every eviction.
func (c *Chain) OnChange(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, f)
}

func (c *Chain) notify() {
	c.mu.Lock()
	ls := slices.Clone(c.listeners)
	c.mu.Unlock()
	for _, f := range ls {
		f()
	}
}

// Tip is the height of the best block.
func (c *Chain) Tip() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tipLocked()
}

func (c *Chain) tipLocked() int64 { return ChainBaseHeight + int64(len(c.blocks)) - 1 }

// Fund confirms, in a new block, a transaction with no real input paying value
// base units to pkScript, and returns its outpoint.
func (c *Chain) Fund(pkScript []byte, value int64) wire.OutPoint {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0xffffffff},
		SignatureScript:  []byte(randHex(16)),
		Sequence:         0xffffffff,
	})
	tx.AddTxOut(wire.NewTxOut(value, pkScript))
	c.mu.Lock()
	h := tx.TxHash()
	c.txs[h] = tx
	c.blocks = append(c.blocks, []chainhash.Hash{h})
	c.height[h] = c.tipLocked()
	c.mu.Unlock()
	c.notify()
	return wire.OutPoint{Hash: h, Index: 0}
}

// ErrTxInvalid is a transaction the chain cannot accept: an input it does not
// know, or one a confirmed transaction already spent.
var ErrTxInvalid = errors.New("cashtest: transaction spends a missing or spent output")

func coinbase(in *wire.TxIn) bool { return in.PreviousOutPoint.Index == 0xffffffff }

// Broadcast offers tx to the mempool. A transaction already confirmed or in the
// mempool is accepted as it is; one spending an output a confirmed transaction
// spent, or an output of a transaction the chain does not know, is ErrTxInvalid;
// mempool transactions conflicting with it are replaced, with their
// descendants.
func (c *Chain) Broadcast(tx *wire.MsgTx) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := tx.TxHash()
	if _, ok := c.height[h]; ok || slices.Contains(c.mempool, h) {
		return nil
	}
	for _, in := range tx.TxIn {
		if coinbase(in) {
			return fmt.Errorf("%w: a funding input", ErrTxInvalid)
		}
		prev, ok := c.txs[in.PreviousOutPoint.Hash]
		if !ok || int(in.PreviousOutPoint.Index) >= len(prev.TxOut) {
			return fmt.Errorf("%w: %v", ErrTxInvalid, in.PreviousOutPoint)
		}
		if _, confirmed := c.height[in.PreviousOutPoint.Hash]; !confirmed && !slices.Contains(c.mempool, in.PreviousOutPoint.Hash) {
			return fmt.Errorf("%w: parent %v not known", ErrTxInvalid, in.PreviousOutPoint.Hash)
		}
		if _, spent := c.spentBy[in.PreviousOutPoint]; spent {
			return fmt.Errorf("%w: %v spent", ErrTxInvalid, in.PreviousOutPoint)
		}
	}
	for _, other := range slices.Clone(c.mempool) {
		if conflicts(c.txs[other], tx) {
			c.evictLocked(other)
		}
	}
	c.txs[h] = tx
	c.mempool = append(c.mempool, h)
	return nil
}

// conflicts reports two transactions spending a common output.
func conflicts(a, b *wire.MsgTx) bool {
	for _, x := range a.TxIn {
		for _, y := range b.TxIn {
			if x.PreviousOutPoint == y.PreviousOutPoint {
				return true
			}
		}
	}
	return false
}

// evictLocked drops h and its mempool descendants.
func (c *Chain) evictLocked(h chainhash.Hash) {
	i := slices.Index(c.mempool, h)
	if i < 0 {
		return
	}
	c.mempool = slices.Delete(c.mempool, i, i+1)
	for _, child := range slices.Clone(c.mempool) {
		for _, in := range c.txs[child].TxIn {
			if in.PreviousOutPoint.Hash == h {
				c.evictLocked(child)
				break
			}
		}
	}
}

// Mine mines n blocks, one at a time. Each includes, in arrival order, every
// mempool transaction not withheld whose inputs are confirmed (or created earlier
// in the block) and unspent; the listeners run after each block.
func (c *Chain) Mine(n int) {
	for range n {
		c.mineOne()
		c.notify()
	}
}

func (c *Chain) mineOne() {
	c.mu.Lock()
	defer c.mu.Unlock()
	height := c.tipLocked() + 1
	var block []chainhash.Hash
	for progress := true; progress; {
		progress = false
		for _, h := range slices.Clone(c.mempool) {
			if c.withheld[h] || !c.minableLocked(c.txs[h]) {
				continue
			}
			for _, in := range c.txs[h].TxIn {
				c.spentBy[in.PreviousOutPoint] = h
			}
			c.height[h] = height
			block = append(block, h)
			c.mempool = slices.DeleteFunc(c.mempool, func(x chainhash.Hash) bool { return x == h })
			progress = true
		}
	}
	// Whatever now conflicts with the block leaves the mempool.
	for _, h := range slices.Clone(c.mempool) {
		for _, in := range c.txs[h].TxIn {
			if _, spent := c.spentBy[in.PreviousOutPoint]; spent {
				c.evictLocked(h)
				break
			}
		}
	}
	c.blocks = append(c.blocks, block)
}

func (c *Chain) minableLocked(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		if _, ok := c.height[in.PreviousOutPoint.Hash]; !ok {
			return false
		}
		if _, spent := c.spentBy[in.PreviousOutPoint]; spent {
			return false
		}
	}
	return true
}

// Reorg disconnects the depth best blocks (never the first) and drops their
// transactions, then mines depth empty blocks so the tip height is unchanged.
func (c *Chain) Reorg(depth int) {
	c.mu.Lock()
	depth = min(depth, len(c.blocks)-1)
	for range depth {
		last := c.blocks[len(c.blocks)-1]
		c.blocks = c.blocks[:len(c.blocks)-1]
		for _, h := range last {
			delete(c.height, h)
			for _, in := range c.txs[h].TxIn {
				if c.spentBy[in.PreviousOutPoint] == h {
					delete(c.spentBy, in.PreviousOutPoint)
				}
			}
		}
	}
	// Mempool transactions spending a dropped one go too.
	for _, h := range slices.Clone(c.mempool) {
		if !c.parentsKnownLocked(c.txs[h]) {
			c.evictLocked(h)
		}
	}
	for range depth {
		c.blocks = append(c.blocks, nil)
	}
	c.mu.Unlock()
	c.notify()
}

func (c *Chain) parentsKnownLocked(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		_, confirmed := c.height[in.PreviousOutPoint.Hash]
		if !confirmed && !slices.Contains(c.mempool, in.PreviousOutPoint.Hash) {
			return false
		}
	}
	return true
}

// Evict drops an unconfirmed transaction, and its descendants, from the mempool.
func (c *Chain) Evict(txid string) {
	h, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.evictLocked(*h)
	c.mu.Unlock()
	c.notify()
}

// Withhold keeps txid out of every block while on.
func (c *Chain) Withhold(txid string, on bool) {
	h, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return
	}
	c.mu.Lock()
	if on {
		c.withheld[*h] = true
	} else {
		delete(c.withheld, *h)
	}
	c.mu.Unlock()
	c.notify()
}

// Depth is a transaction's confirmations: 0 unconfirmed or unknown.
func (c *Chain) Depth(h chainhash.Hash) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.depthLocked(h)
}

func (c *Chain) depthLocked(h chainhash.Hash) uint32 {
	at, ok := c.height[h]
	if !ok {
		return 0
	}
	return uint32(c.tipLocked() - at + 1)
}

// InMempool reports an unconfirmed transaction the mempool holds.
func (c *Chain) InMempool(h chainhash.Hash) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.mempool, h)
}

// Spendable reports whether every input of tx is still unspent by a confirmed
// transaction (tx itself excepted) and created by one the chain still knows.
func (c *Chain) Spendable(tx *wire.MsgTx) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	self := tx.TxHash()
	for _, in := range tx.TxIn {
		if by, spent := c.spentBy[in.PreviousOutPoint]; spent && by != self {
			return false
		}
		_, confirmed := c.height[in.PreviousOutPoint.Hash]
		if !confirmed && !slices.Contains(c.mempool, in.PreviousOutPoint.Hash) {
			return false
		}
	}
	return true
}

// Raw is a known transaction's serialization, lowercase hex, and its depth.
func (c *Chain) Raw(txid string) (raw string, depth uint32, ok bool) {
	h, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return "", 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, ok := c.txs[*h]
	if !ok {
		return "", 0, false
	}
	return TxHex(tx), c.depthLocked(*h), true
}

// TxHex serializes tx, lowercase hex.
func TxHex(tx *wire.MsgTx) string {
	var b bytes.Buffer
	if err := tx.Serialize(&b); err != nil {
		panic(fmt.Sprintf("cashtest: serialize tx: %v", err))
	}
	return hex.EncodeToString(b.Bytes())
}
