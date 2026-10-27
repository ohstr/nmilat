package conformance

import (
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

// WithdrawChain is an optional Hub offering on-chain withdrawals whose chain and
// node wallet the suite can drive (the CT-WD cases marked [chain]).
type WithdrawChain interface {
	// Tip is the Hub's best block height.
	Tip(t testing.TB) int64
	// Mine mines blocks; Reorg replaces the depth best blocks with empty ones,
	// dropping their transactions. Both are the chain an OrderPayer drives too.
	Mine(t testing.TB, blocks int)
	Reorg(t testing.TB, depth int)
	// EvictTx drops an unconfirmed version from the mempool. It may drop
	// others: cases assert on txid only.
	EvictTx(t testing.TB, txid string)
	// Withhold keeps txid out of every block while on.
	Withhold(t testing.TB, txid string, on bool)
	// Tx is a transaction the chain knows, lowercase hex, and its depth.
	Tx(t testing.TB, txid string) (raw string, depth uint32)
	// ExternalAddress is an address of script type st the Hub does not control.
	ExternalAddress(t testing.TB, st nipcash.ScriptType) string
	// HubOwnAddress is one its node wallet controls (a NIP-CO order address
	// if it sells on-chain).
	HubOwnAddress(t testing.TB) string
	// SetUnconfirmedBound bounds the value of the Hub's unconfirmed payouts
	// (step 3 RATE_LIMITED); ^uint64(0) lifts the bound.
	SetUnconfirmedBound(t testing.TB, millis uint64)
	// StarveCoins leaves the Hub no coins to set aside (step 3
	// INSUFFICIENT_BALANCE) while on.
	StarveCoins(t testing.TB, on bool)
}

// WithdrawToggle is an optional Hub whose on-chain withdrawals the suite can
// turn off and on again (CT-WD-01).
type WithdrawToggle interface {
	SetWithdrawals(t testing.TB, on bool)
}
