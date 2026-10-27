// Package conformance is NIP-CASH's Hub conformance suite: scenario cases that
// drive a Hub over its real wire (the kind-23194 connection and the private
// transport) and assert what the spec says it answers.
//
// nmilat's CI runs it against its own fake Hub; a Hub implementation runs the
// same code against itself through an adapter implementing HubUnderTest and
// whichever optional interfaces it can (Clocked, Faulty, Admin, HubDeleter,
// OrderPayer, PowRelay, Lister, WithdrawChain, WithdrawToggle, Payee,
// SliceRemover, CircleFunder). A case needing
// an optional interface the Hub does not implement is skipped with the
// interface named, so a run lists exactly what it did not exercise.
//
// Each case runs as its own subtest named by its id (t.Run("CT-ENV-03", …)).
package conformance

import (
	"slices"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// HubUnderTest is the one interface every Hub adapter implements.
type HubUnderTest interface {
	// CashHubConnection is a funded Cash Hub connection: its cashhub1 string.
	CashHubConnection() string
	// CircleHubConnection is a Circle Wallet Hub connection (allowlist policy):
	// its circlehub1 string, or "" when the Hub has none (join cases skip).
	CircleHubConnection() string
	TrustIA(t testing.TB, iaXOnly string, trusted bool)
	AddMember(t testing.TB, pubkey string, member bool)
}

// Clocked is an optional Hub whose clock the suite can move. Without it, clock
// cases run on real sleeps under Options.Long or are skipped.
type Clocked interface {
	Advance(t testing.TB, d time.Duration)
}

// Fault is what an optional Faulty Hub is asked to do wrong. FaultNone clears.
type Fault int

const (
	FaultNone Fault = iota
	// FaultStallCommit holds every commit until the fault is cleared; a commit
	// it held past the call's deadline is then refused BAD_REQUEST.
	FaultStallCommit
	// FaultBreakSigner makes the node signer fail.
	FaultBreakSigner
	// FaultDropReply commits, then never replies.
	FaultDropReply
	// FaultDropBeforeCommit stops before committing and never replies.
	FaultDropBeforeCommit
	// FaultRouteOverBound makes the next external route cost more than the
	// routing-fee bound (CASH-RED-07).
	FaultRouteOverBound
	// FaultHoldPayments keeps payments in flight until cleared (CASH-S-36).
	FaultHoldPayments
	// FaultHoldSign writes no about-to-sign record until cleared (withdrawals).
	FaultHoldSign
	// FaultCrashAfterSign stores the record and the signed version, never
	// broadcasts it, and restarts the Hub (withdrawals).
	FaultCrashAfterSign
	// FaultHoldBroadcast holds broadcasting until cleared (withdrawals).
	FaultHoldBroadcast
)

// Faulty is an optional Hub that can be made to fail on purpose.
type Faulty interface{ InjectFault(t testing.TB, f Fault) }

// Admin is an optional Hub exposing its operator's hand.
type Admin interface {
	Rotate(t testing.TB, memberReq *nip01.Event)
	DeleteBill(t testing.TB, wallet string)
	Balance(t testing.TB) uint64
	// SetAccepting opens or closes the circle to joins (CT-JOIN-17).
	SetAccepting(t testing.TB, accepting bool)
	// AddCircleConnection adds a second connection of the circle and returns its
	// circlehub1 (CT-JOIN-18).
	AddCircleConnection(t testing.TB) string
	// RevokeCircleConnection revokes one; its bill proofs then verify nothing.
	RevokeCircleConnection(t testing.TB, circlehub1 string)
	// SetLiveWalletCap and SetSpinOffRate bound new wallets (CASH-CSEC-02,
	// CASH-S-35).
	SetLiveWalletCap(t testing.TB, n int)
	SetSpinOffRate(t testing.TB, n int, per time.Duration)
	// DropArchive drops a destroyed bill's archive while its pairing key stays
	// derivable (CASH-S-34).
	DropArchive(t testing.TB, walletPubkey string)
}

// HubDeleter is an optional Hub whose owner can delete its Cash Hub (CT-TD-01).
// The error is the Hub's refusal.
type HubDeleter interface {
	DeleteHub(t testing.TB, confirmEndWatch bool) error
}

// OrderPayer is an optional Hub that sells cash (NIP-CO), with a payer and a
// chain the suite can drive.
type OrderPayer interface {
	// OrderConnection is a signed cashorder1 string of the Hub under test.
	OrderConnection(t testing.TB) string
	// PayInvoice pays an order invoice; more or less than asked is allowed.
	PayInvoice(t testing.TB, bolt11 string, millis uint64)
	// PayAddress sends one output to an order address and returns the outpoint.
	PayAddress(t testing.TB, address string, millis uint64) string
	Mine(t testing.TB, blocks int)
	Reorg(t testing.TB, depth int)
	// Evict drops an unconfirmed payment from the mempool.
	Evict(t testing.TB, outpoint string)
	RetireOrderConnection(t testing.TB, pubkey string)
}

// PowRelay is an optional Hub whose inbox relay's proof-of-work minimum the
// suite can set.
type PowRelay interface {
	SetMinPow(t testing.TB, difficulty int)
	RelayURL() string
}

// Lister is an optional Hub that publishes offer listings (CT-LIST-*).
type Lister interface {
	// Listings are the Hub's published kind-31190 events and their deletions.
	Listings(t testing.TB) []*nip01.Event
	// Retire retires the listed Order connection behind addr.
	Retire(t testing.TB, addr string)
	// CloseCircle sets accepting false for the listed circle d.
	CloseCircle(t testing.TB, d string)
}

// CircleFunder is an optional Circle Wallet Hub whose issued wallets the suite
// can credit, as a payment received would (CT-JOIN-08, CT-JOIN-15).
type CircleFunder interface {
	FundCircleWallet(t testing.TB, walletPubkey string, millis uint64)
}

// Payee is an optional Hub with a Lightning payee the suite can invoice, for
// the cases that redeem a slice (CT-WD-09).
type Payee interface {
	// Invoice is a fresh invoice for millis that the Hub under test pays as an
	// external payment (never one its own node receives), settling at once.
	Invoice(t testing.TB, millis uint64) string
}

// SliceRemover is an optional Hub whose wallet owner can remove a recipient's
// unclaimed slice (NIP-CASH §Removing a Recipient). The error is the Hub's
// refusal.
type SliceRemover interface {
	RemoveSlice(t testing.TB, wallet, identityType, identityValue string) error
}

// Options tunes a run.
type Options struct {
	// Long runs the cases that need real time, and waits longer before deciding
	// that no reply is coming.
	Long bool
	// Only, when set, runs just the cases with these ids.
	Only []string
}

type need int

const (
	needClock need = iota
	needFaulty
	needAdmin
	needDeleter
	needOrder
	needPow
	needLister
	needWithdrawChain
	needWithdrawToggle
	needPayee
	needCircleFunds
)

func (n need) name() string {
	return [...]string{"Clocked", "Faulty", "Admin", "HubDeleter", "OrderPayer", "PowRelay", "Lister", "WithdrawChain", "WithdrawToggle", "Payee",
		"CircleFunder"}[n]
}

func (n need) satisfiedBy(h HubUnderTest) bool {
	var ok bool
	switch n {
	case needClock:
		_, ok = h.(Clocked)
	case needFaulty:
		_, ok = h.(Faulty)
	case needAdmin:
		_, ok = h.(Admin)
	case needDeleter:
		_, ok = h.(HubDeleter)
	case needOrder:
		_, ok = h.(OrderPayer)
	case needPow:
		_, ok = h.(PowRelay)
	case needLister:
		_, ok = h.(Lister)
	case needWithdrawChain:
		_, ok = h.(WithdrawChain)
	case needWithdrawToggle:
		_, ok = h.(WithdrawToggle)
	case needPayee:
		_, ok = h.(Payee)
	case needCircleFunds:
		_, ok = h.(CircleFunder)
	}
	return ok
}

// ctCase is one conformance case.
type ctCase struct {
	id    string
	needs []need
	run   func(t *testing.T, s *suite)
}

func allCases() []ctCase {
	var out []ctCase
	out = append(out, envCases...)
	out = append(out, scopeCases...)
	out = append(out, powCases...)
	out = append(out, orderCases...)
	out = append(out, withdrawCases...)
	out = append(out, listCases...)
	out = append(out, joinCases...)
	return out
}

// IDs lists every case id this version of the suite runs, in order.
func IDs() []string {
	var ids []string
	for _, c := range allCases() {
		ids = append(ids, c.id)
	}
	return ids
}

// Run runs every case against h, each as a subtest named by its id.
func Run(t *testing.T, h HubUnderTest, o Options) {
	t.Helper()
	s := connect(t, h, o)
	for _, c := range allCases() {
		if len(o.Only) > 0 && !slices.Contains(o.Only, c.id) {
			continue
		}
		t.Run(c.id, func(t *testing.T) {
			for _, n := range c.needs {
				if !n.satisfiedBy(h) {
					t.Skipf("the Hub does not implement %s", n.name())
				}
			}
			c.run(t, s)
		})
	}
}
