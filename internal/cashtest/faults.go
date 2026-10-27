package cashtest

import (
	"time"

	"github.com/ohstr/nmilat/nipcash/transport"
)

// ItemCtx is what a decision hook sees about one item.
type ItemCtx struct {
	Item     transport.Item
	Envelope *transport.Envelope
	// Index is the item's position in the envelope, from 0.
	Index int
	Now   time.Time
	// Fault is the fault in force for this item, so a decision hook can act out
	// the ones the fake has no path of its own for (FaultRouteOverBound,
	// FaultHoldPayments).
	Fault Fault
	// Relay is the relay the envelope arrived on, nil for one handed to Serve.
	Relay *Relay
}

type faultKind int

const (
	faultNone faultKind = iota
	faultDropBeforeCommit
	faultCommitThenDropReply
	faultStallUntil
	faultInternal
	faultBreakSigner
	faultRouteOverBound
	faultHoldPayments
	faultHoldSign
	faultCrashAfterSign
	faultHoldBroadcast
	faultStallCommit
)

// Fault is what goes wrong while the fake Hub serves one item.
type Fault struct {
	kind  faultKind
	until time.Time
}

var (
	// FaultNone serves the item normally.
	FaultNone = Fault{}
	// FaultDropBeforeCommit is a Hub that stops before committing: the item is not
	// decided, nothing is recorded, the envelope gets no reply and its nonce is not
	// consumed.
	FaultDropBeforeCommit = Fault{kind: faultDropBeforeCommit}
	// FaultCommitThenDropReply decides and records the item, then never replies.
	FaultCommitThenDropReply = Fault{kind: faultCommitThenDropReply}
	// FaultInternal answers the item INTERNAL, nothing committed.
	FaultInternal = Fault{kind: faultInternal}
	// FaultBreakSigner is a Hub whose node signer fails: an item that would sign
	// is answered INTERNAL, nothing committed.
	FaultBreakSigner = Fault{kind: faultBreakSigner}
	// FaultRouteOverBound makes the next external route cost more than the Hub's
	// routing-fee bound (CASH-RED-07). The fake has no payment path of its own
	// yet, so only the decision hook acts on it, through ItemCtx.Fault.
	FaultRouteOverBound = Fault{kind: faultRouteOverBound}
	// FaultHoldPayments keeps payments in flight until cleared (CASH-S-36).
	// Like FaultRouteOverBound it is visible to the decision hook only.
	FaultHoldPayments = Fault{kind: faultHoldPayments}
	// FaultHoldSign keeps the withdrawal ledger from writing any about-to-sign
	// record until cleared (WithdrawLedger.InjectFault).
	FaultHoldSign = Fault{kind: faultHoldSign}
	// FaultCrashAfterSign is a Hub that stored a signed version and restarted
	// without broadcasting it: the ledger never broadcasts that version until
	// cleared.
	FaultCrashAfterSign = Fault{kind: faultCrashAfterSign}
	// FaultHoldBroadcast holds every payout broadcast until cleared.
	FaultHoldBroadcast = Fault{kind: faultHoldBroadcast}
	// FaultStallCommit holds the item's commit for as long as the fault hook
	// keeps answering it for that item. A commit that resumes past the
	// envelope's not_after on the Hub's clock is refused BAD_REQUEST.
	FaultStallCommit = Fault{kind: faultStallCommit}
)

// FaultStallUntil holds the item's commit until the Hub's clock reaches t. A
// commit that resumes past the envelope's not_after is refused BAD_REQUEST,
// nothing committed (NIP-CASH: a call that reaches its commit after its
// deadline is refused BAD_REQUEST, finally); the envelope's other items are
// still served.
func FaultStallUntil(t time.Time) Fault { return Fault{kind: faultStallUntil, until: t} }

// Is reports whether f is the same fault as g, ignoring a stall's time.
func (f Fault) Is(g Fault) bool { return f.kind == g.kind }

func (f Fault) String() string {
	switch f.kind {
	case faultNone:
		return "none"
	case faultDropBeforeCommit:
		return "drop before commit"
	case faultCommitThenDropReply:
		return "commit then drop reply"
	case faultStallUntil:
		return "stall until " + f.until.UTC().Format(time.RFC3339)
	case faultInternal:
		return "internal"
	case faultBreakSigner:
		return "break signer"
	case faultRouteOverBound:
		return "route over bound"
	case faultHoldPayments:
		return "hold payments"
	case faultHoldSign:
		return "hold sign"
	case faultCrashAfterSign:
		return "crash after sign"
	case faultHoldBroadcast:
		return "hold broadcast"
	case faultStallCommit:
		return "stall commit"
	default:
		return "unknown fault"
	}
}
