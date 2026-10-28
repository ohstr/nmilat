package nipcash

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// QuoteCheck is what a Hub knows when it answers cash_withdraw_quote (NIP-CASH
// §Quoting a Withdrawal). Found is false when no slice answers to the item
// proof's signer, or a connection_key slice's attestation does not verify
// (VerifySliceAttestation's err). Claimable is false for a slice claimed,
// terminal or past its expiry, and for a connection_key slice whose IA is no
// longer trusted (VerifySliceAttestation's trusted false). PayoutFor gives the
// payout (WithdrawFee) and the network's dust limit for the address's script
// type; it is called only once rows 1 to 6 pass. EarliestSentBy is the
// earliest time the Hub could broadcast by.
type QuoteCheck struct {
	Found                bool
	Address, NetworkHRP  string
	Pays                 []ScriptType
	Claimable            bool
	AmountMillis         uint64
	MinMillis, MaxMillis *uint64
	PayoutFor            func(ScriptType) (payoutMillis, dustMillis uint64, err error)
	SendBefore           *int64
	EarliestSentBy       int64
}

// CheckQuoteRequest evaluates the quote refusal table in order and returns the
// first refusal as a *WithdrawError with its Row and Detail, or nil. An error
// from PayoutFor is returned as it is (the Hub answers INTERNAL).
func CheckQuoteRequest(c QuoteCheck) error {
	if !c.Found {
		return withdrawErr(ErrCodeNotFound, "", 1, "no slice")
	}
	st, err := ClassifyAddress(c.Address, c.NetworkHRP)
	switch {
	case errors.Is(err, ErrAddressNoWitness):
		return withdrawErr(ErrCodeRestricted, DetailScriptType, 4, "no witness program")
	case errors.Is(err, ErrAddressNetwork):
		return withdrawErr(ErrCodeRestricted, DetailNetwork, 3, "another network")
	case err != nil:
		return withdrawErr(ErrCodeBadRequest, "", 2, "malformed address")
	case !PaysScriptType(c.Pays, st):
		return withdrawErr(ErrCodeRestricted, DetailScriptType, 4, "script type not paid")
	case !c.Claimable:
		return withdrawErr(ErrCodeRestricted, "", 5, "slice not claimable")
	case c.MaxMillis != nil && c.AmountMillis > *c.MaxMillis:
		return withdrawErr(ErrCodeQuotaExceeded, "", 6, "above the withdrawal maximum")
	case c.MinMillis != nil && c.AmountMillis < *c.MinMillis:
		return withdrawErr(ErrCodeRestricted, DetailBelowMin, 7, "below the withdrawal minimum")
	}
	if c.PayoutFor == nil {
		return errors.New("nipcash: QuoteCheck.PayoutFor is required")
	}
	payout, dust, err := c.PayoutFor(st)
	if err != nil {
		return err
	}
	if payout == 0 || payout < dust {
		return withdrawErr(ErrCodeRestricted, DetailBelowMin, 7, "payout below dust")
	}
	if c.SendBefore != nil && c.EarliestSentBy > *c.SendBefore {
		return withdrawErr(ErrCodeRestricted, DetailTooSlow, 8, "send_before unreachable")
	}
	return nil
}

// PayoutCheck is what a Hub knows at cash_withdraw step 3 (NIP-CASH
// §Processing Algorithm). QuoteOK: signed by this Hub's node identity and for
// this bill and slice, its amount included (QuoteForSlice); QuoteValid: QuoteValidAt the tip; OrderedUnfinal: an
// ordered slice made from a payment not yet at final_depth; RefuseUnfinal: the
// Hub's choice to refuse one; OwnAddress: an address the Hub's node wallet
// controls, a NIP-CO order address included.
type PayoutCheck struct {
	QuoteOK, QuoteValid, AtUnconfirmedBound, CoinsSetAside, OrderedUnfinal, RefuseUnfinal, OwnAddress bool
}

// CheckWithdrawPayout evaluates step 3's six rows in order, own_address last,
// and returns the first refusal as a *WithdrawError, or nil. A refusal here
// leaves the slice claimable.
func CheckWithdrawPayout(c PayoutCheck) error {
	switch {
	case !c.QuoteOK:
		return withdrawErr(ErrCodeRestricted, DetailQuoteInvalid, 1, "quote invalid")
	case !c.QuoteValid:
		return withdrawErr(ErrCodeRestricted, DetailQuoteExpired, 2, "quote expired")
	case c.AtUnconfirmedBound:
		return withdrawErr(ErrCodeRateLimited, "", 3, "unconfirmed payouts at their bound")
	case !c.CoinsSetAside:
		return withdrawErr(ErrCodeInsufficientBalance, "", 4, "no coins to set aside")
	case c.OrderedUnfinal && c.RefuseUnfinal:
		return withdrawErr(ErrCodeRestricted, DetailUnfinal, 5, "ordered slice not final")
	case c.OwnAddress:
		return withdrawErr(ErrCodeRestricted, DetailOwnAddress, 6, "own address")
	}
	return nil
}

// PayoutFacts are a payout's chain facts.
type PayoutFacts struct {
	Cancelled, Broadcast, FinalReached bool
	Depth, FinalDepth                  uint32
}

// PayoutStateOf is the state a payout reports: cancelled; final once it reached
// final_depth (FinalReached keeps it final); confirmed at depth ≥ 1; broadcast
// once a version was broadcast (a reorganisation back to depth 0 included);
// else queued.
func PayoutStateOf(f PayoutFacts) PayoutState {
	switch {
	case f.Cancelled:
		return PayoutCancelled
	case f.FinalReached || (f.FinalDepth > 0 && f.Depth >= f.FinalDepth):
		return PayoutFinal
	case f.Depth >= 1:
		return PayoutConfirmed
	case f.Broadcast:
		return PayoutBroadcast
	}
	return PayoutQueued
}

// Cancel timing (NIP-CASH §Cancelling a Payout), in seconds after sent_by.
const (
	// CancelGrace: a payout never broadcast is cancelled from sent_by + 1 day.
	CancelGrace = 86400
	// CancelRequestAfter: a broadcast payout may be cancelled on the caller's
	// request from sent_by + 7 days.
	CancelRequestAfter = 604800
)

// CancelFacts are what decides a cancellation: whether the Hub holds an
// about-to-sign record, whether a version was broadcast, the payout's state
// and its sent_by.
type CancelFacts struct {
	AboutToSign, Broadcast bool
	State                  PayoutState
	SentBy                 int64
}

// CancelStep is what the Hub does about an unconfirmed payout now.
type CancelStep int

const (
	// CancelNotDue: nothing yet.
	CancelNotDue CancelStep = iota
	// CancelNow: no about-to-sign record; cancel and re-mint.
	CancelNow
	// InvalidateThenCancel: a record, nothing broadcast; invalidate, then
	// cancel once the invalidation is final.
	InvalidateThenCancel
)

// CancelDue is the Hub's own cancellation of a payout never broadcast: from
// sent_by + CancelGrace (inclusive), CancelNow without an about-to-sign record,
// InvalidateThenCancel with one. A broadcast, confirmed, final or cancelled
// payout is never due here (a broadcast one waits for a cancel request).
func CancelDue(f CancelFacts, now int64) CancelStep {
	if f.Broadcast || f.State != PayoutQueued || now < f.SentBy+CancelGrace {
		return CancelNotDue
	}
	if f.AboutToSign {
		return InvalidateThenCancel
	}
	return CancelNow
}

// CancelRequestAnswer is the Hub's answer to a cancel request: RESTRICTED
// before sent_by + CancelRequestAfter (exclusive); from then, invalidate is true
// only for a broadcast payout. The answer is the payout's current state either
// way.
func CancelRequestAnswer(f CancelFacts, now int64) (invalidate bool, err error) {
	if now < f.SentBy+CancelRequestAfter {
		return false, withdrawErr(ErrCodeRestricted, "", 0, "a cancel request comes 7 days after sent_by")
	}
	return f.State == PayoutBroadcast, nil
}

// SpendsFromEach reports whether inputs (outpoints "txid:vout", lowercase)
// share at least one with every non-empty set in versionInputs: what a new
// version, and an invalidating transaction, must do. The caller passes every
// version that may have been signed and can still confirm, the about-to-sign
// inputs included.
func SpendsFromEach(versionInputs [][]string, inputs []string) bool {
	have := make(map[string]bool, len(inputs))
	for _, in := range inputs {
		have[in] = true
	}
	for _, set := range versionInputs {
		if len(set) == 0 {
			continue
		}
		shared := false
		for _, in := range set {
			if have[in] {
				shared = true
				break
			}
		}
		if !shared {
			return false
		}
	}
	return true
}

// RemintExpiry is a cancelled payout's re-minted bill's expiry: never when the
// slice never expired, never when the Hub's default expiry is never, else the
// later of the slice's expiry and the cancel time plus the default.
func RemintExpiry(sliceExpiresAt *int64, cancelAt int64, defaultExpiry *int64) *int64 {
	if sliceExpiresAt == nil || defaultExpiry == nil {
		return nil
	}
	v := max(*sliceExpiresAt, cancelAt+*defaultExpiry)
	return &v
}

// WithdrawRetention is a withdrawal record's retention facts: its deadline,
// H, the time it became final or cancelled (0: not yet), the bill's tombstone
// window, and whether a bill its cancellation re-minted is still live.
type WithdrawRetention struct {
	Deadline, Horizon, EndedAt, TombstoneWindow int64
	RemintLive                                  bool
}

// WithdrawRecordRetained reports whether a Hub still keeps the record: while
// not ended, while a re-minted bill lives, and until the later of deadline + H
// and end + tombstone window (inclusive).
func WithdrawRecordRetained(r WithdrawRetention, now int64) bool {
	if r.EndedAt == 0 || r.RemintLive {
		return true
	}
	return now <= max(r.Deadline+r.Horizon, r.EndedAt+r.TombstoneWindow)
}

// WithdrawBlocksHubDelete reports whether the record blocks deleting the Cash
// Hub: a payout not final or cancelled, or a record still kept.
func WithdrawBlocksHubDelete(r WithdrawRetention, now int64) bool {
	return r.EndedAt == 0 || WithdrawRecordRetained(r, now)
}

// WithdrawNoticeDelay is the random wait before a state notice: 600 s plus a
// uniform value in [0, 600) s, at millisecond resolution, from rand.
func WithdrawNoticeDelay(rand io.Reader) (time.Duration, error) {
	const span = 600_000 // ms
	const limit = (1<<64 - 1) / span * span
	var b [8]byte
	for {
		if _, err := io.ReadFull(rand, b[:]); err != nil {
			return 0, fmt.Errorf("nipcash: notice delay: %w", err)
		}
		if v := binary.BigEndian.Uint64(b[:]); v < limit {
			return 600*time.Second + time.Duration(v%span)*time.Millisecond, nil
		}
	}
}
