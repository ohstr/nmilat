package nipcash

import (
	"errors"
	"fmt"
)

// The horizon H, max_request_age, in seconds (NIP-CASH §Deadlines).
const (
	// MinMaxRequestAge is the smallest H a Hub may announce.
	MinMaxRequestAge = 60
	// AdvisedMaxRequestAge is the largest H a Hub SHOULD announce.
	AdvisedMaxRequestAge = 86400
	// DefaultMaxRequestAge is the RECOMMENDED H.
	DefaultMaxRequestAge = 300
	// MinPublishMargin is how many seconds must remain before a call's deadline
	// just before it is published; with less, the client does not send it.
	MinPublishMargin = 20
)

var (
	ErrDeadlineMissing = errors.New("nipcash: the call has no deadline")
	ErrDeadlinePassed  = errors.New("nipcash: the call's deadline has passed")
	ErrDeadlineTooFar  = errors.New("nipcash: the call's deadline lies more than H past its arrival")
	ErrHorizonUnusable = errors.New("nipcash: the hub's max_request_age is below 60 seconds")
)

// DeadlineWindow is how far ahead a client sets a call's deadline for a Hub of
// horizon H: min(60, ⌊H/2⌋) seconds, leaving room for clock skew and relay delay.
func DeadlineWindow(horizon int64) int64 { return min(60, horizon/2) }

// CheckDeadline is a Hub's arrival check of a call's deadline: missing (≤ 0),
// passed (now > deadline) and more than H ahead (deadline > now + H) are refused;
// a deadline exactly H ahead is accepted. A horizon below 60 is unusable.
func CheckDeadline(deadline, now, horizon int64) error {
	switch {
	case horizon < MinMaxRequestAge:
		return fmt.Errorf("%w: %d", ErrHorizonUnusable, horizon)
	case deadline <= 0:
		return ErrDeadlineMissing
	case now > deadline:
		return ErrDeadlinePassed
	case deadline > now+horizon:
		return ErrDeadlineTooFar
	}
	return nil
}

// CommitAllowed reports whether a call may commit at now: never after its
// deadline (a later commit is refused BAD_REQUEST, final).
func CommitAllowed(deadline, now int64) bool { return now <= deadline }

// RecordRetained reports the minimum retention of a request_id record: true while
// now ≤ deadline + H, when the Hub MUST keep it. False means it MAY drop it (a
// record kept longer still answers done), never that it must.
func RecordRetained(now, deadline, horizon int64) bool { return now <= deadline+horizon }

// TombstoneAnswerable reports whether a destroyed bill's tombstone is still
// answered: now ≤ retained_until.
func TombstoneAnswerable(now, retainedUntil int64) bool { return now <= retainedUntil }

// SliceLive reports whether a slice has not expired: nil or 0 never expires;
// otherwise now ≤ expires_at.
func SliceLive(now int64, expiresAt *int64) bool {
	return expiresAt == nil || *expiresAt == 0 || now <= *expiresAt
}
