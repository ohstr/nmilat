package nipcash

// LookupStatus is a cash_lookup answer's status (NIP-CASH §Looking Up a Call).
type LookupStatus string

const (
	LookupDone    LookupStatus = "done"
	LookupPending LookupStatus = "pending"
	LookupUnknown LookupStatus = "unknown"
	LookupExpired LookupStatus = "expired"
)

// Join lookup windows (NIP-CW): a kind-23199 join proof is fresh for 5 minutes,
// and a join lookup uses 6 minutes in place of H.
const (
	JoinFreshness    = 300
	JoinLookupWindow = 360
)

// LookupInput is what a Hub knows when it answers a lookup. Horizon is its
// current H; HaveRecord is a record matched for this caller. For a join
// lookup, a join under another signer is passed as none. For a request_id
// lookup, a record under another authorizer is not passed at all: the Hub
// answers it UNAUTHORIZED before DecideLookup, never unknown.
type LookupInput struct {
	Now, Deadline, Horizon int64
	Join                   bool
	HaveRecord             bool
}

// LookupDecision is the answer: a status, and for pending the retry_after.
type LookupDecision struct {
	Status     LookupStatus
	RetryAfter int64
}

// DecideLookup applies the finality table: a record is done; otherwise, with
// h = H (360 for a join), the lookup's deadline is treated as at most h from now
// for pending (retry_after = that deadline + 1); past the deadline and no later
// than deadline + h it is unknown; later, expired.
func DecideLookup(in LookupInput) LookupDecision {
	if in.HaveRecord {
		return LookupDecision{Status: LookupDone}
	}
	h := in.Horizon
	if in.Join {
		h = JoinLookupWindow
	}
	d := min(in.Deadline, in.Now+h)
	switch {
	case in.Now <= d:
		return LookupDecision{Status: LookupPending, RetryAfter: d + 1}
	case in.Now <= in.Deadline+h:
		return LookupDecision{Status: LookupUnknown}
	default:
		return LookupDecision{Status: LookupExpired}
	}
}
