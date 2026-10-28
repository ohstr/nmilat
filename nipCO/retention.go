package nipCO

// OrderRetention is what decides how long a Hub keeps an order record (NIP-CO
// §Reading an Order). Deadline is the order call's deadline and Horizon the
// Hub's max_request_age. Seen is any payment seen; Watched that the Hub still
// watches the on-chain address; BillLiveOrTombstoned that a bill the Lightning
// order minted is live or inside its tombstone window.
type OrderRetention struct {
	Payment                  string
	PayBy, Deadline, Horizon int64
	Seen, Watched            bool
	BillLiveOrTombstoned     bool
}

// OrderRetained reports whether the Hub MUST keep the order at now: until
// pay_by, until deadline + H even unpaid, an on-chain order with a payment while
// its address is watched, a Lightning order while a bill it minted is live or
// tombstoned. false means the Hub MAY drop it.
func OrderRetained(r OrderRetention, now int64) bool {
	return now <= r.PayBy || now <= r.Deadline+r.Horizon ||
		(r.Payment == PaymentOnchain && r.Seen && r.Watched) ||
		(r.Payment == PaymentLightning && r.BillLiveOrTombstoned)
}

// UnmintedPayments are an order's payments seen and not minted. Confirmed are
// those at their tier (Lightning: settled); Unconfirmed are on-chain outputs
// seen in the mempool or in a block below their tier and not dropped from the
// mempool; LastSeenAt is the latest time one of those was seen; MaxWait the
// Hub's setting for how long it waits on them.
type UnmintedPayments struct {
	Confirmed, Unconfirmed int
	LastSeenAt, MaxWait    int64
}

// OrderBlocksHubDelete reports whether the order blocks deleting its Cash Hub
// at now: OrderRetained without the on-chain watch clause (a paid on-chain order
// kept only to watch its address does not block, and deleting the Hub ends the
// watch), or a payment seen and not yet minted: a confirmed one until it is
// minted, an unconfirmed one while now ≤ LastSeenAt + MaxWait.
func OrderBlocksHubDelete(r OrderRetention, u UnmintedPayments, now int64) bool {
	return now <= r.PayBy || now <= r.Deadline+r.Horizon ||
		(r.Payment == PaymentLightning && r.BillLiveOrTombstoned) ||
		u.Confirmed > 0 ||
		(u.Unconfirmed > 0 && now <= u.LastSeenAt+u.MaxWait)
}

// OrderHubDeleteAt is the earliest time at which OrderBlocksHubDelete turns
// false absent new facts: 1 + max(pay_by, deadline + H, and LastSeenAt +
// MaxWait while an unconfirmed payment waits). ok is false while a confirmed
// payment waits to be minted or a Lightning bill is live or tombstoned.
func OrderHubDeleteAt(r OrderRetention, u UnmintedPayments) (at int64, ok bool) {
	if u.Confirmed > 0 || (r.Payment == PaymentLightning && r.BillLiveOrTombstoned) {
		return 0, false
	}
	at = max(r.PayBy, r.Deadline+r.Horizon)
	if u.Unconfirmed > 0 {
		at = max(at, u.LastSeenAt+u.MaxWait)
	}
	return at + 1, true
}

// UnpaidOnchainDeleteAt is when the Hub deletes an on-chain order that saw
// nothing by pay_by: at pay_by, or at deadline + H if that is later.
func UnpaidOnchainDeleteAt(payBy, deadline, horizon int64) int64 {
	return max(payBy, deadline+horizon)
}

// UsedMarkDroppable reports whether an unpaid order's used request_id mark may
// be dropped at now: never for a paid order, and only past deadline + H.
func UsedMarkDroppable(deadline, horizon, now int64, paid bool) bool {
	return !paid && now > deadline+horizon
}
