// Package nipcw implements NIP-CW (Circle Wallet): a host extends their own
// Lightning node to a group of people ("a circle") who don't run their own
// node, via a Circle Wallet Hub connection members send a self-service
// create_circle_wallet request to.
//
// This package is the protocol layer only: the Credential abstraction and
// the request/response shapes NIP-CW defines on top of raw NIP-47. It makes
// no network calls and has no opinion on how a caller dials out — see
// nipcw/client for the NWC transport built on top of it.
//
// See https://github.com/ohstr/nips/blob/main/NIP-CW.md for
// the full spec this package implements.
package nipcw

import "github.com/ohstr/nmilat/nip47"

// KindCircleIdentityProof is NIP-CW's own per-call identity proof kind —
// deliberately its own number, not NIP-CASH's 23198 (a structurally
// similar but distinct NIP's proof), and not NIP-IC's 35521 (a long-lived,
// reusable claim, incompatible with this proof's single-use, per-request
// binding — see nipcash.KindClaimProof's own doc comment for the general
// reasoning, which applies identically here). Ephemeral range
// (20000-29999): never independently published to a relay, only ever
// travels embedded inside an already end-to-end-encrypted NIP-47 request.
// Sits directly adjacent to NIP-CASH's 23198 and NIP-47's own 23194-23197
// block, since NIP-CW depends on NIP-47 too.
const KindCircleIdentityProof = 23199

// MethodCreateCircleWallet is the "method" field of a create_circle_wallet
// NIP-47 request.
const MethodCreateCircleWallet = "create_circle_wallet"

// MethodDeleteCircleWallet is the member's own wallet deletion, sent over the
// wallet's connection (NIP-CW §Deleting a Circle Wallet).
const MethodDeleteCircleWallet = nip47.MethodDeleteCircleWallet

// The NIP-47 error codes of NIP-CW §Errors, exported so Hubs and clients share
// one spelling. A join is refused with BAD_REQUEST, UNAUTHORIZED,
// REQUEST_REUSED, NOT_READY, RESTRICTED, WALLET_EXISTS, LIMIT_EXCEEDED,
// RATE_LIMITED, INSUFFICIENT_CAPACITY or NOT_IMPLEMENTED (a join on the standard
// transport); a wallet and a member request add NOT_FOUND,
// INSUFFICIENT_BALANCE, QUOTA_EXCEEDED, PAYMENT_FAILED, ROTATION_PENDING and
// FROZEN.
const (
	// ErrBadRequest: a param is missing or malformed, or the proof passed its
	// freshness window before the join could commit. Nothing was made.
	ErrBadRequest = nip47.ErrBadRequest
	// ErrUnauthorized: the identity proof, item proof or member request did not
	// verify.
	ErrUnauthorized = nip47.ErrUnauthorized
	// ErrRequestReused: the proof was already used; a copy of the join may have
	// made the wallet, so the join is looked up, never read as failed.
	ErrRequestReused = nip47.ErrRequestReused
	// ErrNotReady: the Hub cannot decide membership yet. Retry later.
	ErrNotReady = nip47.ErrNotReady
	// ErrRestricted: not accepting joins, not a member, or a connection key in use.
	ErrRestricted = nip47.ErrRestricted
	// ErrWalletExists: the requester already holds an Active or Suspended Circle
	// Wallet under this Hub.
	ErrWalletExists = nip47.ErrWalletExists
	// ErrLimitExceeded: a requested term is over the Hub's limits.
	ErrLimitExceeded = nip47.ErrLimitExceeded
	// ErrRateLimited: the requester has asked too often. Retry later.
	ErrRateLimited = nip47.ErrRateLimited
	// ErrInsufficientCapacity: the circle's holdings reached its ceiling.
	ErrInsufficientCapacity = nip47.ErrInsufficientCapacity
	// ErrNotImplemented: a join on the standard transport, or rotation not served.
	ErrNotImplemented = nip47.ErrNotImplemented
	// ErrNotFound: a member request names a wallet the Hub does not hold.
	ErrNotFound = nip47.ErrNotFound
	// ErrInsufficientBalance: a payment's full cost exceeds the balance.
	ErrInsufficientBalance = nip47.ErrInsufficientBalance
	// ErrQuotaExceeded: a payment or invoice past a cap or the outbound ceiling.
	ErrQuotaExceeded = nip47.ErrQuotaExceeded
	// ErrPaymentFailed: the payment could not be routed.
	ErrPaymentFailed = nip47.ErrPaymentFailed
	// ErrRotationPending: the wallet already has a pending rotation.
	ErrRotationPending = nip47.ErrRotationPending
	// ErrFrozen: the wallet is frozen, so its current key is refused.
	ErrFrozen = nip47.ErrFrozen
)
