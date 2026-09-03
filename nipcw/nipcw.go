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
// See https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CW.md for
// the full spec this package implements.
package nipcw

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
