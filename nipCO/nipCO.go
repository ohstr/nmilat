// Package nipCO implements NIP-CO (Cash Order): ordering a NIP-CASH bill from a
// Cash Hub and paying for it over Lightning or on-chain, through an Order
// connection the Hub publishes.
//
// This package is the protocol layer only: the cashorder1 codec, the selling
// terms, the order fee and confirmation tiers, the cash_order request and order
// shapes, the buyer key, the kind-23189 order notice, and the pure decisions a
// Hub makes (placement steps 2 to 5, order state, retention). It makes no
// network calls; see nipCO/client for ordering over the private transport.
//
// See https://github.com/ohstr/nips/blob/main/NIP-CO.md for the spec.
package nipCO

import "errors"

var (
	// ErrOrderConnection is a cashorder1 string that does not decode or encode.
	ErrOrderConnection = errors.New("nipCO: invalid order connection")
	// ErrOrderTerms is a get_info cash_order object that does not parse or
	// breaks the rules of NIP-CO §Terms.
	ErrOrderTerms = errors.New("nipCO: invalid order terms")
	// ErrOrderRequest is a cash_order request a client refuses to build.
	ErrOrderRequest = errors.New("nipCO: invalid cash_order request")
	// ErrOrderReply is an order reply or lookup result that does not have the
	// shape of NIP-CO §Response. The call stays pending; it is never read as
	// unknown.
	ErrOrderReply = errors.New("nipCO: malformed order")
	// ErrBuyerKeyUnusable is a buyer-key digest that is zero or not below the
	// secp256k1 group order: the client generates a new cash secret.
	ErrBuyerKeyUnusable = errors.New("nipCO: the buyer key derived from this cash secret is unusable")
	// ErrOrderAmount is an amount or fee computation that overflows.
	ErrOrderAmount = errors.New("nipCO: order amount out of range")
)
