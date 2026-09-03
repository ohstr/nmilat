// Package nipcash implements NIP-CASH (Cash Hub): a Chaumian ecash system
// built directly on NIP-47 (Nostr Wallet Connect). A Cash Hub mints cash
// tokens — bech32 strings that carry real, spendable value the moment
// they're minted, packaged as a specially-scoped NWC connection — that a
// holder can redeem to a Lightning invoice, hand on whole, split part off
// while keeping the rest, or combine with other tokens from the same Hub.
//
// This package is the protocol layer only: the Recipient/Credential/
// BearerTarget/Source abstractions, the cash-token TLV codec, mint-provenance
// verification, and the request/response shapes NIP-CASH defines on top of
// raw NIP-47. It makes no network calls and has no opinion on how a caller
// dials out — see nipcash/client for the NWC transport built on top of it.
//
// See https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CASH.md
// for the full spec this package implements.
package nipcash

import "errors"

// KindClaimProof is NIP-CASH's own per-call proof of identity, used by
// cash_redeem/cash_transfer/cash_consolidate: a fresh, single-use event
// signed for each call, bound to one specific wallet and one specific
// invoice/new_identity/amount. It is deliberately NOT NIP-IC's kind 35521
// (Identity Connection) — that claim is long-lived and reusable by design,
// which would reopen the exact replay surface this proof exists to close on
// a shared cash_wallet connection every co-recipient can decrypt. It is also
// never independently published to a relay: it only ever travels embedded
// inside an already end-to-end-encrypted NIP-47 request body, which is why
// it lives in the ephemeral range (20000-29999) rather than the
// addressable/parameterized-replaceable range NIP-IC's claim correctly uses.
// Sits directly adjacent to NIP-47's own 23194-23197 block, since NIP-CASH
// depends on NIP-47.
const KindClaimProof = 23198

// NIP-CASH method names, used as the "method" field of a NIP-47 request.
const (
	MethodMintCash        = "mint_cash"
	MethodCashRedeem      = "cash_redeem"
	MethodCashTransfer    = "cash_transfer"
	MethodCashConsolidate = "cash_consolidate"
	MethodListRecipients  = "list_recipients"
)

// Identity type strings used on the wire (a request/response's
// "identity_type" field). Callers never see these directly — Recipient and
// Credential exist precisely so no identity_type string literal needs to
// appear in caller code.
const (
	identityTypePubkey        = "pubkey"
	identityTypeConnectionKey = "connection_key"
	identityTypeBearer        = "bearer"
)

var (
	// ErrMixedBearerAllocation is returned by MintCash when a bearer
	// allocation is mixed with any other entry in the same call — a bearer
	// slice's wallet MUST always be single-recipient (NIP-CASH §Minting
	// Cash), so this is rejected client-side before ever reaching the wire.
	ErrMixedBearerAllocation = errors.New("nipcash: a bearer allocation must be the only entry in a mint_cash call")

	// ErrTooFewSources is returned by CashConsolidate when fewer than two
	// sources are given — consolidating fewer than two slices isn't a
	// combine operation (NIP-CASH §Consolidating Tokens).
	ErrTooFewSources = errors.New("nipcash: cash_consolidate requires at least two sources")

	// ErrBearerSource is returned by CashConsolidate when a source is
	// bearer-identified. Unlike cash_transfer/cash_redeem, cash_consolidate
	// can name a source wallet other than the caller's own, so a bearer
	// source's secret would transit over a connection with no claim on it
	// (NIP-CASH §Security Considerations) — rejected client-side, not just
	// deferred to the server.
	ErrBearerSource = errors.New("nipcash: cash_consolidate does not accept a bearer-identified source")

	// ErrConsolidateTargetNotPubkey is returned by CashConsolidate when the
	// target identity isn't a bare pubkey — this revision of NIP-CASH only
	// accepts a pubkey new_identity for a consolidated wallet.
	ErrConsolidateTargetNotPubkey = errors.New("nipcash: cash_consolidate requires a pubkey new_identity")

	// ErrWrongCredentialForTarget is returned when a BearerTarget is used
	// where a Recipient is expected, or vice versa — mint_cash's bearer
	// recipient gets its secret minted by the Hub (safe, since it travels
	// over the Hub's own single-owner connection), while cash_transfer's
	// bearer target requires the caller to generate the secret themselves
	// (the response travels back over a shared connection every
	// co-recipient can decrypt) — see BearerTarget's own doc comment.
	ErrWrongCredentialForTarget = errors.New("nipcash: Anyone() cannot be used where a BearerTarget is required")
)
