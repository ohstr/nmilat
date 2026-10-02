package nipcash

// Cash-status scopes, which select how much of the roster a Hub answers with
// (NIP-CASH §Scoping the Roster).
//
// Only meaningful on the private transport, where every item carries a proof
// signed by one specific recipient, so a Hub knows who is asking. On the standard
// transport every recipient holds the SAME connection string, so the Hub cannot
// identify the caller at all — which is why ScopeMine MUST be rejected there
// rather than approximated.
const (
	// ScopeAll returns every recipient's row — the shared roster.
	ScopeAll = "all"
	// ScopeMine returns only the calling recipient's own row.
	ScopeMine = "mine"
)

// CashStatusParams is cash_status' request.
//
// Scope is OPTIONAL, and absent does NOT mean one fixed thing: a Hub reads it as
// ScopeMine on the private transport and ScopeAll on the standard one. The
// defaults differ because the transports differ in what they can know, so a
// client that wants a specific answer regardless of transport must say so.
type CashStatusParams struct {
	Scope string `json:"scope,omitempty"`
	// AttestationEvent lets a connection_key recipient read their own row.
	//
	// A connection_key slice's identity_value is hex(sha256(platform + ":" + externalID)),
	// never a pubkey, so the item's signer can never equal it and a Hub's transport gate
	// has nothing to compare. cash_redeem already requires an IA attestation binding the
	// claimant's keypair to that identity; this is the same evidence, for a read instead of
	// a spend, and a Hub resolves WHICH claim from the attestation itself rather than from
	// anything the caller names.
	//
	// Omit it for pubkey and cash-mode slices, which need nothing: a pubkey slice's
	// identity IS the signer, and a cash-mode slice's secret is its whole authorization.
	AttestationEvent string `json:"attestation_event,omitempty"`
}

// CashStatusRequest is cash_status' wire request.
//
// CashSecret exists for the private transport only. A cash-mode bill has no keypair,
// so its items carry no proof and the secret in params is the whole authorization
// (NIP-CASH §Bearer Items) — and an item with neither is malformed, which the codec
// refuses locally. Without a field to put it in, no cash-mode bill could be read over
// the private transport at all: the item was rejected before it was ever sent, and
// the failure surfaced only against a live hub.
//
// Omitted on the standard transport, where the connection itself is the
// authorization and there is nothing to attach.
type CashStatusRequest struct {
	Scope      string `json:"scope,omitempty"`
	CashSecret string `json:"cash_secret,omitempty"`
	// AttestationEvent is the connection_key counterpart to CashSecret: the evidence
	// that authorizes a read the signer alone cannot. See CashStatusParams.
	AttestationEvent string `json:"attestation_event,omitempty"`
}

// IsValidCashStatusScope reports whether s is a scope a Hub can honour. An empty
// string is valid: it means "the default for this transport".
//
// Exported so a client and a Hub check the same rule rather than each keeping its
// own list — the kind of drift that shows up as a request silently answered with
// the wrong amount of data.
func IsValidCashStatusScope(s string) bool {
	return s == "" || s == ScopeAll || s == ScopeMine
}

// RecipientStatus is one entry of cash_status' response roster —
// includes every recipient this wallet was ever created or split into,
// claimed or not (NIP-CASH §Listing Recipients).
type RecipientStatus struct {
	IdentityType  string `json:"identity_type"`
	IdentityValue string `json:"identity_value,omitempty"`
	AmountMillis  uint64 `json:"amount_millis"`
	Claimed       bool   `json:"claimed"`
	ClaimedAt     *int64 `json:"claimed_at,omitempty"`
	// RedeemFeeMillis/NetRedeemableMillis are this slice's own worst-case
	// redeem-fee quote — a same-node cash_redeem pays out more (up to the
	// full AmountMillis, fee-free); it will never pay out less. See
	// NIP-CASH §The Redeem Fee.
	RedeemFeeMillis     uint64 `json:"redeem_fee_millis"`
	NetRedeemableMillis uint64 `json:"net_redeemable_millis"`
	// MinTransferMillis is this slice's own split floor (NIP-CASH §Splitting
	// a Slice), fixed at creation — check this before attempting a
	// CashTransfer split rather than discovering it from a rejected call.
	MinTransferMillis uint64 `json:"min_transfer_millis"`
	// ExpiresAt is the wallet's own shared redemption deadline — identical
	// on every row, omitted entirely for a wallet that never expires.
	ExpiresAt *int64 `json:"expires_at,omitempty"`
}

// CashStatusResult is cash_status' response, and carries one of two mutually
// exclusive answers.
//
// Recipients is the roster. How much of it arrives depends on the request's Scope
// and on the transport (NIP-CASH §Scoping the Roster): on the standard transport
// it is every slice this bill was created or split into, unscoped, because every
// holder of the connection is indistinguishable there; on the private transport an
// unscoped request returns only the caller's own row, since a per-item proof makes
// the caller identifiable for the first time.
//
// Error/RetainedUntil is the tombstone for a bill that has been spent and
// destroyed. It exists because silence cannot be told apart from a Hub that is
// merely slow or unreachable, which forces every client to choose a wrong
// answer: treat the timeout as retryable and a genuinely spent bill retries
// forever, or treat it as gone and a reachable-Hub outage tells someone their
// funds are lost. Three outcomes replace two:
//
//	roster returned              -> available
//	Error "spent" + RetainedUntil -> definitive, and when the answer stops
//	no answer at all              -> indeterminate; retry, never report spent
//
// Past RetainedUntil the Hub falls back to silence, so the tombstone is never
// wrong — only absent for old bills.
type CashStatusResult struct {
	Recipients []RecipientStatus `json:"recipients,omitempty"`
	// Error is ErrorSpent, or empty on a roster response.
	Error string `json:"error,omitempty"`
	// RetainedUntil is the unix second past which this Hub stops answering
	// for this bill and returns to silence. Set whenever Error is.
	RetainedUntil *int64 `json:"retained_until,omitempty"`
}

// ErrorSpent is CashStatusResult.Error's only current value: this bill existed,
// was spent, and has been destroyed.
const ErrorSpent = "spent"

// IsSpent reports whether r is a tombstone rather than a roster.
func (r CashStatusResult) IsSpent() bool { return r.Error == ErrorSpent }

// IsCash reports whether r is a cash-mode recipient row — the one
// place identityTypeCash's own comparison lives, so a caller outside
// this package (nipcash/client's CheckClaim, say) never needs the
// unexported wire constant itself just to ask this question.
func (r RecipientStatus) IsCash() bool { return r.IdentityType == identityTypeCash }
