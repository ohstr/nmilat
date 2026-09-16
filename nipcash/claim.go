package nipcash

import "errors"

// NoLocalIdentity documents an absent identity at CheckClaim/MatchClaim
// call sites — same pattern as the stdlib's http.NoBody: the underlying
// type is still a plain string ("" can never be a valid hex pubkey, so
// it's already an unambiguous sentinel on its own, the same convention
// bearerRecipient.identityValue() already uses for "not applicable"),
// this just gives call sites a name instead of an unexplained "".
const NoLocalIdentity = ""

// ErrClaimNotFound is returned by CheckClaim when tok has no matching,
// unclaimed recipient on the Cash Hub it's checked against.
var ErrClaimNotFound = errors.New("nipcash: no matching, unclaimed recipient on this Cash Hub")

// CheckClaimResult is everything a caller needs to decide whether/how to
// act on a cash bill, resolved by actually asking its Cash Hub — no
// local storage concept; that's entirely the caller's own.
type CheckClaimResult struct {
	IsBearer     bool
	AmountMillis uint64  // authoritative, from list_recipients
	MinterPubkey *string // non-nil only if a verified mint-provenance signature is present
	// RedeemFeeMillis/NetRedeemableMillis/ExpiresAt mirror the matched
	// RecipientStatus row's own fields — surfaced here so a caller
	// building a pre-spend preview doesn't need a second lookup.
	RedeemFeeMillis     uint64
	NetRedeemableMillis uint64
	ExpiresAt           *int64
}

// MatchClaim is the pure matching rule CheckClaim uses — kept as its own
// function (not inlined into the network-calling method) so it's
// unit-testable with a hand-built []RecipientStatus, no dial needed,
// mirroring VerifyProvenance's own split (protocol logic lives in
// nipcash, not nipcash/client). Only ever considers an unclaimed
// recipient a match: bearer matches any unclaimed bearer entry,
// non-bearer matches only an unclaimed entry whose IdentityValue equals
// asPubkeyHex exactly. asPubkeyHex == NoLocalIdentity never matches a
// non-bearer entry (no local identity to compare against).
//
// connection_key matching isn't implemented — a caller checking a
// connection_key-bound token gets no match today, same as before this
// existed.
func MatchClaim(recipients []RecipientStatus, isBearer bool, asPubkeyHex string) (amountMillis uint64, ok bool) {
	for _, r := range recipients {
		if r.Claimed {
			continue
		}
		matched := (isBearer && r.IdentityType == identityTypeBearer) ||
			(!isBearer && r.IdentityType == identityTypePubkey && asPubkeyHex != NoLocalIdentity && r.IdentityValue == asPubkeyHex)
		if matched {
			return r.AmountMillis, true
		}
	}
	return 0, false
}

// MatchClaimAuto is MatchClaim's caller-friendly wrapper: a caller
// checking a bill doesn't reliably know in advance whether it's
// bearer-mode or identity-bound — a token's identity_required TLV is
// only "a best-effort hint... NOT a live guarantee" (§Redemption
// Metadata), since it can go stale after the wallet it describes is
// reassigned. Tries a pubkey match (if asPubkeyHex is given) then a
// bearer match, live. Safe, not ambiguous: a wallet is always all-bearer
// or all identity-bound, never mixed, so at most one attempt can match.
//
// Returns the full matched RecipientStatus row, not just its amount, so
// a caller can also read net_redeemable/redeem_fee/expires_at off it
// without a second lookup.
func MatchClaimAuto(recipients []RecipientStatus, asPubkeyHex string) (recipient RecipientStatus, ok bool) {
	for _, r := range recipients {
		if r.Claimed {
			continue
		}
		matched := r.IsBearer() ||
			(r.IdentityType == identityTypePubkey && asPubkeyHex != NoLocalIdentity && r.IdentityValue == asPubkeyHex)
		if matched {
			return r, true
		}
	}
	return RecipientStatus{}, false
}
