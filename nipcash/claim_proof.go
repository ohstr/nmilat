package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
)

// The methods a claim proof's m tag names.
const (
	claimMethodRedeem      = "cash_redeem"
	claimMethodWithdraw    = "cash_withdraw"
	claimMethodTransfer    = "cash_transfer"
	claimMethodConsolidate = "cash_consolidate"
)

// Freshness window of kinds 23192, 23193 and 23198 (NIP-CASH §Freshness), in
// seconds, both bounds inclusive.
const (
	freshPastSeconds   = 300
	freshFutureSeconds = 60
	// claimRetainSeconds is how long a consumed claim-proof id is kept past its
	// created_at: 6 minutes.
	claimRetainSeconds = 360
)

// FreshAt reports whether createdAt lies in now − 300 ≤ c ≤ now + 60, with now
// truncated to whole unix seconds.
func FreshAt(createdAt int64, now time.Time) bool {
	n := now.Unix()
	return createdAt >= n-freshPastSeconds && createdAt <= n+freshFutureSeconds
}

// ClaimRetainUntil is the earliest time a Hub may forget a consumed claim-proof
// id: its created_at plus 6 minutes.
func ClaimRetainUntil(createdAt int64) int64 { return createdAt + claimRetainSeconds }

// ClaimBinding is what a kind-23198 claim proof binds, by method (NIP-CASH §Claim
// Proofs): every proof carries d (Wallet) and m (Method); cash_redeem adds
// bolt11_hash; cash_withdraw adds q (QuoteID); cash_transfer adds
// new_identity_hash and amount_millis; cash_consolidate adds those and s
// (SourcesHash).
type ClaimBinding struct {
	Method          string
	Wallet          string
	Bolt11Hash      string
	QuoteID         string
	NewIdentityHash string
	AmountMillis    *uint64
	SourcesHash     string
}

// Tags are the claim proof's binding tags: d, m, then the method's own, in that
// order. A connection_key credential appends connection_key and e.
func (b ClaimBinding) Tags() [][]string {
	tags := [][]string{{"d", b.Wallet}, {"m", b.Method}}
	switch b.Method {
	case claimMethodRedeem:
		tags = append(tags, []string{"bolt11_hash", b.Bolt11Hash})
	case claimMethodWithdraw:
		tags = append(tags, []string{"q", b.QuoteID})
	case claimMethodTransfer, claimMethodConsolidate:
		tags = append(tags, []string{"new_identity_hash", b.NewIdentityHash})
		if b.AmountMillis != nil {
			tags = append(tags, []string{"amount_millis", strconv.FormatUint(*b.AmountMillis, 10)})
		}
		if b.Method == claimMethodConsolidate {
			tags = append(tags, []string{"s", b.SourcesHash})
		}
	}
	return tags
}

// SourcesHash is the s tag of a cash_consolidate claim proof: the lowercase hex
// sha256 of every source wallet pubkey, in sources order, as 64 lowercase hex.
func SourcesHash(walletPubkeys []string) (string, error) {
	h := sha256.New()
	for _, w := range walletPubkeys {
		if !isLowerHex64(w) {
			return "", fmt.Errorf("nipcash: source wallet %q is not 64 lowercase hex", w)
		}
		h.Write([]byte(w))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NewIdentityHash is the new_identity_hash a target binds:
// sha256(identity_type ":" identity_value ":" ia_pubkey), hex.
func NewIdentityHash(t Target) string { return newIdentityHash(t) }

// NewIdentityHashOf is the same hash from the raw wire fields, for a Hub.
func NewIdentityHashOf(identityType, identityValue, iaPubkey string) string {
	sum := sha256.Sum256([]byte(identityType + ":" + identityValue + ":" + iaPubkey))
	return hex.EncodeToString(sum[:])
}

// ClaimExpectation is what a Hub expects a claim proof to bind, and how it
// judges the signer.
type ClaimExpectation struct {
	Binding ClaimBinding
	// SliceType is the slice's identity_type: pubkey or connection_key.
	SliceType string
	// SliceValue is the registered pubkey, or the ConnectionKey.
	SliceValue string
	// SliceIA is the ia_pubkey recorded on a connection_key slice.
	SliceIA string
	// Attestation is the raw attestation_event JSON string (connection_key).
	Attestation string
	// IATrusted reports whether the wallet owner's allowlist holds an IA now.
	IATrusted func(ia string) bool
	// Consumed reports a claim-proof id the Hub already consumed.
	Consumed func(recomputedID string) bool
}

// ClaimVerdict is a verified claim proof's signer and recomputed id. The Hub
// consumes RecomputedID once the call commits; verifying consumes nothing.
type ClaimVerdict struct{ Signer, RecomputedID string }

// ClaimError is a claim proof refusal with the code a Hub answers.
type ClaimError struct {
	Code   string // UNAUTHORIZED or RESTRICTED
	Reason string
}

func (e *ClaimError) Error() string { return "nipcash: claim proof " + e.Code + ": " + e.Reason }

func unauthorized(format string, a ...any) error {
	return &ClaimError{Code: "UNAUTHORIZED", Reason: fmt.Sprintf(format, a...)}
}

// claimSchema is the exact tag set of a claim proof, by method and slice type.
func claimSchema(method, sliceType string) (map[string]bool, bool) {
	tags := map[string]bool{"d": true, "m": true}
	switch method {
	case claimMethodRedeem:
		tags["bolt11_hash"] = true
	case claimMethodWithdraw:
		tags["q"] = true
	case claimMethodTransfer:
		tags["new_identity_hash"], tags["amount_millis"] = true, true
	case claimMethodConsolidate:
		tags["new_identity_hash"], tags["amount_millis"], tags["s"] = true, true, true
	default:
		return nil, false
	}
	switch sliceType {
	case identityTypePubkey:
	case identityTypeConnectionKey:
		tags["connection_key"], tags["e"] = true, true
	default:
		return nil, false
	}
	return tags, true
}

// hexTags are the claim-proof tags whose value is 64 lowercase hex.
var hexTags = map[string]bool{"d": true, "bolt11_hash": true, "q": true, "new_identity_hash": true, "s": true,
	"connection_key": true, "e": true}

// VerifyClaimProof verifies a kind-23198 claim proof against what the Hub
// expects (NIP-CASH §Claim Proofs). Cheap checks run before any signature: JSON
// shape, kind, freshness, the exact tag schema with its encodings, the bound
// values, the consumed set; then the id and signature; then the signer (for a
// connection_key slice, its attestation's checks and signature). Every failure
// is a *ClaimError with UNAUTHORIZED, except an attestation by an IA the wallet
// owner no longer trusts, which is RESTRICTED once everything else holds.
// It never consumes the proof.
func VerifyClaimProof(raw string, want ClaimExpectation, now time.Time) (ClaimVerdict, error) {
	var ev nip01.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return ClaimVerdict{}, unauthorized("not an event: %v", err)
	}
	if ev.Kind != KindClaimProof {
		return ClaimVerdict{}, unauthorized("kind %d", ev.Kind)
	}
	if ev.Content != "" {
		return ClaimVerdict{}, unauthorized("content is not empty")
	}
	if !isLowerHex64(ev.PubKey) {
		return ClaimVerdict{}, unauthorized("signer is not 64 lowercase hex")
	}
	if !FreshAt(int64(ev.CreatedAt), now) { //nolint:gosec // event timestamps are seconds
		return ClaimVerdict{}, unauthorized("created_at %d is outside the freshness window", ev.CreatedAt)
	}
	schema, ok := claimSchema(want.Binding.Method, want.SliceType)
	if !ok {
		return ClaimVerdict{}, unauthorized("no claim proof for method %q on a %q slice", want.Binding.Method, want.SliceType)
	}
	got := map[string]string{}
	for _, tag := range ev.Tags {
		if len(tag) == 0 {
			return ClaimVerdict{}, unauthorized("empty tag")
		}
		name := tag[0]
		if !schema[name] {
			return ClaimVerdict{}, unauthorized("tag %q is not one this method and slice use", name)
		}
		if len(tag) != 2 {
			return ClaimVerdict{}, unauthorized("tag %q is not one string", name)
		}
		if _, dup := got[name]; dup {
			return ClaimVerdict{}, unauthorized("tag %q repeated", name)
		}
		if hexTags[name] && !isLowerHex64(tag[1]) {
			return ClaimVerdict{}, unauthorized("tag %q is not 64 lowercase hex", name)
		}
		got[name] = tag[1]
	}
	for name := range schema {
		if _, ok := got[name]; !ok {
			return ClaimVerdict{}, unauthorized("tag %q missing", name)
		}
	}
	b := want.Binding
	wantTags := map[string]string{}
	for _, tag := range b.Tags() {
		wantTags[tag[0]] = tag[1]
	}
	if amt, ok := got["amount_millis"]; ok {
		if v, err := strconv.ParseUint(amt, 10, 64); err != nil || strconv.FormatUint(v, 10) != amt {
			return ClaimVerdict{}, unauthorized("amount_millis %q is not unsigned decimal", amt)
		}
	}
	for name, w := range wantTags {
		if got[name] != w {
			return ClaimVerdict{}, unauthorized("tag %q does not match the call", name)
		}
	}
	if want.SliceType == identityTypeConnectionKey && got["connection_key"] != want.SliceValue {
		return ClaimVerdict{}, unauthorized("connection_key is not the slice's")
	}
	if want.Consumed != nil && want.Consumed(ev.ID) {
		return ClaimVerdict{}, unauthorized("already consumed")
	}
	// Only now the id and the signature.
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return ClaimVerdict{}, unauthorized("id or signature: %v", err)
	}
	v := ClaimVerdict{Signer: ev.PubKey, RecomputedID: ev.ID}
	switch want.SliceType {
	case identityTypePubkey:
		if ev.PubKey != want.SliceValue {
			return ClaimVerdict{}, unauthorized("signed by another key than the slice's")
		}
	case identityTypeConnectionKey:
		trusted, attID, err := verifySliceAttestation(want.Attestation, want.SliceValue, want.SliceIA, ev.PubKey, want.IATrusted, now)
		if err != nil {
			return ClaimVerdict{}, err
		}
		if got["e"] != attID {
			return ClaimVerdict{}, unauthorized("e is not the attestation's id")
		}
		if !trusted {
			return ClaimVerdict{}, &ClaimError{Code: "RESTRICTED", Reason: "the slice's IA is not on the wallet owner's allowlist"}
		}
	}
	return v, nil
}

// ItemSignerMatchesClaim reports whether an item proof was signed by the key that
// signed the item's claim proof; a Hub treats any other item proof as one that
// does not verify.
func ItemSignerMatchesClaim(itemSigner string, v ClaimVerdict) bool {
	return itemSigner != "" && itemSigner == v.Signer
}

// AttestationExpectation is what a slice's attestation must show without a claim
// proof (cash_withdraw_quote).
type AttestationExpectation struct {
	SliceValue, SliceIA, Signer string
	IATrusted                   func(ia string) bool
}

// VerifySliceAttestation runs a connection_key slice's attestation checks
// without a claim proof: kind 35522, id and signature, author = SliceIA, d =
// SliceValue, p = Signer, platform, evidence and an unpassed expiration. err
// means it names no slice; trusted is false when the IA is not on the allowlist.
func VerifySliceAttestation(raw string, want AttestationExpectation, now int64) (trusted bool, err error) {
	trusted, _, err = verifySliceAttestation(raw, want.SliceValue, want.SliceIA, want.Signer, want.IATrusted, time.Unix(now, 0))
	return trusted, err
}

func verifySliceAttestation(raw, sliceValue, sliceIA, signer string, iaTrusted func(string) bool, now time.Time) (bool, string, error) {
	var ev nip01.Event
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return false, "", unauthorized("attestation is not an event: %v", err)
	}
	if ev.Kind != nipIC.KindAttestation {
		return false, "", unauthorized("attestation kind %d", ev.Kind)
	}
	if ev.PubKey != sliceIA {
		return false, "", unauthorized("attestation is not by the slice's IA")
	}
	tag := func(name string) (string, int) {
		v, n := "", 0
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == name {
				v, n = t[1], n+1
			}
		}
		return v, n
	}
	if d, _ := tag("d"); d != sliceValue {
		return false, "", unauthorized("attestation d is not the slice's identity value")
	}
	if p, _ := tag("p"); p != signer {
		return false, "", unauthorized("attestation p is not the signer")
	}
	if _, n := tag("platform"); n == 0 {
		return false, "", unauthorized("attestation has no platform")
	}
	if _, n := tag("evidence"); n == 0 {
		return false, "", unauthorized("attestation has no evidence")
	}
	exp, n := tag("expiration")
	if n == 0 {
		return false, "", unauthorized("attestation has no expiration")
	}
	ts, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || now.Unix() >= ts {
		return false, "", unauthorized("attestation expiration has passed or is malformed")
	}
	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return false, "", unauthorized("attestation id or signature: %v", err)
	}
	return iaTrusted != nil && iaTrusted(sliceIA), ev.ID, nil
}
