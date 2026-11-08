package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// A Pre-Authorisation grant delegates limited authority over a bill to another
// key, so a holder can let someone *read* or *pull from* a bill without handing
// over the bearer connection secret (NIP-CASH §Pre-Authorisation, proposed).
//
// It is a signed event whose signer is the bill's connection secret -- the same
// key that signs a kind-23193 bill proof -- so the hub recovers the same x-only
// pubkey it already compares against the bill's connection pubkey. The hub
// accepts a grant IN PLACE OF a bill proof, but only when the item's own
// kind-23192 slice proof is signed by the grant's delegate. That binding is the
// single load-bearing rule: without it a leaked grant would be a second bearer
// secret, which is exactly the problem a grant exists to avoid.
//
// Unlike a proof, a grant deliberately binds NO envelope nonce and NO params
// hash. A proof is pinned to one envelope so it cannot be banked and replayed; a
// grant is meant to be reused across the delegate's own envelopes within its
// lifetime (one grant lets an accountant poll a bill, or a payer pull up to a
// cap, over many requests). Its authority is scoped by target + hub + method
// (+ an optional amount cap) and bounded in time by its OWN expiration.
const (
	tagDelegate  = "delegate" // x-only pubkey authorised to use this grant
	tagMaxAmount = "max"      // optional: max amount in mloki the delegate may move
	tagSingleUse = "su"       // optional: "1" if the grant may be used only once
)

var (
	ErrGrantMalformed   = errors.New("transport: pre-auth grant is malformed")
	ErrGrantWrongTarget = errors.New("transport: grant is bound to a different wallet")
	ErrGrantWrongHub    = errors.New("transport: grant is bound to a different hub")
	ErrGrantWrongMethod = errors.New("transport: grant does not authorise this method")
	ErrGrantExpired     = errors.New("transport: grant has expired")
	ErrGrantFromFuture  = errors.New("transport: grant created_at is in the future")
	ErrGrantSignature   = errors.New("transport: grant signature is invalid")
)

// GrantParams is what a holder signs when delegating authority.
type GrantParams struct {
	Delegate  string // x-only pubkey of the key that may use the grant
	Target    string // the bill's wallet pubkey (what the delegated items act on)
	HubXOnly  string // the hub's x-only identity: no cross-hub replay
	Method    string // the one method the grant authorises (e.g. "cash_status")
	ExpiresAt int64  // unix seconds the grant is valid until (its own deadline)
	MaxAmount int64  // optional amount cap in mloki; 0 = no cap
	SingleUse bool   // if true, the grant may be redeemed only once
}

// GrantInfo is what VerifyGrant returns for the hub to act on.
type GrantInfo struct {
	ConnKey   string // x-only pubkey that signed the grant: the bill's connection key
	Delegate  string // x-only pubkey the grant authorises: must equal the item proof's signer
	MaxAmount int64  // amount cap in mloki; 0 = no cap
	SingleUse bool   // the grant may be used only once (hub keys single-use on ID)
	ID        string // the grant event's id: a stable unique id for single-use tracking
	ExpiresAt int64  // the grant's own not_after
}

// BuildGrant signs a pre-auth grant with the bill's connection secret.
func BuildGrant(connSecretHex string, g GrantParams) (json.RawMessage, error) {
	if g.Delegate == "" || g.Target == "" || g.HubXOnly == "" || g.Method == "" {
		return nil, fmt.Errorf("%w: delegate, target, hub and method are required", ErrGrantMalformed)
	}
	if g.ExpiresAt <= 0 {
		return nil, fmt.Errorf("%w: expiration is required", ErrGrantMalformed)
	}
	tags := [][]string{
		{tagDelegate, g.Delegate},
		{tagTarget, g.Target},
		{tagHub, g.HubXOnly},
		{tagMethod, g.Method},
		{tagExpiration, strconv.FormatInt(g.ExpiresAt, 10)},
	}
	if g.MaxAmount > 0 {
		tags = append(tags, []string{tagMaxAmount, strconv.FormatInt(g.MaxAmount, 10)})
	}
	if g.SingleUse {
		tags = append(tags, []string{tagSingleUse, "1"})
	}
	ev, err := nip01.NewSignedEvent(KindPreAuthGrant, "", connSecretHex, tags...)
	if err != nil {
		return nil, fmt.Errorf("transport: sign grant: %w", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("transport: marshal grant: %w", err)
	}
	return raw, nil
}

// VerifyGrant checks a grant against the binding the hub computed itself and
// returns the signer (the bill's connection key) and the authorised delegate.
//
// Order mirrors verifyProof: every structural comparison runs before the
// signature, so a grant that fails a binding costs string comparisons, not
// secp256k1 time. The caller still has two checks left that this cannot make:
// the ConnKey must be a live connection of the target bill, and the Delegate
// must equal the item's own slice-proof signer -- the latter is the load-bearing
// anti-bearer-secret rule.
func VerifyGrant(grant json.RawMessage, want GrantBinding, now time.Time) (GrantInfo, error) {
	var ev nip01.Event
	if err := json.Unmarshal(grant, &ev); err != nil {
		return GrantInfo{}, fmt.Errorf("%w: %v", ErrGrantMalformed, err)
	}
	if ev.Kind != KindPreAuthGrant {
		return GrantInfo{}, fmt.Errorf("%w: kind %d, want %d", ErrGrantMalformed, ev.Kind, KindPreAuthGrant)
	}
	if len(ev.PubKey) != keyHexLen || !isLowerHex(ev.PubKey) {
		return GrantInfo{}, fmt.Errorf("%w: signer pubkey must be %d lowercase hex characters", ErrGrantMalformed, keyHexLen)
	}
	if ev.Content != "" {
		return GrantInfo{}, fmt.Errorf("%w: content must be empty", ErrGrantMalformed)
	}

	got, err := grantTags(ev.Tags)
	if err != nil {
		return GrantInfo{}, err
	}

	if got[tagTarget] != want.Target {
		return GrantInfo{}, fmt.Errorf("%w: bound to %q, item targets %q", ErrGrantWrongTarget, got[tagTarget], want.Target)
	}
	if got[tagHub] != want.HubXOnly {
		return GrantInfo{}, fmt.Errorf("%w: bound to %q", ErrGrantWrongHub, got[tagHub])
	}
	if got[tagMethod] != want.Method {
		return GrantInfo{}, fmt.Errorf("%w: authorises %q, item calls %q", ErrGrantWrongMethod, got[tagMethod], want.Method)
	}

	expiresAt, err := strconv.ParseInt(got[tagExpiration], 10, 64)
	if err != nil {
		return GrantInfo{}, fmt.Errorf("%w: expiration %q is not an integer", ErrGrantMalformed, got[tagExpiration])
	}
	// A grant is long-lived by design, so (unlike a proof) there is no past
	// freshness bound: its own expiration is the deadline. Only guard against a
	// grant whose created_at is implausibly in the future.
	n := now.Unix()
	if expiresAt <= n {
		return GrantInfo{}, fmt.Errorf("%w: expired at %d, now %d", ErrGrantExpired, expiresAt, n)
	}
	if int64(ev.CreatedAt) > n+int64(ProofFreshnessFuture/time.Second) { //nolint:gosec // seconds since epoch
		return GrantInfo{}, fmt.Errorf("%w: created_at %d, now %d", ErrGrantFromFuture, ev.CreatedAt, n)
	}

	var maxAmount int64
	if raw := got[tagMaxAmount]; raw != "" {
		if maxAmount, err = strconv.ParseInt(raw, 10, 64); err != nil || maxAmount < 0 {
			return GrantInfo{}, fmt.Errorf("%w: max %q is not a non-negative integer", ErrGrantMalformed, raw)
		}
	}

	if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
		return GrantInfo{}, fmt.Errorf("%w: %v", ErrGrantSignature, err)
	}

	return GrantInfo{
		ConnKey:   ev.PubKey,
		Delegate:  got[tagDelegate],
		MaxAmount: maxAmount,
		SingleUse: got[tagSingleUse] == "1",
		ID:        ev.ID,
		ExpiresAt: expiresAt,
	}, nil
}

// GrantBinding is the part of a grant the hub checks against the item it arrived
// with: the bill, the hub, and the method being called.
type GrantBinding struct {
	Target   string
	HubXOnly string
	Method   string
}

// grantTags collects a grant's tags, rejecting duplicates (an ambiguous grant
// authorises nothing). delegate/target/hub are 64-hex; method/expiration are
// required; max/single_use are optional.
func grantTags(tags [][]string) (map[string]string, error) {
	out := make(map[string]string, 7)
	known := map[string]bool{tagDelegate: true, tagTarget: true, tagHub: true, tagMethod: true, tagExpiration: true, tagMaxAmount: true, tagSingleUse: true}
	hexTag := map[string]bool{tagDelegate: true, tagTarget: true, tagHub: true}
	for _, tag := range tags {
		if len(tag) == 0 || !known[tag[0]] {
			continue
		}
		name := tag[0]
		if len(tag) != 2 {
			return nil, fmt.Errorf("%w: %q tag is not one string", ErrGrantMalformed, name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicate %q tag", ErrGrantMalformed, name)
		}
		if hexTag[name] && (len(tag[1]) != keyHexLen || !isLowerHex(tag[1])) {
			return nil, fmt.Errorf("%w: %q must be %d lowercase hex characters", ErrGrantMalformed, name, keyHexLen)
		}
		out[name] = tag[1]
	}
	for _, name := range []string{tagDelegate, tagTarget, tagHub, tagMethod, tagExpiration} {
		if out[name] == "" {
			return nil, fmt.Errorf("%w: missing %q tag", ErrGrantMalformed, name)
		}
	}
	return out, nil
}
