package nipAZ

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipIC"
)

var (
	// ErrUnresolved: no current attestation of a trusted IA (the request's
	// ia, when it has one) resolves the ConnectionKey to a pubkey.
	ErrUnresolved = errors.New("nipAZ: no current trusted attestation resolves this identity")
	// ErrSweepRefused: the claimant is not the pubkey held value may be swept to.
	ErrSweepRefused = errors.New("nipAZ: the claimant may not sweep this held value")
)

// ResolveIdentity is how an LNURL server resolves a request's p (or P) to a
// Nostr pubkey (NIP-AZ §The ia Tag, §r / R — Resolved Identity). A pubkey
// identity is returned as is, with no lookup. For a ConnectionKey it runs
// nipIC.Evaluate over claims (the 35521s queried by the key as their d tag)
// with trust narrowed to ia when ia is set, so only that IA's current
// attestation resolves the key; with ia empty any IA trust accepts counts, the
// latest attestation winning. It returns the Verified pubkey or ErrUnresolved.
//
// The key comes only from id, never from a 35521's content or a receipt's
// handle. A server sets AltZapReceiptParams.ResolvedRecipientPubkey or
// ResolvedSenderPubkey only from this result, and only with LinkAuthorized.
func ResolveIdentity(ctx context.Context, id Identity, ia string, claims []*nip01.Event, src nipIC.AttestationSource, trust func(string) bool, now time.Time) (string, error) {
	if id.IsZero() {
		return "", fmt.Errorf("%w: no identity", ErrUnresolved)
	}
	if !isLowerHex64(id.value) {
		return "", ErrInvalidIdentityTag
	}
	if id.webIdentity == "" {
		return id.value, nil
	}
	if ia != "" && !isLowerHex64(ia) {
		return "", ErrInvalidIATag
	}
	if src == nil || trust == nil {
		return "", fmt.Errorf("%w: no attestation source or trusted IAs", ErrUnresolved)
	}
	narrowed := func(author string) bool {
		if ia != "" && author != ia {
			return false
		}
		return trust(author)
	}
	for _, v := range nipIC.Evaluate(ctx, ConnectionKey(id.value), claims, src, narrowed, now) {
		if v.State == nipIC.Verified && v.Attestation != nil && v.Attestation.Platform == id.webIdentity {
			return v.Pubkey, nil
		}
	}
	return "", ErrUnresolved
}

// HeldValue is value an LNURL server holds in custody for a request's p: the
// identity, and the request's ia ("" when it had none). Value held for a p
// carrying ia is held against that ConnectionKey and IA together.
type HeldValue struct {
	Key Identity
	IA  string
}

// SweepAllowed reports whether held value may be swept, claimed or withdrawn
// to claimant (NIP-AZ §Custodial Settlement). For a pubkey Key the claimant
// must be that pubkey. For a ConnectionKey the claimant must be the pubkey
// ResolveIdentity returns with h.IA: when h.IA is set only that IA's current
// attestation releases the value, and a valid, current attestation for the
// same key from another trusted IA does not; with h.IA empty any trusted IA's
// current attestation counts. Run it before every claim or withdrawal.
func SweepAllowed(ctx context.Context, h HeldValue, claimant string, claims []*nip01.Event, src nipIC.AttestationSource, trust func(string) bool, now time.Time) error {
	if h.Key.IsZero() {
		return fmt.Errorf("%w: no identity", ErrSweepRefused)
	}
	if h.Key.webIdentity == "" {
		if h.IA != "" || claimant != h.Key.value {
			return ErrSweepRefused
		}
		return nil
	}
	resolved, err := ResolveIdentity(ctx, h.Key, h.IA, claims, src, trust, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSweepRefused, err)
	}
	if resolved != claimant {
		return ErrSweepRefused
	}
	return nil
}
