package nipIC

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// VerificationState is what a client may show for a Kind 35521 claim (NIP-IC
// §Verification Model).
type VerificationState int

const (
	// Unverified: no 35521 was found for the ConnectionKey.
	Unverified VerificationState = iota
	// Verified: the 35521 points to a trusted IA's current attestation for its
	// own pubkey, and no newer trusted attestation names another.
	Verified
	// Spoofed: a 35521 was found, but no attestation it points to checks out, or
	// a newer trusted attestation names another pubkey.
	Spoofed
)

func (s VerificationState) String() string {
	switch s {
	case Verified:
		return "verified"
	case Spoofed:
		return "spoofed"
	default:
		return "unverified"
	}
}

// MaxAttestationFuture is how far ahead of the verifier's clock an
// attestation's created_at may be and still count: 15 minutes.
const MaxAttestationFuture = 900 * time.Second

// AttestationSource is the relay I/O a Deep Check needs; fetchers live outside
// this package.
type AttestationSource interface {
	// Fetch returns the event a 35521 reference names, from its relay hint.
	Fetch(ctx context.Context, ref AttestationRef) (*nip01.Event, error)
	// Current returns the id of the IA's current 35522 for key on its relay.
	Current(ctx context.Context, ia string, key ConnectionKey) (eventID string, err error)
	// DeletedByAuthor reports a NIP-09 deletion of eventID by ia itself.
	DeletedByAuthor(ctx context.Context, ia, eventID string) (bool, error)
}

// Verdict is the outcome for one 35521 (or, with no 35521 at all, the single
// Unverified verdict). Pubkey is the claim's author; Attestation is the one that
// verified it; Reasons say why references did not count.
type Verdict struct {
	State       VerificationState
	Pubkey      string
	Attestation *Attestation
	Reasons     []string
}

// Evaluate runs NIP-IC's Verification Model for key over the 35521s queried by
// its d tag. The key is the caller's, never one read from a claim's content; a
// claim for another d is ignored. Each reference counts only if every step-3
// check passes; an unreachable source means that reference does not count. Of
// all attestations that count, the latest created_at wins (ties: the lowest
// event id), and claims by any other pubkey are Spoofed.
func Evaluate(ctx context.Context, key ConnectionKey, claims []*nip01.Event, src AttestationSource, trusted func(ia string) bool, now time.Time) []Verdict {
	var out []Verdict
	var winner *Attestation
	for _, ev := range claims {
		claim, err := ParseIdentityConnection(ev)
		if err != nil {
			if ev != nil && ev.Kind == KindIdentityConnection && hasD(ev, key) {
				out = append(out, Verdict{State: Spoofed, Pubkey: ev.PubKey, Reasons: []string{err.Error()}})
			}
			continue
		}
		if claim.ConnectionKey != key {
			continue
		}
		v := Verdict{State: Spoofed, Pubkey: claim.PubKey}
		for _, ref := range claim.Attestations {
			att, reason := deepCheck(ctx, claim, ref, src, trusted, now)
			if att == nil {
				v.Reasons = append(v.Reasons, reason)
				continue
			}
			if mismatch := contentMismatch(claim, att); mismatch != "" {
				v.Reasons = append(v.Reasons, mismatch)
				continue
			}
			if v.Attestation == nil || newer(att, v.Attestation) {
				v.Attestation = att
			}
		}
		if v.Attestation != nil {
			v.State = Verified
			if winner == nil || newer(v.Attestation, winner) {
				winner = v.Attestation
			}
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return []Verdict{{State: Unverified}}
	}
	for i := range out {
		if out[i].State == Verified && out[i].Pubkey != winner.UserPubkey {
			out[i].State = Spoofed
			out[i].Reasons = append(out[i].Reasons, "a newer trusted attestation names another pubkey")
		}
	}
	return out
}

func hasD(ev *nip01.Event, key ConnectionKey) bool {
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == TagDTag && t[1] == string(key) {
			return true
		}
	}
	return false
}

// newer reports a later than b: the latest created_at, ties to the lowest id.
func newer(a, b *Attestation) bool {
	if a.CreatedAt != b.CreatedAt {
		return a.CreatedAt > b.CreatedAt
	}
	return a.ID < b.ID
}

// deepCheck runs step 3 for one reference and returns the attestation when it
// counts, or why it does not.
func deepCheck(ctx context.Context, claim *IdentityConnection, ref AttestationRef, src AttestationSource, trusted func(string) bool, now time.Time) (*Attestation, string) {
	ev, err := src.Fetch(ctx, ref)
	if err != nil || ev == nil {
		return nil, fmt.Sprintf("%s: not fetched", ref.EventID)
	}
	if ev.ID != ref.EventID {
		return nil, fmt.Sprintf("%s: the relay returned another event", ref.EventID)
	}
	att, err := ParseAttestation(ev)
	if err != nil {
		return nil, fmt.Sprintf("%s: %v", ref.EventID, err)
	}
	switch {
	case !trusted(att.PubKey):
		return nil, fmt.Sprintf("%s: not a trusted IA", ref.EventID)
	case att.PubKey == claim.PubKey:
		return nil, fmt.Sprintf("%s: self-attested", ref.EventID)
	case att.ConnectionKey != claim.ConnectionKey || att.Platform != claim.Platform:
		return nil, fmt.Sprintf("%s: d or platform differs from the claim", ref.EventID)
	case att.UserPubkey != claim.PubKey:
		return nil, fmt.Sprintf("%s: p names another pubkey", ref.EventID)
	case att.ExpiresAt != nil && !now.Before(*att.ExpiresAt):
		return nil, fmt.Sprintf("%s: expired", ref.EventID)
	case time.Unix(int64(att.CreatedAt), 0).After(now.Add(MaxAttestationFuture)): //nolint:gosec // a unix time
		return nil, fmt.Sprintf("%s: dated more than 15 minutes ahead", ref.EventID)
	}
	if deleted, err := src.DeletedByAuthor(ctx, att.PubKey, att.ID); err != nil || deleted {
		return nil, fmt.Sprintf("%s: deleted by its IA, or the deletion check failed", ref.EventID)
	}
	if current, err := src.Current(ctx, att.PubKey, claim.ConnectionKey); err != nil || current != att.ID {
		return nil, fmt.Sprintf("%s: not the IA's current attestation", ref.EventID)
	}
	return att, ""
}

// contentMismatch cross-checks the user-controlled content against the
// attestation's evidence: a differing user_id or username makes the claim spoofed.
func contentMismatch(claim *IdentityConnection, att *Attestation) string {
	var c profileContent
	if claim.Content == "" || json.Unmarshal([]byte(claim.Content), &c) != nil {
		return ""
	}
	if (c.UserID != "" && c.UserID != att.Evidence.UserID) || (c.Username != "" && c.Username != att.Evidence.Username) {
		return fmt.Sprintf("%s: content names another account than the evidence", att.ID)
	}
	return ""
}
