package nipCP

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

// StatusInput is one answer about a held bill, as NIP-CP §Balance maps it.
// Tombstone is a tombstone from cash_status, cash_redeem, cash_transfer,
// cash_consolidate or a lookup done; NotFound a NOT_FOUND, with ProofByEntryKey
// when its item proof was signed by the entry's identity key (or, for a cash
// entry, made with its secret); OwnSpend the wallet's own successful spend;
// NoAnswer a timeout or nothing heard.
type StatusInput struct {
	Tombstone       *nipcash.Tombstone
	NotFound        bool
	ProofByEntryKey bool
	OwnSpend        bool
	NoAnswer        bool
}

// MapStatus maps an answer to the entry's state, and reports whether it is
// definitive: only a definitive answer may set a final state. A tombstone's
// reason describes how the bill's last live slice ended, so expired and
// reclaimed map to themselves and any other reason, or none, to spent.
func MapStatus(in StatusInput) (State, bool) {
	switch {
	case in.OwnSpend:
		return StateSpent, true
	case in.Tombstone != nil:
		switch in.Tombstone.Reason {
		case nipcash.ReasonExpired:
			return StateExpired, true
		case nipcash.ReasonReclaimed:
			return StateReclaimed, true
		}
		return StateSpent, true
	case in.NotFound && in.ProofByEntryKey:
		return StateReclaimed, true
	}
	return StateUnknown, false
}

// Balance is, per chain, the sum of amount over the live entries.
func Balance(winners map[string]Entry) map[string]uint64 {
	out := map[string]uint64{}
	for _, e := range winners {
		if e.State == StateLive {
			out[e.Chain] += e.Amount
		}
	}
	return out
}

// ExpiresSoon reports a live bill whose expires_at falls within the next
// within: the wallet warns, and claims or redeems it before then.
func ExpiresSoon(e Entry, at time.Time, within time.Duration) bool {
	return e.State == StateLive && e.ExpiresAt != nil && *e.ExpiresAt <= at.Add(within).Unix()
}

// NeedsRekey reports a live cash-mode bill: the wallet SHOULD transfer it to
// the user's pubkey promptly.
func NeedsRekey(e Entry) bool {
	return e.State == StateLive && e.Identity.Type == IdentityCash
}

// NeedsExpiry reports a live bill with no expires_at (an older entry, or a bill
// that never expires): the wallet checks it with cash_status and, if the answer
// gives one, rewrites it with WithExpiry.
func NeedsExpiry(e Entry) bool {
	return e.State == StateLive && e.Cash != "" && e.ExpiresAt == nil
}

// WithExpiry is e at its next rev with expires_at from a Hub's answer; a 0
// (never) leaves it without one.
func WithExpiry(e Entry, expiresAt int64, at int64) Entry {
	n := rewrite(e, at)
	if expiresAt > 0 {
		n.ExpiresAt = &expiresAt
	}
	return n
}

// PruneAfter is how long a final entry MAY be kept before its wrap is removed.
const PruneAfter = 30 * 24 * time.Hour

// Prunable reports a final entry checked at least PruneAfter ago: the wallet
// may delete its wrap.
func Prunable(e Entry, at time.Time) bool {
	return e.State.Final() && e.CheckedAt > 0 && at.Unix()-e.CheckedAt >= int64(PruneAfter/time.Second)
}

const week = 7 * 24 * 60 * 60

// WrapExpiration is a NIP-40 expiration for an entry's wrap (NIP-CP §Writing,
// Expiration): expiresAt plus grace, rounded up to the week, plus 0 to 6 random
// days from rnd (crypto/rand when nil). The wallet still deletes the wrap itself.
func WrapExpiration(expiresAt int64, grace time.Duration, rnd io.Reader) int64 {
	t := expiresAt + int64(grace/time.Second)
	if r := t % week; r != 0 {
		t += week - r
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var b [8]byte
	if _, err := io.ReadFull(rnd, b[:]); err == nil {
		t += int64(binary.BigEndian.Uint64(b[:])%7) * 24 * 60 * 60
	}
	return t
}

// rewrite is e as the next version: rev + 1, checked at at, read-only fields
// cleared (Seal sets the wrap key).
func rewrite(e Entry, at int64) Entry {
	n := e
	n.Rev = e.Rev + 1
	n.CheckedAt = at
	n.WrapKey, n.RumorID, n.RumorCreatedAt, n.WrapID, n.RawState = "", "", 0, "", ""
	n.Secrets = append([]nipcash.PendingSecret(nil), e.Secrets...)
	return n
}

// WithState is e at its next rev in state s, checked at at, keeping its token,
// secret and source (a spent source keeps its token for lookups).
func WithState(e Entry, s State, at int64) Entry {
	n := rewrite(e, at)
	n.State = s
	return n
}
