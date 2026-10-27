package nipCZ

import (
	"sort"
	"time"

	"github.com/ohstr/nmilat/nipcash"
)

// Count totals Cash Zaps per note (NIP-CZ §Counting), apart from Lightning
// zaps. zaps[i] was verified as verdicts[i] by VerifyClient. A zap counts only
// if its verdict is Countable (rules 1-8, so its Minter is trusted by the reader
// or listed by the recipient), it is to a pubkey, names a target, carries a
// zap bill (TLV 8 = 2), its expires_at is 0 or at least minLife after
// issued_at, and its id is not in deletedBySender (the 9522s their own signer
// deleted with NIP-09; anyone else's deletion is not counted there). A token
// counts once, whatever copies share its w. collapse counts one zap per pair of
// sender and recipient, either way round, so a bill zapped back and forth adds
// once. Anything else may be listed, never totalled. A zap revoked after it
// was issued still counts: a count means "issued to the recipient by a trusted
// Hub", not "received".
func Count(zaps []*CashZap, verdicts []Verdict, deletedBySender map[string]bool, minLife time.Duration, collapse bool) (total uint64, counted []string) {
	type item struct {
		z *CashZap
		v Verdict
	}
	var items []item
	for i, z := range zaps {
		if i < len(verdicts) && z != nil && z.Event != nil {
			items = append(items, item{z, verdicts[i]})
		}
	}
	sort.SliceStable(items, func(a, b int) bool {
		x, y := items[a].z.Event, items[b].z.Event
		if x.CreatedAt != y.CreatedAt {
			return x.CreatedAt < y.CreatedAt
		}
		return x.ID < y.ID
	})
	seenW := map[string]bool{}
	seenPair := map[[2]string]bool{}
	for _, it := range items {
		z := it.z
		if !countable(z, it.v, minLife) || deletedBySender[z.Event.ID] || seenW[z.W] {
			continue
		}
		pair := [2]string{z.Event.PubKey, z.Recipient.Value}
		if pair[0] > pair[1] {
			pair[0], pair[1] = pair[1], pair[0]
		}
		if collapse && seenPair[pair] {
			continue
		}
		seenW[z.W], seenPair[pair] = true, true
		total += z.Amount
		counted = append(counted, z.Event.ID)
	}
	return total, counted
}

func countable(z *CashZap, v Verdict, minLife time.Duration) bool {
	switch {
	case !v.Countable, z.Recipient.IsConnectionKey(), z.E == "" && z.A == "",
		z.Token.Scheme != nipcash.SchemeZapV1, z.IssuedAt == nil, z.ExpiresAt == nil:
		return false
	case *z.ExpiresAt == 0:
		return true
	case *z.ExpiresAt < *z.IssuedAt:
		return false
	}
	return time.Duration(*z.ExpiresAt-*z.IssuedAt)*time.Second >= minLife
}

// PossiblyExpired reports a Cash Zap past its expires_at, which a client MAY
// mark as possibly expired. A 0 or missing expires_at never expires here.
func PossiblyExpired(z *CashZap, now time.Time) bool {
	return z != nil && z.ExpiresAt != nil && *z.ExpiresAt != 0 && now.Unix() >= 0 && uint64(now.Unix()) >= *z.ExpiresAt
}

// SelectCopy picks, among copies of one token (one w), the copy a wallet may
// dial: only copies whose token signature recovers a Minter (rule 6) are
// considered, so a copy carrying other relay hints or another connection
// secret, or a token with no valid provenance, is never dialled. When the
// considered copies recover more than one Minter it returns ErrCopiesDisagree:
// only trust tells them apart (SelectTrustedCopy). Otherwise the earliest copy.
func SelectCopy(copies []*CashZap) (*CashZap, error) {
	return selectCopy(copies, nil)
}

// SelectTrustedCopy is SelectCopy keeping only copies whose Minter passes rule
// 8: trusted by the reader or listed in the recipient's 10522 for the chain.
func SelectTrustedCopy(copies []*CashZap, info *CashZapInfo, trust Trust) (*CashZap, error) {
	return selectCopy(copies, func(z *CashZap, minter string) bool {
		return minterTrust(minter, z.Chain, info, trust, z.Recipient)
	})
}

func selectCopy(copies []*CashZap, keep func(*CashZap, string) bool) (*CashZap, error) {
	var best *CashZap
	minter, w := "", ""
	for _, z := range copies {
		if z == nil || z.Event == nil {
			continue
		}
		if w == "" {
			w = z.W
		} else if z.W != w {
			return nil, ErrCopiesOfDifferentTokens
		}
		m, _ := provenance(z)
		if m == "" || (keep != nil && !keep(z, m)) {
			continue
		}
		switch {
		case minter == "":
			minter = m
		case !SameMinter(minter, m):
			return nil, ErrCopiesDisagree
		}
		if best == nil || z.Event.CreatedAt < best.Event.CreatedAt ||
			(z.Event.CreatedAt == best.Event.CreatedAt && z.Event.ID < best.Event.ID) {
			best = z
		}
	}
	if best == nil {
		return nil, ErrNoVerifiedCopy
	}
	return best, nil
}
