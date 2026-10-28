package listing

import "slices"

// Trust is whom a wallet takes signals from: the user's follows and curators,
// never global counts.
type Trust struct{ Follows, Curators map[string]bool }

// Accepts reports whether author is a follow or a curator.
func (t Trust) Accepts(author string) bool { return t.Follows[author] || t.Curators[author] }

// Signals are what a wallet shows with a listing, each from an accepted author.
// OperatorFollowedBy is set only when the listing's operator is verified.
type Signals struct {
	Recommendations    []*Recommendation
	Reports            []*Report
	OperatorFollowedBy []string
}

// SignalsFor gathers l's signals (§Wallet Rules "Signals"): the recommendations
// (pass NewestRecommendations' output) credited to l by CreditedOffers, the
// reports on l's node (a report applies to every listing of its node), and,
// when operatorOf finds l's operator verified, the accepted accounts among
// operatorFollowers. Only authors t accepts count.
func SignalsFor(l *Listing, t Trust, recs []*Recommendation, reps []*Report, operatorFollowers []string,
	operatorOf func(string) (string, bool)) Signals {
	var s Signals
	if l == nil {
		return s
	}
	addr := l.Address()
	for _, r := range recs {
		if r == nil || !t.Accepts(r.Author) || r.Node != l.NodeIdentity {
			continue
		}
		if slices.Contains(CreditedOffers(r, []*Listing{l}, operatorOf), addr) {
			s.Recommendations = append(s.Recommendations, r)
		}
	}
	for _, r := range reps {
		if r != nil && t.Accepts(r.Author) && r.Node == l.NodeIdentity {
			s.Reports = append(s.Reports, r)
		}
	}
	if operatorOf != nil {
		if _, ok := operatorOf(addr); ok {
			for _, f := range operatorFollowers {
				if t.Accepts(f) && !slices.Contains(s.OperatorFollowedBy, f) {
					s.OperatorFollowedBy = append(s.OperatorFollowedBy, f)
				}
			}
		}
	}
	return s
}

// RankKey is l's sort key: signalled listings (a recommendation or a verified
// operator followed by a trusted account) before unsignalled ones, then fresh
// (at most StaleAfterSecs old) before stale, then newest first. Reports are
// shown, not ranked on.
func RankKey(l *Listing, s Signals, now int64) (signalled, fresh bool, createdAt int64) {
	createdAt = l.CreatedAt()
	return len(s.Recommendations) > 0 || len(s.OperatorFollowedBy) > 0, now-createdAt <= StaleAfterSecs, createdAt
}

// RankLess orders two listings by RankKey: a before b.
func RankLess(a *Listing, sa Signals, b *Listing, sb Signals, now int64) bool {
	as, af, ac := RankKey(a, sa, now)
	bs, bf, bc := RankKey(b, sb, now)
	if as != bs {
		return as
	}
	if af != bf {
		return af
	}
	return ac > bc
}
