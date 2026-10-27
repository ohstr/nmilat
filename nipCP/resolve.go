package nipCP

import "sort"

// NextVersion is the rev of the next write for w: the highest rev of any entry
// with that w, recognised or not, plus 1 (NIP-CP §Writing, Versions).
func NextVersion(all []Entry, w string) uint64 {
	var max uint64
	for _, e := range all {
		if e.W == w && e.Rev > max {
			max = e.Rev
		}
	}
	return max + 1
}

// Resolve picks the current entry per w (NIP-CP §Reading, Resolving): the
// highest rev wins, a final state winning over the other entries of its own rev;
// then the latest rumor created_at; then the lowest rumor id. Entries whose
// state this reader does not recognise are ignored. Copies of one rumor (the
// same rumor id) are one entry. conflicts lists, sorted, each w whose winning
// rev holds more than one distinct rumor: the wallet re-checks that bill with
// cash_status under every identity it holds.
func Resolve(all []Entry) (winners map[string]Entry, conflicts []string) {
	winners = map[string]Entry{}
	rivals := map[string]map[string]bool{}
	for _, e := range all {
		if !e.Recognised() {
			continue
		}
		cur, ok := winners[e.W]
		if !ok {
			winners[e.W] = e
			rivals[e.W] = map[string]bool{e.RumorID: true}
			continue
		}
		switch {
		case e.Rev > cur.Rev:
			winners[e.W] = e
			rivals[e.W] = map[string]bool{e.RumorID: true}
		case e.Rev == cur.Rev:
			rivals[e.W][e.RumorID] = true
			if beats(e, cur) {
				winners[e.W] = e
			}
		}
	}
	for w, ids := range rivals {
		if len(ids) > 1 {
			conflicts = append(conflicts, w)
		}
	}
	sort.Strings(conflicts)
	return winners, conflicts
}

// beats orders two entries of one w and rev.
func beats(a, b Entry) bool {
	if af, bf := a.State.Final(), b.State.Final(); af != bf {
		return af
	}
	if a.RumorCreatedAt != b.RumorCreatedAt {
		return a.RumorCreatedAt > b.RumorCreatedAt
	}
	return a.RumorID < b.RumorID
}

// DerivedEntryExists reports any entry whose w is id, whatever its state,
// including one this reader does not recognise (NIP-CP §Writing, Placing it
// again, step 2). Give it every entry synced, not Resolve's winners.
func DerivedEntryExists(raw []Entry, id string) bool {
	for _, e := range raw {
		if e.W == id {
			return true
		}
	}
	return false
}
