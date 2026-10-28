package nipcash

// OrderedResult is whether a bill made from sources is ordered (NIP-CASH §Data
// Model): every source ordered → ordered; some but not all → mixed (a
// consolidate of them is refused RESTRICTED); none, or no sources → neither. A
// transfer's single source passes its own flag on.
func OrderedResult(sourcesOrdered []bool) (ordered, mixed bool) {
	n := 0
	for _, o := range sourcesOrdered {
		if o {
			n++
		}
	}
	switch {
	case n == 0:
		return false, false
	case n == len(sourcesOrdered):
		return true, false
	default:
		return false, true
	}
}
