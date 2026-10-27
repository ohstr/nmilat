package client

import (
	"fmt"

	"github.com/ohstr/nmilat/nipcash"
)

// The ordered mark is local: a bill minted for an order, or made from ordered
// bills only, is ordered (NIP-CASH §Data Model), and a Hub refuses a consolidate
// mixing ordered and unordered sources with RESTRICTED. The client knows the mark
// of the bills it got from an order (Bill.Ordered, nipcash.Source.Ordered) and
// refuses the mix before anything is written or sent. A bill received from
// someone else carries no mark, so a mix the client cannot see still reaches the
// Hub and comes back RESTRICTED, on the coded-refusal path.

// consolidateOrdered is whether a consolidate of sources makes an ordered bill,
// or ErrMixedOrdered when their marks differ. A source that is the item's own
// bill (same wallet pubkey) also carries bill's mark.
func consolidateOrdered(bill Bill, sources []nipcash.Source) (bool, error) {
	marks := make([]bool, len(sources))
	for i, s := range sources {
		marks[i] = s.Ordered || (bill.Ordered && bill.target != "" && s.WalletPubkey == bill.target)
	}
	ordered, mixed := nipcash.OrderedResult(marks)
	if mixed {
		return false, ErrMixedOrdered
	}
	return ordered, nil
}

// sourcesOrdered is consolidateOrdered without a bill, for the composites.
func sourcesOrdered(sources []nipcash.Source) (bool, error) {
	return consolidateOrdered(Bill{}, sources)
}

// mixedItem names the item a mixed consolidate was found in.
func mixedItem(id string) error {
	return fmt.Errorf("%w: item %q", ErrMixedOrdered, id)
}
