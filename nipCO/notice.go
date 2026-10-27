package nipCO

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/ohstr/nmilat/nip01"
)

// KindOrderNotice is the ephemeral order notice (NIP-CO §Order Notice):
// published when an order changes state or gains a bill. NIP-CASH's
// cash_withdraw uses the same kind for its own notices.
const KindOrderNotice = 23189

// NewOrderNotice builds a notice for notify: signed by a fresh key used once,
// tags exactly [["p", notify]], content "", created_at now. A notice proves
// nothing; it only tells a client to read the order.
func NewOrderNotice(notify string) (*nip01.Event, error) {
	if !ValidNotify(notify) {
		return nil, fmt.Errorf("nipCO: notify is 64 lowercase hex")
	}
	var d [32]byte
	var sk string
	for {
		if _, err := io.ReadFull(randReader, d[:]); err != nil {
			return nil, fmt.Errorf("nipCO: notice key: %w", err)
		}
		if _, _, err := buyerKeyFromDigest(d); err == nil {
			sk = hex.EncodeToString(d[:])
			break
		}
	}
	return nip01.NewSignedEvent(KindOrderNotice, "", sk, []string{"p", notify})
}

// OrderNoticeFilter is the subscription for notify's notices:
// {"kinds":[23189],"#p":[notify]}.
func OrderNoticeFilter(notify string) nip01.SubscriptionFilter {
	return nip01.SubscriptionFilter{Kinds: []int{KindOrderNotice}, Tags: map[string][]string{"p": {notify}}}
}

// IsOrderNotice reports a notice for notify: kind 23189, exactly one tag
// ["p", notify], empty content and a valid id and signature. Anything else is
// ignored.
func IsOrderNotice(ev *nip01.Event, notify string) bool {
	if ev == nil || ev.Kind != KindOrderNotice || ev.Content != "" || len(ev.Tags) != 1 {
		return false
	}
	if t := ev.Tags[0]; len(t) != 2 || t[0] != "p" || t[1] != notify {
		return false
	}
	return ev.Verify() == nil
}
