package listing

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rivo/uniseg"

	"github.com/ohstr/nmilat/nip01"
)

// F-LIST-1: the parsers never panic; a parsed listing always has exactly one
// type, a verified string of that type's HRP and TLV 4 = pubkey.
func FuzzParseListing(f *testing.F) {
	for _, ev := range []*nip01.Event{kList1Event(f), kOps1Event(f), kRec1Event(f)} {
		b, _ := json.Marshal(ev)
		f.Add(b)
	}
	f.Add([]byte(`{"kind":31190,"tags":[["d"],["t"]]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var ev nip01.Event
		if json.Unmarshal(b, &ev) != nil {
			return
		}
		if l, err := ParseListing(&ev, CheckOptions{Chains: []string{"bitcoin"}, TestNetworks: true}); err == nil {
			switch {
			case l.Type == TypeCashOrder && l.Order != nil && l.Circle == nil:
				if l.Order.Verify() != nil || l.Order.HubIdentity != ev.PubKey || !strings.HasPrefix(l.Connection, "cashorder1") {
					t.Fatal("cash_order listing not verified")
				}
			case l.Type == TypeCircleWallet && l.Circle != nil && l.Order == nil:
				if l.Circle.Verify() != nil || l.Circle.HubIdentity != ev.PubKey || !strings.HasPrefix(l.Connection, "circlehub1") {
					t.Fatal("circle_wallet listing not verified")
				}
			default:
				t.Fatalf("listing type %q with order %v circle %v", l.Type, l.Order != nil, l.Circle != nil)
			}
		}
		_, _ = ParseOperatorOffers(&ev)
		_, _ = ParseRecommendation(&ev)
		_, _ = ParseReport(&ev)
	})
}

// F-LIST-1: SanitizeText never returns a stripped code point and never exceeds
// its cap.
func FuzzSanitizeText(f *testing.F) {
	f.Add("Alice​'s‮ cash counter", 40)
	f.Add("✔️ é\r\n", 3)
	f.Fuzz(func(t *testing.T, s string, n int) {
		n %= 300
		out := SanitizeText(s, n)
		for _, r := range out {
			if stripped(r) || lineBreak(r) {
				t.Fatalf("%q kept %U", out, r)
			}
		}
		if n > 0 && uniseg.GraphemeClusterCount(out) > n {
			t.Fatalf("%q exceeds %d clusters", out, n)
		}
	})
}
