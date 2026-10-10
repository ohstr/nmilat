package relay

import (
	"fmt"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// The store and nip01.LatestVersion must keep the same version of a
// replaceable or addressable event, so a client resolving a slot itself
// agrees with what relays serve.
func TestStoreAgreesWithLatestVersion(t *testing.T) {
	const key = "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c"
	now := uint64(time.Now().Unix())

	cases := map[string][]struct {
		kind int
		at   uint64
	}{
		"addressable, distinct times": {{30001, now - 30}, {30001, now - 10}, {30001, now - 20}},
		"addressable, all tied":       {{30001, now}, {30001, now}, {30001, now}, {30001, now}},
		"addressable, tie at the top": {{30001, now - 50}, {30001, now - 5}, {30001, now - 5}},
		"replaceable, tied":           {{10002, now}, {10002, now}, {10002, now - 1}},
	}
	for name, versions := range cases {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			var events []*nip01.Event
			for i, v := range versions {
				ev := &nip01.Event{Kind: v.kind, CreatedAt: v.at, Content: fmt.Sprintf("v%d", i), Tags: [][]string{}}
				if v.kind >= 30000 {
					ev.Tags = [][]string{{"d", "slot"}}
				}
				if err := ev.Sign(key); err != nil {
					t.Fatal(err)
				}
				events = append(events, ev)
				// One at a time, so the store applies its rule on every insert.
				InsertTestEvents(t, store, []*nip01.Event{ev})
			}

			kept, err := store.FetchAll()
			if err != nil {
				t.Fatal(err)
			}
			want := nip01.LatestVersion(events, time.Now(), time.Minute)
			if len(kept) != 1 || kept[0].ID != want.ID {
				ids := make([]string, len(kept))
				for i, k := range kept {
					ids[i] = k.ID
				}
				t.Fatalf("store kept %v, LatestVersion picked %s", ids, want.ID)
			}
		})
	}
}
