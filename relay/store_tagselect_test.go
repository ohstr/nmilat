package relay

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ohstr/nmilat/nip01"
)

// A filter with several tag names is driven by the smallest tag range, the
// rest checked per event: #d x few + #l shared by the whole store must cost
// about the #d matches, not the #l range.

const sharedTagEvents = rangeProbeCap + 200

func TestTagScanDrivenByMostSelectiveTag(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var bulk []*nip01.Event
	for i := 0; i < sharedTagEvents; i++ {
		bulk = append(bulk, signEventAt(t, probeKeyA, 30383, base-100-uint64(i),
			fmt.Sprintf("bulk %d", i), []string{"d", fmt.Sprintf("bulk-%d", i)}, []string{"l", "60"}))
	}
	InsertTestEvents(t, store, bulk)

	want := []*nip01.Event{
		signEventAt(t, probeKeyA, 30383, base-1, "x1", []string{"d", "x1"}, []string{"l", "60"}),
		signEventAt(t, probeKeyA, 30383, base-2, "x2", []string{"d", "x2"}, []string{"l", "60"}),
		signEventAt(t, probeKeyA, 30383, base-3, "x3", []string{"d", "x3"}, []string{"l", "60"}),
	}
	other := signEventAt(t, probeKeyA, 30383, base-4, "x4", []string{"d", "x4"}, []string{"l", "20"})
	InsertTestEvents(t, store, append(append([]*nip01.Event{}, want...), other))

	for _, tc := range []struct {
		name   string
		filter *nip01.SubscriptionFilter
	}{
		{"tags only", &nip01.SubscriptionFilter{
			Tags: map[string][]string{"d": {"x1", "x2", "x3", "x4"}, "l": {"60"}},
		}},
		{"kind and author", &nip01.SubscriptionFilter{
			Kinds:   []int{30383},
			Authors: []string{want[0].PubKey},
			Tags:    map[string][]string{"d": {"x1", "x2", "x3", "x4"}, "l": {"60"}},
		}},
		{"with limit", &nip01.SubscriptionFilter{
			Tags:  map[string][]string{"d": {"x1", "x2", "x3", "x4"}, "l": {"60"}},
			Limit: 100,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newQuery(t, store, filterGroup(tc.filter))
			assertIDsInOrder(t, readEventsCollecting(t, q, false), want)
			if got := q.scanners[0].scanned; got > 4 {
				t.Errorf("scanned %d index entries, want at most the 4 #d entries", got)
			}
		})
	}
}

// When every tag range is large but kind+author is narrow, the kind+pubkey
// index drives the scan instead.
func TestTagScanFallsBackToKindPubkey(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())

	var bulk []*nip01.Event
	for i := 0; i < sharedTagEvents; i++ {
		bulk = append(bulk, signEventAt(t, probeKeyB, 1, base-100-uint64(i),
			fmt.Sprintf("bulk %d", i), []string{"l", "60"}, []string{"t", "bitcoin"}))
	}
	InsertTestEvents(t, store, bulk)

	want := []*nip01.Event{
		signEventAt(t, probeKeyA, 1, base-1, "a1", []string{"l", "60"}, []string{"t", "bitcoin"}),
		signEventAt(t, probeKeyA, 1, base-2, "a2", []string{"l", "60"}, []string{"t", "bitcoin"}),
	}
	InsertTestEvents(t, store, append(append([]*nip01.Event{}, want...),
		signEventAt(t, probeKeyA, 1, base-3, "a3", []string{"l", "20"}, []string{"t", "bitcoin"})))

	q := newQuery(t, store, filterGroup(&nip01.SubscriptionFilter{
		Kinds:   []int{1},
		Authors: []string{want[0].PubKey},
		Tags:    map[string][]string{"l": {"60"}, "t": {"bitcoin"}},
	}))
	assertIDsInOrder(t, readEventsCollecting(t, q, false), want)
	if got := q.scanners[0].scanned; got > 3 {
		t.Errorf("scanned %d index entries, want at most author A's 3", got)
	}
}

// A candidate queued on one pass can be deleted before the next pass loads
// it; the scan skips it rather than failing the whole query.
func TestCollectBatchSkipsVanishedEvent(t *testing.T) {
	store := newStore(t)
	ev := signEventAt(t, probeKeyA, 1, uint64(time.Now().Unix()), "kept", []string{"t", "x"})
	InsertTestEvents(t, store, []*nip01.Event{ev})

	ss, err := newStoreScan(store, &nip01.SubscriptionFilter{Tags: map[string][]string{"t": {"x"}}}, map[uint64]bool{})
	if err != nil {
		t.Fatal(err)
	}
	ss.queueEvents.AddEvent(&PotentialEvent{Evsid: 1 << 40, CreatedAt: ev.CreatedAt + 1})

	var batch []*PotentialEvent
	err = store.db.View(func(tx *bolt.Tx) error {
		var err error
		batch, _, err = ss.collectBatch(tx, nil, false, 0, -1)
		return err
	})
	if err != nil {
		t.Fatalf("collectBatch: %v", err)
	}
	if len(batch) != 0 {
		t.Fatalf("got %d events from a vanished evsid, want 0", len(batch))
	}
}

// TestTagScanMatchesAllCursorScan runs random multi-tag filters through the
// chosen scan and through the old one-cursor-per-value scan, and requires the
// same events in the same order. Events carry at most defaultMaxIndexableTags
// tags, so every tag is indexed and both scans see the same entries.
func TestTagScanMatchesAllCursorScan(t *testing.T) {
	store := newStore(t)
	base := uint64(time.Now().Unix())
	r := rand.New(rand.NewSource(20261024))

	keys := []string{probeKeyA, probeKeyB}
	pick := func(prefix string, n int) string { return fmt.Sprintf("%s%d", prefix, r.Intn(n)) }
	kinds := []int{1, 30383, 30384}

	var events []*nip01.Event
	for i := 0; i < 1500; i++ {
		tags := [][]string{{"d", pick("d", 400)}}
		// l is common, t middling, h rare.
		if r.Intn(10) < 8 {
			tags = append(tags, []string{"l", pick("l", 2)})
		}
		if r.Intn(2) == 0 {
			tags = append(tags, []string{"t", pick("t", 20)})
		}
		if r.Intn(20) == 0 {
			tags = append(tags, []string{"h", pick("h", 5)})
		}
		// Repeated timestamps exercise tie ordering across cursors.
		events = append(events, signEventAt(t, keys[r.Intn(2)], kinds[r.Intn(3)], base-uint64(r.Intn(600)),
			fmt.Sprintf("ev %d", i), tags...))
	}
	InsertTestEvents(t, store, events)

	var pubkeys []string
	seen := map[string]bool{}
	for _, ev := range events {
		if !seen[ev.PubKey] {
			seen[ev.PubKey] = true
			pubkeys = append(pubkeys, ev.PubKey)
		}
	}

	values := func(prefix string, n, max int) []string {
		var vs []string
		for j := 0; j < 1+r.Intn(max); j++ {
			vs = append(vs, pick(prefix, n))
		}
		return vs
	}

	for i := 0; i < 300; i++ {
		f := &nip01.SubscriptionFilter{Tags: map[string][]string{}}
		if r.Intn(2) == 0 {
			f.Tags["d"] = values("d", 400, 50)
		}
		if r.Intn(2) == 0 {
			f.Tags["l"] = values("l", 2, 2)
		}
		if r.Intn(3) == 0 {
			f.Tags["t"] = values("t", 20, 3)
		}
		if r.Intn(4) == 0 {
			f.Tags["h"] = values("h", 5, 2)
		}
		if len(f.Tags) == 0 {
			f.Tags["l"] = []string{"l0"}
		}
		if r.Intn(2) == 0 {
			f.Kinds = []int{kinds[r.Intn(3)]}
		}
		if r.Intn(2) == 0 {
			f.Authors = []string{pubkeys[r.Intn(len(pubkeys))]}
		}
		if r.Intn(3) == 0 {
			f.Limit = 1 + r.Intn(40)
		}
		if r.Intn(4) == 0 {
			f.Since = base - uint64(r.Intn(600))
		}

		t.Run(fmt.Sprintf("filter_%d", i), func(t *testing.T) {
			got := readEventsCollecting(t, newQuery(t, store, filterGroup(f)), false)

			old := newQuery(t, store, filterGroup(f))
			cursors, err := createCursorsByTags(f.Tags)
			if err != nil {
				t.Fatal(err)
			}
			old.scanners[0].index, old.scanners[0].cursors = indexTag, cursors
			want := readEventsCollecting(t, old, false)

			if len(got) != len(want) {
				t.Fatalf("filter %+v: got %d events, all-cursor scan got %d", f, len(got), len(want))
			}
			for j := range want {
				if got[j].EventID != want[j].EventID {
					t.Fatalf("filter %+v: position %d got %s, all-cursor scan got %s", f, j, got[j].EventID, want[j].EventID)
				}
			}
		})
	}
}
