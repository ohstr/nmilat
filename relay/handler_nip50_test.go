package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/utils"
	"github.com/ohstr/nmilat/wire"
)

// searchProfile is a signed kind 0 for the n-th small test key.
func searchProfile(t *testing.T, n int, createdAt uint64) (*nip01.Event, string) {
	t.Helper()
	priv := fmt.Sprintf("%064x", n)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ev := nip01.NewEvent(0, fmt.Sprintf(`{"name":"user%d"}`, n))
	ev.CreatedAt = createdAt
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev, pub
}

func potentialEvent(t *testing.T, ev *nip01.Event) *PotentialEvent {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return &PotentialEvent{CreatedAt: ev.CreatedAt, EventID: ev.ID, Bytes: b}
}

func eventIDs(events []*PotentialEvent) []string {
	ids := make([]string, len(events))
	for i, ev := range events {
		ids[i] = ev.EventID
	}
	return ids
}

func TestSearchRank_OrdersByRankThenLimits(t *testing.T) {
	strong, strongPub := searchProfile(t, 1, 1000)
	mid, midPub := searchProfile(t, 2, 2000)
	weak, weakPub := searchProfile(t, 3, 3000)
	stray, _ := searchProfile(t, 4, 4000)
	// Store order: created_at desc.
	stored := []*PotentialEvent{potentialEvent(t, stray), potentialEvent(t, weak), potentialEvent(t, mid), potentialEvent(t, strong)}

	ranks := []string{strongPub, midPub, weakPub}
	for name, tc := range map[string]struct {
		limit int
		want  []string
	}{
		"no limit":         {0, []string{strong.ID, mid.ID, weak.ID, stray.ID}},
		"limit after rank": {2, []string{strong.ID, mid.ID}},
		"limit above size": {10, []string{strong.ID, mid.ID, weak.ID, stray.ID}},
	} {
		in := append([]*PotentialEvent(nil), stored...)
		got := eventIDs(newSearchRank(ranks, tc.limit).order(in))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

func TestSearchRank_NewestFirstWithinAnAuthor(t *testing.T) {
	older := signedNote(t, "older", 1000)
	newer := signedNote(t, "newer", 2000)
	got := eventIDs(newSearchRank([]string{authTestPubKey}, 0).order(
		[]*PotentialEvent{potentialEvent(t, older), potentialEvent(t, newer)}))
	if len(got) != 2 || got[0] != newer.ID || got[1] != older.ID {
		t.Fatalf("got %v, want [newer older]", got)
	}
}

// NIP-50: results come back in descending search quality, not created_at, and
// limit applies to the ranked list, so a strong match with an old profile
// beats a weak one updated yesterday.
func TestNIP50_ResultsInSearchOrderWithLimitAfterRanking(t *testing.T) {
	strong, strongPub := searchProfile(t, 1, 1000)
	mid, midPub := searchProfile(t, 2, 2000)
	weak, weakPub := searchProfile(t, 3, 3000)
	store := newStoreWithEvents(t, []*nip01.Event{strong, mid, weak})

	svc := &MockSearchService{
		FindProfilesFunc: func(context.Context, string, int) ([]string, error) {
			return []string{strongPub, midPub, weakPub}, nil
		},
	}
	sess := &Session{SessionContext: NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, svc, nil, nil)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for name, tc := range map[string]struct {
		limit int
		want  []string
	}{
		"all":     {0, []string{strong.ID, mid.ID, weak.ID}},
		"limit 2": {2, []string{strong.ID, mid.ID}},
	} {
		subID := strings.ReplaceAll(name, " ", "-")
		rp := &wire.RequestPacket{
			SubscriptionID: subID,
			Filters:        nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{Kinds: []int{0}, Search: "user", Limit: tc.limit}),
		}
		if err := sess.processRequest(ctx, rp); err != nil {
			t.Fatal(err)
		}
		got := expectStoredEvents(t, sess, subID)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// expectStoredEvents is expectEvents for a subscription, which sends raw
// EventBytes rather than a decoded Event.
func expectStoredEvents(t *testing.T, sess *Session, subID string) []string {
	t.Helper()
	var ids []string
	for {
		switch r := nextReply(t, sess).(type) {
		case *wire.EventSubscriptionResponse:
			if r.SubscriptionID != subID {
				t.Fatalf("EVENT for %q, want %q", r.SubscriptionID, subID)
			}
			var ev nip01.Event
			if err := json.Unmarshal(r.EventBytes, &ev); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, ev.ID)
		case *wire.EOSESubscriptionResponse:
			return ids
		default:
			t.Fatalf("unexpected reply %T %+v", r, r)
		}
	}
}
