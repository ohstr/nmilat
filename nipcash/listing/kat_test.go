package listing

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

// T22-01: NewListing from K-CO-1 with the NIP example fields → K-LIST-1.
func TestT22_01_KList1(t *testing.T) {
	ev := kList1Event(t)
	if ev.ID != kList1ID {
		t.Fatalf("K-LIST-1 id = %s\ntags = %v", ev.ID, ev.Tags)
	}
	want := []string{"d", "t", "t", "t", "n", "network", "connection", "title", "image", "p", "status", "expiration",
		"hint", "L", "l", "l", "g", "location", "alt"}
	if len(ev.Tags) != len(want) {
		t.Fatalf("tags = %v", ev.Tags)
	}
	for i, n := range want {
		if ev.Tags[i][0] != n {
			t.Fatalf("tag %d = %v, want %s", i, ev.Tags[i], n)
		}
	}
	if ev.PubKey != node || ev.Tags[len(ev.Tags)-1][1] != "Cash offer: Alice's cash counter" {
		t.Fatalf("pubkey %s alt %v", ev.PubKey, ev.Tags[len(ev.Tags)-1])
	}
}

// T22-04: ClosedListing → K-LIST-2; NewListingDeletion → K-LDEL-1.
func TestT22_04_KList2KLDel1(t *testing.T) {
	l := kList1(t)
	ev, err := ClosedListing(l, 1793318400, signWith(key1))
	if err != nil || ev.ID != kList2ID {
		t.Fatalf("K-LIST-2 = %v (%v)", ev, err)
	}
	if l.Event.ID != kList1ID {
		t.Fatal("ClosedListing changed its input")
	}
	del, err := NewListingDeletion(addr1, 1793318460, signWith(key1))
	if err != nil || del.ID != kLDel1 {
		t.Fatalf("K-LDEL-1 = %v (%v)", del, err)
	}
	if _, err := NewListingDeletion(addr1, 1793318460, signWith(key2)); err == nil {
		t.Fatal("a deletion signed by another key was built")
	}
	if _, err := ClosedListing(l, createdList1, signWith(key1)); err == nil {
		t.Fatal("a closed version not newer was built")
	}
}

func signedAt(t testing.TB, ev *nip01.Event, createdAt int64, priv string) *nip01.Event {
	t.Helper()
	ev.CreatedAt = uint64(createdAt)
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// K-OPS-1, K-REC-1, K-REP-1 rebuilt with the builders.
func TestKOps1KRec1KRep1(t *testing.T) {
	ops := signedAt(t, NewOperatorOffers([]Ref{{addr1, relayURL}}, []Ref{{node, relayURL}}), createdList1, key2)
	if ops.ID != kOps1 {
		t.Fatalf("K-OPS-1 id = %s", ops.ID)
	}
	rec := signedAt(t, NewRecommendation(node, relayURL, []Ref{{addr1, relayURL}}, "fast payouts, used it for months"),
		1792800000, key4)
	if rec.ID != kRec1 {
		t.Fatalf("K-REC-1 id = %s", rec.ID)
	}
	rep := signedAt(t, NewReport(node, addr1, kList1ID, ReasonNoPayout, "took my payment, never minted"), 1792800000, key4)
	if rep.ID != kRep1 {
		t.Fatalf("K-REP-1 id = %s", rep.ID)
	}
}
