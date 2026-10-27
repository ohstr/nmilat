package listing

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

const otherConn = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"

func circleFields(t testing.TB, conn string) ListingFields {
	return ListingFields{Circle: circleConn(t, conn), Network: "mainnet", Summary: []string{"allowlist"}, Title: "Circle",
		Expiration: createdList1 + 1000}
}

// T22-02: NewListing refuses what §Hub Rules forbids.
func TestT22_02_NewListingRefuses(t *testing.T) {
	unverified := kco1(t)
	unverified.Label = "Bob's cash counter"
	cases := []struct {
		name string
		edit func(f *ListingFields)
		now  int64
		sign func(*nip01.Event) error
		want error
	}{
		{"no connection", func(f *ListingFields) { f.Order = nil }, 0, nil, ErrNotListable},
		{"both connections", func(f *ListingFields) { f.Circle = circleConn(t, otherConn) }, 0, nil, ErrNotListable},
		{"unverified", func(f *ListingFields) { f.Order = unverified }, 0, nil, nipcash.ErrConnUnverified},
		{"post-dated", func(*ListingFields) {}, createdList1 - 1, nil, ErrPostDated},
		{"expiry too far", func(f *ListingFields) { f.Expiration = createdList1 + 2592001 }, 0, nil, ErrExpiryTooFar},
		{"hint on a circle", func(f *ListingFields) {
			h := f.Hints
			*f = circleFields(t, otherConn)
			f.Hints = h
		}, 0, nil, ErrListingField},
		{"a on an allowlist circle", func(f *ListingFields) {
			*f = circleFields(t, otherConn)
			f.FollowSet = "30000:" + pub2 + ":friends"
		}, 0, nil, ErrListingField},
		{"g of 6", func(f *ListingFields) { f.Geohashes = []string{"eycabc"} }, 0, nil, ErrGeohashPrecision},
		{"g of 5", func(f *ListingFields) { f.Geohashes = []string{"eycab"} }, 0, nil, ErrGeohashPrecision},
		{"g of 2", func(f *ListingFields) { f.Geohashes = []string{"ey"} }, 0, nil, ErrGeohashPrecision},
		{"location with a newline", func(f *ListingFields) { f.Location = "Lisbon\nBaixa" }, 0, nil, ErrListingField},
		{"location with a link", func(f *ListingFields) { f.Location = "https://evil.example" }, 0, nil, ErrListingField},
		{"location of 41", func(f *ListingFields) { f.Location = strings.Repeat("a", 41) }, 0, nil, ErrListingField},
		{"image not https", func(f *ListingFields) { f.Image = "http://example.com/x.png" }, 0, nil, ErrListingField},
		{"unknown network", func(f *ListingFields) { f.Network = "moonnet" }, 0, nil, ErrListingField},
		{"summary of the other type", func(f *ListingFields) { f.Summary = []string{"allowlist"} }, 0, nil, ErrListingField},
		{"two hints of one kind", func(f *ListingFields) { f.Hints = append(f.Hints, f.Hints[0]) }, 0, nil, ErrListingField},
		{"bad language", func(f *ListingFields) { f.Languages = []string{"por"} }, 0, nil, ErrListingField},
		{"bad status", func(f *ListingFields) { f.Status = "gone" }, 0, nil, ErrListingField},
		{"signer other than TLV 4", func(*ListingFields) {}, 0, signWith(key2), ErrWrongSigner},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := kList1Fields(t)
			c.edit(&f)
			now := int64(createdList1)
			if c.now != 0 {
				now = c.now
			}
			sign := c.sign
			if sign == nil {
				sign = signWith(key1)
			}
			_, err := NewListing(f, createdList1, now, sign)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	// A follow_set circle takes its a; a circle listing builds and parses.
	f := circleFields(t, otherConn)
	f.Summary = []string{"follow_set"}
	f.FollowSet = "30000:" + pub2 + ":friends"
	ev, err := NewListing(f, createdList1, createdList1, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseListing(ev, mainnet)
	if err != nil || l.Type != TypeCircleWallet || l.FollowSet != f.FollowSet || l.Circle == nil || l.D != otherConn {
		t.Fatalf("circle listing = %+v (%v)", l, err)
	}
	// Defaults: status open, expiration created_at + 30 days.
	f = circleFields(t, otherConn)
	f.Expiration = 0
	ev, err = NewListing(f, createdList1, createdList1, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	if l, err = ParseListing(ev, mainnet); err != nil || l.Status != StatusOpen || l.Expiration != createdList1+MaxExpirySecs {
		t.Fatalf("defaults = %+v (%v)", l, err)
	}
}

func cashHub1(t testing.TB) string {
	sign, err := nipcash.LocalChainSigner(key1, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := nipcash.SignCashHubConnection(nipcash.CashHubConnection{Pubkey: kcoConn, Relays: []string{relayURL},
		Secret: connSecret(), HubIdentity: node, Chain: "bitcoin"}, sign, node)
	if err != nil {
		t.Fatal(err)
	}
	s, err := nipcash.EncodeCashHubConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stepOf(err error) int {
	var le *ListingError
	if errors.As(err, &le) {
		return le.Step
	}
	return 0
}

// T22-03: ParseListing in step order.
func TestT22_03_ParseListingSteps(t *testing.T) {
	base := kList1Event(t)
	unverified := kco1(t)
	unverified.Label = "Bob's cash counter"
	unverifiedStr, err := nipCO.EncodeOrderConnection(*unverified)
	if err != nil {
		t.Fatal(err)
	}
	circleStr, err := nipcw.EncodeCircleHubConnection(*circleConn(t, kcoConn))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		priv string
		edit func(e *nip01.Event)
		o    CheckOptions
		want int
	}{
		{"two d", key1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"d", kcoConn}) }, mainnet, 1},
		{"no status", key1, func(e *nip01.Event) { dropTag(e, "status") }, mainnet, 1},
		{"no expiration", key1, func(e *nip01.Event) { dropTag(e, "expiration") }, mainnet, 1},
		{"two titles", key1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"title", "x"}) }, mainnet, 1},
		{"two lightning hints", key1, func(e *nip01.Event) {
			e.Tags = append(e.Tags, []string{"hint", "lightning", "1", "2", "3", "4"})
		}, mainnet, 1},
		{"two type t of one value", key1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"t", "cash_order"}) }, mainnet, 1},
		{"expiration 1795305600.0", key1, func(e *nip01.Event) { setTag(e, "expiration", "1795305600.0") }, mainnet, 1},
		{"expiration -1", key1, func(e *nip01.Event) { setTag(e, "expiration", "-1") }, mainnet, 1},
		{"unknown status", key1, func(e *nip01.Event) { setTag(e, "status", "gone") }, mainnet, 1},
		{"two location", key1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"location", "x"}) }, mainnet, 1},
		{"bad signature", "", func(e *nip01.Event) { e.Content = "changed" }, mainnet, 1},
		{"both type values", key1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"t", "circle_wallet"}) }, mainnet, 2},
		{"no type", key1, func(e *nip01.Event) { setTag(e, "t", "lightning") }, mainnet, 2},
		{"cashhub1 connection", key1, func(e *nip01.Event) { setTag(e, "connection", cashHub1(t)) }, mainnet, 2},
		{"circlehub1 under cash_order", key1, func(e *nip01.Event) { setTag(e, "connection", circleStr) }, mainnet, 2},
		{"cashorder1 under circle_wallet", key1, func(e *nip01.Event) { setTag(e, "t", "circle_wallet") }, mainnet, 2},
		{"garbage connection", key1, func(e *nip01.Event) { setTag(e, "connection", "cashorder1qqqq") }, mainnet, 2},
		{"unverified", key1, func(e *nip01.Event) { setTag(e, "connection", unverifiedStr) }, mainnet, 3},
		{"TLV 4 is not pubkey", key3, func(*nip01.Event) {}, mainnet, 3},
		{"TLV 0 is not d", key1, func(e *nip01.Event) { setTag(e, "d", otherConn) }, mainnet, 3},
		{"uppercase d", key1, func(e *nip01.Event) { setTag(e, "d", strings.ToUpper(kcoConn)) }, mainnet, 3},
		{"TLV 6 is not n", key1, func(e *nip01.Event) { setTag(e, "n", "litecoin") }, CheckOptions{Chains: []string{"litecoin"}}, 3},
		{"chain not held", key1, func(*nip01.Event) {}, CheckOptions{Chains: []string{"litecoin"}}, 4},
		{"regtest", key1, func(e *nip01.Event) { setTag(e, "network", "regtest") }, mainnet, 4},
		{"regtest with test networks", key1, func(e *nip01.Event) { setTag(e, "network", "regtest") },
			CheckOptions{Chains: []string{"bitcoin"}, TestNetworks: true}, 0},
		{"unknown network with test networks", key1, func(e *nip01.Event) { setTag(e, "network", "moonnet") },
			CheckOptions{Chains: []string{"bitcoin"}, TestNetworks: true}, 4},
		{"step 1 and step 3 → 1", key3, func(e *nip01.Event) { dropTag(e, "status") }, mainnet, 1},
		{"step 2 and step 4 → 2", key1, func(e *nip01.Event) { setTag(e, "t", "lightning") }, CheckOptions{}, 2},
		{"uppercase connection", key1, func(e *nip01.Event) {
			for _, tg := range e.Tags {
				if tg[0] == "connection" {
					tg[1] = strings.ToUpper(tg[1])
				}
			}
		}, mainnet, 0},
		{"mixed-case connection", key1, func(e *nip01.Event) {
			for _, tg := range e.Tags {
				if tg[0] == "connection" {
					tg[1] = strings.ToUpper(tg[1][:3]) + tg[1][3:]
				}
			}
		}, mainnet, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := base.Copy()
			if c.priv == "" {
				c.edit(ev)
			} else {
				ev = resign(t, base, c.priv, c.edit)
			}
			l, err := ParseListing(ev, c.o)
			if got := stepOf(err); got != c.want || (c.want == 0 && err != nil) {
				t.Fatalf("step = %d (%v), want %d", got, err, c.want)
			}
			if c.want == 0 && l.Connection != strings.ToLower(l.Connection) {
				t.Fatalf("connection not lowercased: %s", l.Connection)
			}
		})
	}
	l := kList1(t)
	if l.Type != TypeCashOrder || l.D != kcoConn || l.Chain != "bitcoin" || l.Network != "mainnet" || l.Order == nil ||
		l.Title != "Alice's cash counter" || l.Location != "Lisbon, Baixa" || l.Operator.Pubkey != pub2 ||
		l.Operator.Relay != relayURL || l.Status != StatusOpen || l.Expiration != expList1 || len(l.Hints) != 1 ||
		!slices.Equal(l.Languages, []string{"pt", "en"}) || !slices.Equal(l.Geohashes, []string{"eyc"}) ||
		!slices.Equal(l.Summary, []string{"lightning", "onchain"}) || l.Address() != addr1 {
		t.Fatalf("K-LIST-1 parsed = %+v", l)
	}
}

// T22-05: ignored tags are dropped and the listing kept.
func TestT22_05_IgnoredTags(t *testing.T) {
	ev := resign(t, kList1Event(t), key1, func(e *nip01.Event) {
		e.Tags = append(e.Tags, []string{"t", "bogus"}, []string{"t", "allowlist"},
			[]string{"hint", "bolt12", "1", "2", "3", "4"}, []string{"g", "eycabc"}, []string{"a", "30000:" + pub2 + ":x"},
			[]string{"hint", "onchain", "1", "x", "3", "4"})
		setTag(e, "image", "http://example.com/counter.png")
	})
	l, err := ParseListing(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.Summary, []string{"lightning", "onchain"}) || len(l.Hints) != 1 || l.Hints[0].Payment != "lightning" ||
		!slices.Equal(l.Geohashes, []string{"eyc"}) || l.Image != "" || l.FollowSet != "" {
		t.Fatalf("parsed = %+v", l)
	}
	// A circle listing carrying a hint: the hint dropped.
	cev, err := NewListing(circleFields(t, otherConn), createdList1, createdList1, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	cev = resign(t, cev, key1, func(e *nip01.Event) {
		e.Tags = append(e.Tags, []string{"hint", "lightning", "1", "2", "3", "4"}, []string{"a", "30000:" + pub2 + ":x"})
	})
	if cl, err := ParseListing(cev, mainnet); err != nil || len(cl.Hints) != 0 || cl.FollowSet != "" {
		t.Fatalf("circle = %+v (%v)", cl, err)
	}
}

func listingWithExpiration(t testing.TB, exp string) *Listing {
	t.Helper()
	ev := resign(t, kList1Event(t), key1, func(e *nip01.Event) { setTag(e, "expiration", exp) })
	l, err := ParseListing(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// T22-06: ExpiresAt and skew (K-LEXP-1..3).
func TestT22_06_KLExp(t *testing.T) {
	for exp, want := range map[string]int64{"1795305600": 1795305600, "1800000000": 1795305600, "1793000000": 1793000000} {
		if got := listingWithExpiration(t, exp).ExpiresAt(); got != want {
			t.Errorf("expiration %s → %d, want %d", exp, got, want)
		}
	}
	l := kList1(t)
	if !NewVersionBook().Offer(l, 1792712700) {
		t.Error("900 s ahead refused")
	}
	if NewVersionBook().Offer(l, 1792712699) {
		t.Error("901 s ahead accepted")
	}
	b := NewVersionBook()
	b.Offer(l, createdList1)
	if _, ok := b.Current(addr1, expList1); !ok {
		t.Error("not current at its expiry")
	}
	if _, ok := b.Current(addr1, expList1+1); ok {
		t.Error("current after its expiry")
	}
}

func kList2(t testing.TB) *Listing {
	t.Helper()
	ev, err := ClosedListing(kList1(t), 1793318400, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseListing(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// T22-07: VersionBook (K-LVER-1), the deletion floor, Snapshot/Restore.
func TestT22_07_VersionBook(t *testing.T) {
	// Equal created_at: the lower id kept, whatever the order.
	a := kList1(t)
	bEv := resign(t, a.Event, key1, func(e *nip01.Event) { e.Content = "another text" })
	b2, err := ParseListing(bEv, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	low, high := a, b2
	if high.Event.ID < low.Event.ID {
		low, high = high, low
	}
	for _, order := range [][]*Listing{{low, high}, {high, low}} {
		book := NewVersionBook()
		for _, l := range order {
			book.Offer(l, createdList1)
		}
		if cur, ok := book.Current(addr1, createdList1); !ok || cur.Event.ID != low.Event.ID {
			t.Fatalf("tie kept %v", cur)
		}
	}
	// K-LIST-1 after K-LIST-2: refused; K-LIST-2 hides the address (closed).
	book := NewVersionBook()
	l2 := kList2(t)
	if !book.Offer(l2, 1793318400) {
		t.Fatal("K-LIST-2 refused")
	}
	if book.Offer(kList1(t), 1793318400) {
		t.Fatal("K-LIST-1 taken after K-LIST-2")
	}
	if _, ok := book.Current(addr1, 1793318400); ok {
		t.Fatal("a closed version is current")
	}
	// After K-LIST-2 expired, K-LIST-1 is still refused, also across a snapshot.
	if book.Offer(kList1(t), expList1+10) {
		t.Fatal("K-LIST-1 taken after K-LIST-2 expired")
	}
	snap, err := book.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored := NewVersionBook()
	if err := restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if restored.Offer(kList1(t), 1793318400) {
		t.Fatal("K-LIST-1 taken after Restore")
	}
	if err := restored.Restore([]byte(`{"newest":[{"kind":1}]}`)); err == nil {
		t.Fatal("a bad snapshot restored")
	}
	// Deletion floor: a version at the floor refused, one after it accepted.
	book = NewVersionBook()
	del, err := NewListingDeletion(addr1, createdList1+100, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	if !book.ApplyDeletion(del) {
		t.Fatal("deletion not applied")
	}
	at := resign(t, kList1Event(t), key1, func(e *nip01.Event) { e.CreatedAt = createdList1 + 100 })
	atL, err := ParseListing(at, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if book.Offer(atL, createdList1+100) {
		t.Fatal("a version at the floor taken")
	}
	after := resign(t, kList1Event(t), key1, func(e *nip01.Event) { e.CreatedAt = createdList1 + 101 })
	afterL, err := ParseListing(after, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if !book.Offer(afterL, createdList1+101) {
		t.Fatal("a version after the floor refused")
	}
	if _, ok := book.Current(addr1, createdList1+101); !ok {
		t.Fatal("not current")
	}
	// Tap outcomes hide through the book.
	book.Taps().Record(afterL, TapResult{Outcome: TapHideUntilNewer})
	if _, ok := book.Current(addr1, createdList1+101); ok {
		t.Fatal("hidden version current")
	}
	snap, err = book.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored = NewVersionBook()
	if err := restored.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.Current(addr1, createdList1+101); ok || !restored.Taps().Hidden(afterL) {
		t.Fatal("tap outcome lost by the snapshot")
	}
	if restored.Offer(atL, createdList1+100) {
		t.Fatal("floor lost by the snapshot")
	}
}

// T22-08: ApplyDeletion only by the node identity, only with k 31190.
func TestT22_08_ApplyDeletion(t *testing.T) {
	del, err := NewListingDeletion(addr1, 1793318460, signWith(key1))
	if err != nil || del.ID != kLDel1 {
		t.Fatal(err)
	}
	for _, l := range []*Listing{kList1(t), kList2(t)} {
		book := NewVersionBook()
		book.ApplyDeletion(del)
		if book.Offer(l, 1793318460) {
			t.Fatalf("%s taken after K-LDEL-1", l.Event.ID)
		}
	}
	byOperator := nip01.NewEvent(5, "", []string{"a", addr1}, []string{"k", "31190"})
	signedAt(t, byOperator, 1793318460, key2)
	noK := nip01.NewEvent(5, "", []string{"a", addr1})
	signedAt(t, noK, 1793318460, key1)
	for name, ev := range map[string]*nip01.Event{"by the operator": byOperator, "without k": noK} {
		book := NewVersionBook()
		if book.ApplyDeletion(ev) || !book.Offer(kList1(t), createdList1) {
			t.Fatalf("deletion %s applied", name)
		}
	}
}

func kOps1Event(t testing.TB) *nip01.Event {
	return signedAt(t, NewOperatorOffers([]Ref{{addr1, relayURL}}, []Ref{{node, relayURL}}), createdList1, key2)
}

// T22-09: OperatorVerified and NewestOperatorOffers.
func TestT22_09_OperatorVerified(t *testing.T) {
	ops, err := ParseOperatorOffers(kOps1Event(t))
	if err != nil || ops.Author != pub2 || len(ops.Offers) != 1 || len(ops.Nodes) != 1 {
		t.Fatalf("K-OPS-1 = %+v (%v)", ops, err)
	}
	l := kList1(t)
	if !OperatorVerified(l, ops) {
		t.Fatal("K-OPS-1 + K-LIST-1 not verified")
	}
	noA, _ := ParseOperatorOffers(signedAt(t, NewOperatorOffers(nil, []Ref{{node, relayURL}}), createdList1, key2))
	if OperatorVerified(l, noA) {
		t.Fatal("verified without the a (an 11191 p alone)")
	}
	other := resign(t, l.Event, key1, func(e *nip01.Event) {
		setTag(e, "p", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
	})
	ol, err := ParseListing(other, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	if OperatorVerified(ol, ops) {
		t.Fatal("verified with p naming another key")
	}
	noP := resign(t, l.Event, key1, func(e *nip01.Event) { dropTag(e, "p") })
	nl, _ := ParseListing(noP, mainnet)
	if OperatorVerified(nl, ops) || nl.Operator != nil {
		t.Fatal("verified without p")
	}
	// Private items ignored.
	priv := NewOperatorOffers(nil, nil)
	priv.Content = "encrypted-items"
	pp, err := ParseOperatorOffers(signedAt(t, priv, createdList1, key2))
	if err != nil || len(pp.Offers) != 0 {
		t.Fatalf("private items read: %+v %v", pp, err)
	}
	// Newest wins; the lower id on a tie; another author never.
	older := signedAt(t, NewOperatorOffers(nil, nil), createdList1-10, key2)
	tieA := signedAt(t, NewOperatorOffers([]Ref{{addr1, ""}}, nil), createdList1, key2)
	tieB := kOps1Event(t)
	stranger := signedAt(t, NewOperatorOffers(nil, nil), createdList1+10, key3)
	n := NewestOperatorOffers([]*nip01.Event{older, tieA, stranger, tieB}, pub2)
	want := min(tieA.ID, tieB.ID)
	if n == nil || n.Event.ID != want {
		t.Fatalf("newest = %v, want %s", n, want)
	}
}

func kRec1Event(t testing.TB) *nip01.Event {
	return signedAt(t, NewRecommendation(node, relayURL, []Ref{{addr1, relayURL}}, "fast payouts, used it for months"),
		1792800000, key4)
}

// T22-10: ParseRecommendation and CreditedOffers.
func TestT22_10_Recommendations(t *testing.T) {
	r, err := ParseRecommendation(kRec1Event(t))
	if err != nil || r.Node != node || !slices.Equal(r.Offers, []string{addr1}) || r.Author != pub4 {
		t.Fatalf("K-REC-1 = %+v (%v)", r, err)
	}
	pd := NewRecommendation(node, relayURL, nil, "")
	setTag(pd, "p", pub2)
	if _, err := ParseRecommendation(signedAt(t, pd, 1792800000, key4)); !errors.Is(err, ErrRecommendation) {
		t.Fatalf("p ≠ d: %v", err)
	}
	foreign := "31190:" + pub2 + ":" + kcoConn
	fr, err := ParseRecommendation(signedAt(t, NewRecommendation(node, "", []Ref{{foreign, ""}}, ""), 1792800000, key4))
	if err != nil || len(fr.Offers) != 0 {
		t.Fatalf("a of another node kept: %+v %v", fr, err)
	}
	if got := CreditedOffers(fr, nil, nil); len(got) != 0 {
		t.Fatalf("credits %v", got)
	}
	// Two more listings of the node: one with the same verified operator, one with another.
	same := Address(node, otherConn)
	another := Address(node, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	ofNode := []*Listing{kList1(t), {NodeIdentity: node, D: otherConn}, {NodeIdentity: node, D: pub2}}
	opOf := func(a string) (string, bool) {
		switch a {
		case addr1, same:
			return pub2, true
		case another:
			return pub4, true
		}
		return "", false
	}
	if got := CreditedOffers(r, ofNode, opOf); !slices.Equal(got, []string{addr1, same}) {
		t.Fatalf("credited %v", got)
	}
}

// T22-11: MergeOperatorOffers.
func TestT22_11_Merge(t *testing.T) {
	ops, _ := ParseOperatorOffers(kOps1Event(t))
	a2 := Address(node, otherConn)
	a3 := Address(node, pub2)
	ev := MergeOperatorOffers(ops, []Ref{{a2, relayURL}, {a3, ""}}, nil)
	if ev.Content != "" || ev.Kind != KindOperatorOffers {
		t.Fatalf("merged = %+v", ev)
	}
	want := [][]string{{"a", addr1, relayURL}, {"a", a2, relayURL}, {"a", a3}, {"p", node, relayURL}, {"alt", operatorAlt}}
	if fmt.Sprint(ev.Tags) != fmt.Sprint(want) {
		t.Fatalf("tags = %v", ev.Tags)
	}
	signedAt(t, ev, createdList1+1, key2)
	merged, _ := ParseOperatorOffers(ev)
	ev = MergeOperatorOffers(merged, nil, []Ref{{addr1, ""}})
	if fmt.Sprint(ev.Tags) != fmt.Sprint([][]string{{"a", a2, relayURL}, {"a", a3}, {"p", node, relayURL}, {"alt", operatorAlt}}) {
		t.Fatalf("removed = %v", ev.Tags)
	}
	if first := MergeOperatorOffers(nil, []Ref{{addr1, ""}}, nil); len(first.Tags) != 2 {
		t.Fatalf("first = %v", first.Tags)
	}
}

// T22-12: reports.
func TestT22_12_Reports(t *testing.T) {
	ev := signedAt(t, NewReport(node, addr1, kList1ID, ReasonNoPayout, "took my payment, never minted"), 1792800000, key4)
	r, err := ParseReport(ev)
	if err != nil || r.Reason != ReasonNoPayout || r.Node != node || r.Addr != addr1 || r.ListingID != kList1ID || r.Author != pub4 {
		t.Fatalf("K-REP-1 = %+v (%v)", r, err)
	}
	for _, reason := range []ReportReason{ReasonImpersonation, ReasonSpam} {
		ev := NewReport(node, "", "", reason, "")
		for _, tg := range ev.Tags {
			if tg[0] == "L" || tg[0] == "l" {
				t.Fatalf("%s carries a label", reason)
			}
		}
		if r, err := ParseReport(signedAt(t, ev, 1792800000, key4)); err != nil || r.Reason != reason {
			t.Fatalf("%s → %+v %v", reason, r, err)
		}
	}
	tm, _ := ParseReport(signedAt(t, NewReport(node, "", "", ReasonTermsMismatch, ""), 1792800000, key4))
	if tm.Reason != ReasonTermsMismatch {
		t.Fatalf("terms_mismatch → %s", tm.Reason)
	}
	noP := signedAt(t, nip01.NewEvent(KindReport, "", []string{"e", kList1ID, "other"}), 1792800000, key4)
	if _, err := ParseReport(noP); !errors.Is(err, ErrReport) {
		t.Fatalf("no p: %v", err)
	}
	// A report with only p applies to every listing of its node.
	onlyP, _ := ParseReport(signedAt(t, NewReport(node, "", "", ReasonSpam, ""), 1792800000, key4))
	trust := Trust{Follows: map[string]bool{pub4: true}}
	for _, l := range []*Listing{kList1(t), {NodeIdentity: node, D: otherConn, Event: kList1(t).Event}} {
		if s := SignalsFor(l, trust, nil, []*Report{onlyP, r}, nil, nil); len(s.Reports) != 2 {
			t.Fatalf("reports on %s: %d", l.D, len(s.Reports))
		}
	}
	if s := SignalsFor(kList1(t), Trust{}, nil, []*Report{onlyP}, nil, nil); len(s.Reports) != 0 {
		t.Fatal("an untrusted report counted")
	}
}

// T22-13: SanitizeText (K-TXT-1).
func TestT22_13_SanitizeText(t *testing.T) {
	e41 := strings.Repeat("é", 41)
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"Alice\u200b's\u202e cash counter", MaxTitle, "Alice's cash counter"},
		{"\u2714 Alice", MaxTitle, " Alice"},
		{"\u2714\ufe0f Alice", MaxTitle, " Alice"},
		{"A\nB", MaxTitle, "A B"},
		{"A\r\nB\tC", MaxTitle, "A B C"},
		{strings.Repeat("a", 41), MaxTitle, strings.Repeat("a", 40)},
		{e41, MaxTitle, strings.Repeat("é", 40)},
		{strings.Repeat("a", 281), MaxContent, strings.Repeat("a", 280)},
		{"see https://evil.example/x", MaxTitle, "see https://evil.example/x"},
		{"\u2066x\u2069\u2060\ufeff\u200c\u200d\u221a\u2611\u2705\U0001F5F8\u2713", 0, "x"},
	}
	for _, c := range cases {
		if got := SanitizeText(c.in, c.max); got != c.want {
			t.Errorf("SanitizeText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Control characters: NUL, ESC (a CSI sequence's introducer) and C1 CSI.
	if got := SanitizeText("a\x00b\x1b[31mc\u009bd", MaxTitle); got != "ab[31mcd" {
		t.Errorf("controls = %q", got)
	}
	// Combining sequences: 41 clusters of e + U+0301 → 40, never cut inside one.
	comb := strings.Repeat("é", 41)
	if got := SanitizeText(comb, MaxTitle); got != strings.Repeat("é", 40) {
		t.Errorf("combining = %q", got)
	}
}

func info(pubkey, network, chain string) *nip47.GetInfoResult {
	return &nip47.GetInfoResult{Pubkey: pubkey, Network: network, Chain: chain, Methods: []string{"get_info"}}
}

const tapTerms = `{"pubkey":"` + node + `","network":"mainnet","chain":"bitcoin","methods":["get_info"],
 "cash_order":{"lightning":{"min_millis":1000000,"max_millis":1000000000,"fee_base":1000,"fee_ppm":1000,"window":3600}}}`

// T22-14: CheckTap shows the terms or hides a signed mismatch for good.
func TestT22_14_CheckTap(t *testing.T) {
	l := kList1(t)
	r := CheckTap(l, info(node, "mainnet", "bitcoin"), json.RawMessage(tapTerms), nil)
	if r.Outcome != TapShow || r.Terms == nil || r.Terms.Lightning == nil || r.HintDiffers {
		t.Fatalf("show = %+v", r)
	}
	differs := strings.Replace(tapTerms, `"fee_ppm":1000`, `"fee_ppm":2000`, 1)
	if r := CheckTap(l, info(node, "mainnet", "bitcoin"), json.RawMessage(differs), nil); r.Outcome != TapShow || !r.HintDiffers {
		t.Fatalf("hint differs = %+v", r)
	}
	if r := CheckTap(l, info("02"+node, "mainnet", "bitcoin"), json.RawMessage(tapTerms), nil); r.Outcome != TapShow {
		t.Fatalf("66-hex identity = %+v", r)
	}
	for name, gi := range map[string]*nip47.GetInfoResult{
		"network differs":  info(node, "regtest", "bitcoin"),
		"identity differs": info(pub2, "mainnet", "bitcoin"),
		"chain differs":    info(node, "mainnet", "litecoin"),
		"no chain":         info(node, "mainnet", ""),
	} {
		if r := CheckTap(l, gi, json.RawMessage(tapTerms), nil); r.Outcome != TapHideForGood {
			t.Errorf("%s → %v", name, r.Outcome)
		}
	}
}

func circleListing(t testing.TB) *Listing {
	ev, err := NewListing(circleFields(t, otherConn), createdList1, createdList1, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseListing(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func circleInfo(identity string, accepting *bool, available int64) *nip47.GetInfoResult {
	gi := info("", "mainnet", "bitcoin")
	gi.CircleWallet = &nip47.CircleWalletInfo{Identity: identity, Accepting: accepting, AvailableMillis: available}
	return gi
}

// T22-15: closed signals hide until newer; everything else is unavailable.
func TestT22_15_TapOutcomes(t *testing.T) {
	l := kList1(t)
	closed := `{"pubkey":"` + node + `","network":"mainnet","chain":"bitcoin","cash_order":{}}`
	r := CheckTap(l, info(node, "mainnet", "bitcoin"), json.RawMessage(closed), nil)
	if r.Outcome != TapHideUntilNewer {
		t.Fatalf("cash_order {} → %v", r.Outcome)
	}
	// No cash_order key at all: not the Hub's closed signal, kept.
	noKey := `{"pubkey":"` + node + `","network":"mainnet","chain":"bitcoin","methods":["get_info"]}`
	if r := CheckTap(l, info(node, "mainnet", "bitcoin"), json.RawMessage(noKey), nil); r.Outcome != TapUnavailable {
		t.Fatalf("no cash_order key → %v", r.Outcome)
	}
	book := NewVersionBook()
	book.Offer(l, createdList1)
	book.Taps().Record(l, r)
	if _, ok := book.Current(addr1, createdList1); ok {
		t.Fatal("hidden version shown")
	}
	newer := resign(t, l.Event, key1, func(e *nip01.Event) { e.CreatedAt = createdList1 + 60 })
	nl, _ := ParseListing(newer, mainnet)
	book.Offer(nl, createdList1+60)
	if _, ok := book.Current(addr1, createdList1+60); !ok {
		t.Fatal("a newer version stays hidden")
	}
	yes, no := true, false
	c := circleListing(t)
	if r := CheckTap(c, circleInfo(node, &no, 1000), nil, nil); r.Outcome != TapHideUntilNewer {
		t.Fatalf("accepting false → %v", r.Outcome)
	}
	if r := CheckTap(c, circleInfo(node, &yes, 0), nil, nil); r.Outcome != TapUnavailable {
		t.Fatalf("available 0 → %v", r.Outcome)
	}
	if r := CheckTap(c, circleInfo(node, &yes, 1000), nil, nil); r.Outcome != TapShow || r.Circle == nil {
		t.Fatalf("circle show → %+v", r)
	}
	if r := CheckTap(c, circleInfo(pub2, &yes, 1000), nil, nil); r.Outcome != TapHideForGood {
		t.Fatalf("circle identity differs → %v", r.Outcome)
	}
	for _, code := range []string{"", "RESTRICTED", "RATE_LIMITED", "QUOTA_EXCEEDED", "INSUFFICIENT_CAPACITY", "NOT_READY", "INTERNAL"} {
		err := errors.New("no answer")
		if code != "" {
			err = fmt.Errorf("nwc error %s", code)
		}
		r := CheckTap(l, nil, nil, err)
		cache := NewTapCache()
		cache.Record(l, r)
		if r.Outcome != TapUnavailable || cache.Hidden(l) {
			t.Fatalf("%q → %v", code, r.Outcome)
		}
	}
}

// T22-16: RecommendAllowed and an unfilled recommendation.
func TestT22_16_RecommendAllowed(t *testing.T) {
	const session, last = 2000000, 1000000
	if RecommendAllowed(false, last, session, last+86400) {
		t.Error("not used → allowed")
	}
	if RecommendAllowed(true, session+1, session, session+86401) {
		t.Error("same session → allowed")
	}
	if RecommendAllowed(true, last, session, last+86399) {
		t.Error("86399 s → allowed")
	}
	if !RecommendAllowed(true, last, session, last+86400) {
		t.Error("86400 s → refused")
	}
	if ev := NewRecommendation(node, "", nil, ""); ev.Content != "" {
		t.Error("pre-filled")
	}
	if ev := NewRecommendation(node, "", nil, "my words"); ev.Content != "my words" {
		t.Error("content changed")
	}
}

func fakeEncrypt(s string) (string, error) { return hex.EncodeToString([]byte(s)), nil }
func fakeDecrypt(s string) (string, error) {
	b, err := hex.DecodeString(s)
	return string(b), err
}

// T22-17: curator sets.
func TestT22_17_CuratorSet(t *testing.T) {
	ev, err := NewCuratorSet(CuratorSet{Curators: []string{pub2, pub4}}, fakeEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != 30000 || len(ev.Tags) != 1 || ev.Tags[0][0] != "d" || ev.Tags[0][1] != CuratorSetD || ev.Content == "" {
		t.Fatalf("set = %+v", ev)
	}
	if strings.Contains(ev.Content, pub2) {
		t.Fatal("curator in the clear")
	}
	signedAt(t, ev, createdList1, key4)
	c, err := ParseCuratorSet(ev, fakeDecrypt)
	if err != nil || !c.Private || !slices.Equal(c.Curators, []string{pub2, pub4}) {
		t.Fatalf("parsed = %+v (%v)", c, err)
	}
	// A public entry is read too.
	ev = resign(t, ev, key4, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"p", node}) })
	if c, _ = ParseCuratorSet(ev, fakeDecrypt); !slices.Equal(c.Curators, []string{node, pub2, pub4}) {
		t.Fatalf("with public = %v", c.Curators)
	}
	if _, err := NewCuratorSet(CuratorSet{Curators: []string{pub2}, Private: true}, nil); err == nil {
		t.Fatal("private without an encrypter")
	}
	pub, err := NewCuratorSet(CuratorSet{Curators: []string{pub2}}, nil)
	if err != nil || len(pub.Tags) != 2 || pub.Content != "" {
		t.Fatalf("public = %+v %v", pub, err)
	}
	for _, tg := range pub.Tags {
		if tg[0] == "title" {
			t.Fatal("title")
		}
	}
}

// T22-18: RankKey.
func TestT22_18_RankKey(t *testing.T) {
	now := int64(createdList1 + StaleAfterSecs + 100)
	mk := func(ca int64) *Listing {
		return &Listing{NodeIdentity: node, D: kcoConn, Event: &nip01.Event{CreatedAt: uint64(ca)}}
	}
	sig := Signals{Recommendations: []*Recommendation{{}}}
	type item struct {
		l *Listing
		s Signals
	}
	staleSig := item{mk(createdList1), sig}
	freshSig := item{mk(now - 10), sig}
	freshOld := item{mk(now - StaleAfterSecs), Signals{}}
	freshNew := item{mk(now - 5), Signals{}}
	stale := item{mk(createdList1 + 50), Signals{Reports: []*Report{{}}}}
	items := []item{stale, freshOld, staleSig, freshNew, freshSig}
	slices.SortFunc(items, func(a, b item) int {
		if RankLess(a.l, a.s, b.l, b.s, now) {
			return -1
		}
		if RankLess(b.l, b.s, a.l, a.s, now) {
			return 1
		}
		return 0
	})
	want := []item{freshSig, staleSig, freshNew, freshOld, stale}
	for i := range want {
		if items[i].l != want[i].l {
			t.Fatalf("rank %d = %d", i, items[i].l.Event.CreatedAt)
		}
	}
	if s, f, _ := RankKey(mk(now-StaleAfterSecs), Signals{}, now); s || !f {
		t.Fatal("10 days old is stale")
	}
}

// T22-19 and T22-21 (filters): the NIP's requests in order.
func TestT22_19_Filters(t *testing.T) {
	fs := TrustedFilters(Trusted{Follows: []string{"f1", "f2"}, Curators: []string{"c1", "f1"}, Nodes: []string{"n1"},
		Operators: []string{"o1"}})
	type want struct {
		kinds   []int
		authors []string
		tag     string
		values  []string
	}
	wants := []want{
		{[]int{31191}, []string{"f1", "f2", "c1"}, "k", []string{"31190"}},
		{[]int{1984}, []string{"f1", "f2", "c1"}, "p", []string{"n1"}},
		{[]int{31190}, []string{"n1"}, "", nil},
		{[]int{5}, []string{"n1"}, "k", []string{"31190"}},
		{[]int{0, 11191}, []string{"o1"}, "", nil},
		{[]int{3}, []string{"f1", "f2"}, "p", []string{"o1"}},
		{[]int{5}, []string{"f1", "f2", "c1"}, "k", []string{"31191"}},
	}
	if len(fs) != len(wants) {
		t.Fatalf("%d filters: %+v", len(fs), fs)
	}
	for i, w := range wants {
		f := fs[i]
		if !slices.Equal(f.Kinds, w.kinds) || !slices.Equal(f.Authors, w.authors) ||
			(w.tag != "" && !slices.Equal(f.Tags[w.tag], w.values)) || (w.tag == "" && len(f.Tags) != 0) {
			t.Errorf("filter %d = %+v, want %+v", i, f, w)
		}
	}
	g := GlobalFilter([]string{"bitcoin"}, 0)
	if !slices.Equal(g.Kinds, []int{31190}) || g.Limit != 500 || !slices.Equal(g.Tags["t"], []string{"cash_order", "circle_wallet"}) ||
		!slices.Equal(g.Tags["n"], []string{"bitcoin"}) {
		t.Fatalf("global = %+v", g)
	}
	authors := make([]string, 250)
	for i := range authors {
		authors[i] = fmt.Sprint(i)
	}
	chunks := ChunkAuthors(authors, 100)
	if len(chunks) != 3 || len(chunks[0]) != 100 || len(chunks[2]) != 50 || chunks[1][0] != "100" || chunks[2][49] != "249" {
		t.Fatalf("chunks = %d", len(chunks))
	}
	if fs := TrustedFilters(Trusted{Follows: authors}); len(fs) != 2*3 { // 31191 and kind 5 #k 31191; the #p requests have no values
		t.Fatalf("chunked filters = %d", len(fs))
	}
	if fs := TrustedFilters(Trusted{}); len(fs) != 0 {
		t.Fatalf("empty = %v", fs)
	}
}

// T22-20: no error string carries a connection secret, a curator or a draft.
func TestT22_20_NoSecretsInErrors(t *testing.T) {
	secret := connSecret()
	base := kList1Event(t)
	conn := ""
	for _, tg := range base.Tags {
		if tg[0] == "connection" {
			conn = tg[1]
		}
	}
	var errs []error
	for _, edit := range []func(e *nip01.Event){
		func(e *nip01.Event) { setTag(e, "d", otherConn) },
		func(e *nip01.Event) { setTag(e, "n", "litecoin") },
		func(e *nip01.Event) { setTag(e, "t", "circle_wallet") },
		func(e *nip01.Event) { setTag(e, "connection", conn[:len(conn)-1]+"q") },
		func(e *nip01.Event) { setTag(e, "network", "regtest") },
	} {
		_, err := ParseListing(resign(t, base, key1, edit), mainnet)
		errs = append(errs, err)
	}
	f := kList1Fields(t)
	f.Order.Label = "changed"
	_, err := NewListing(f, createdList1, createdList1, signWith(key1))
	errs = append(errs, err)
	_, err = NewCuratorSet(CuratorSet{Curators: []string{pub2 + "x"}}, nil)
	errs = append(errs, err)
	_, err = NewCuratorSet(CuratorSet{Curators: []string{pub2}}, func(string) (string, error) { return "", errors.New(pub2) })
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("no error")
		}
		s := err.Error()
		if strings.Contains(s, secret) || strings.Contains(s, conn) || strings.Contains(s, pub2) {
			t.Fatalf("error leaks: %s", s)
		}
	}
}

// T22-21: NewestRecommendations and the withdrawal.
func TestT22_21_NewestRecommendations(t *testing.T) {
	r1, _ := ParseRecommendation(kRec1Event(t))
	newerEv := signedAt(t, NewRecommendation(node, relayURL, []Ref{{addr1, relayURL}}, "still good"), 1792800100, key4)
	r2, _ := ParseRecommendation(newerEv)
	if got := NewestRecommendations([]*Recommendation{r2, r1}, nil); len(got) != 1 || got[0] != r2 {
		t.Fatalf("newest = %v", got)
	}
	tieEv := signedAt(t, NewRecommendation(node, relayURL, []Ref{{addr1, relayURL}}, "tie"), 1792800000, key4)
	r3, _ := ParseRecommendation(tieEv)
	low := r1
	if r3.Event.ID < r1.Event.ID {
		low = r3
	}
	if got := NewestRecommendations([]*Recommendation{r1, r3}, nil); len(got) != 1 || got[0] != low {
		t.Fatal("tie: not the lower id")
	}
	del := NewRecommendationDeletion(r1.Address(), 1792800050)
	if fmt.Sprint(del.Tags) != fmt.Sprint([][]string{{"a", "31191:" + pub4 + ":" + node}, {"k", "31191"}}) || del.Kind != 5 {
		t.Fatalf("deletion = %+v", del)
	}
	signedAt(t, del, 1792800050, key4)
	if got := NewestRecommendations([]*Recommendation{r1}, []*nip01.Event{del}); len(got) != 0 {
		t.Fatal("withdrawn recommendation kept")
	}
	if got := NewestRecommendations([]*Recommendation{r1, r2}, []*nip01.Event{del}); len(got) != 1 || got[0] != r2 {
		t.Fatal("a later version dropped")
	}
	byOther := NewRecommendationDeletion(r1.Address(), 1792800050)
	signedAt(t, byOther, 1792800050, key2)
	if got := NewestRecommendations([]*Recommendation{r1}, []*nip01.Event{byOther}); len(got) != 1 {
		t.Fatal("a deletion by another key applied")
	}
	fs := TrustedFilters(Trusted{Follows: []string{pub4}})
	last := fs[len(fs)-1]
	if !slices.Equal(last.Kinds, []int{5}) || !slices.Equal(last.Tags["k"], []string{"31191"}) || !slices.Equal(last.Authors, []string{pub4}) {
		t.Fatalf("kind-5 31191 request = %+v", last)
	}
}

// SignalsFor credits recommendations through CreditedOffers and shows the
// operator's followers only when verified.
func TestSignalsFor(t *testing.T) {
	l := kList1(t)
	r, _ := ParseRecommendation(kRec1Event(t))
	trust := Trust{Curators: map[string]bool{pub4: true, pub2: true}}
	opOf := func(a string) (string, bool) { return pub2, a == addr1 }
	s := SignalsFor(l, trust, []*Recommendation{r}, nil, []string{pub4, "stranger", pub4}, opOf)
	if len(s.Recommendations) != 1 || !slices.Equal(s.OperatorFollowedBy, []string{pub4}) {
		t.Fatalf("signals = %+v", s)
	}
	if s := SignalsFor(l, trust, []*Recommendation{r}, nil, []string{pub4}, func(string) (string, bool) { return "", false }); len(s.OperatorFollowedBy) != 0 {
		t.Fatal("followers of an unverified operator")
	}
	if s := SignalsFor(l, Trust{}, []*Recommendation{r}, nil, nil, opOf); len(s.Recommendations) != 0 {
		t.Fatal("an untrusted recommendation counted")
	}
	other := &Listing{NodeIdentity: node, D: otherConn, Event: l.Event}
	if s := SignalsFor(other, trust, []*Recommendation{r}, nil, nil, opOf); len(s.Recommendations) != 0 {
		t.Fatal("credited to an offer it does not name")
	}
}

// Several pubkeys listing one d: none shows before a tap, then only the one
// whose signer passed it (§Wallet Rules "Signals").
func TestCurrentByDSeveralSigners(t *testing.T) {
	real := kList1(t)
	copier, err := utils.GetPublicKey(key3)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := nipcash.LocalChainSigner(key3, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := nipCO.SignOrderConnection(nipCO.OrderConnection{Pubkey: kcoConn, Relays: []string{relayURL},
		Secret: connSecret(), Label: "Copied counter", HasLabel: true, HubIdentity: copier, Chain: "bitcoin"}, sign, copier)
	if err != nil {
		t.Fatal(err)
	}
	f := kList1Fields(t)
	f.Order = &c
	ev, err := NewListing(f, createdList1, createdList1, signWith(key3))
	if err != nil {
		t.Fatal(err)
	}
	copy, err := ParseListing(ev, mainnet)
	if err != nil {
		t.Fatal(err)
	}
	book := NewVersionBook()
	if l, ok := book.CurrentByD(kcoConn, createdList1); ok || l != nil {
		t.Fatal("empty book shows a listing")
	}
	book.Offer(real, createdList1)
	if l, ok := book.CurrentByD(kcoConn, createdList1); !ok || l != real {
		t.Fatal("a single signer is not shown")
	}
	book.Offer(copy, createdList1)
	if _, ok := book.CurrentByD(kcoConn, createdList1); ok {
		t.Fatal("two signers shown before a tap")
	}
	// The copy's tap names another identity: hidden for good. The real one
	// passes.
	book.Taps().Record(copy, CheckTap(copy, info(node, "mainnet", "bitcoin"), json.RawMessage(tapTerms), nil))
	book.Taps().Record(real, CheckTap(real, info(node, "mainnet", "bitcoin"), json.RawMessage(tapTerms), nil))
	if l, ok := book.CurrentByD(kcoConn, createdList1); !ok || l != real {
		t.Fatalf("after tap: %v %v", l, ok)
	}
	// The pass survives a snapshot.
	snap, err := book.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	back := NewVersionBook()
	if err := back.Restore(snap); err != nil {
		t.Fatal(err)
	}
	if !back.Taps().Passed(real) || back.Taps().Passed(copy) {
		t.Fatal("pass not restored")
	}
}
