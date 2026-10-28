package vectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/listing"
	"github.com/ohstr/nmilat/nipcw"
)

// ---- listing.json (NIP-CASH \u00a7Offer Listing)

type listingFile struct {
	header
	Events   []listingEventKAT `json:"events"`
	Parse    []listingParse    `json:"parseListing"`
	Expiry   []listingExpiry   `json:"expiresAt"`
	Versions []listingVersion  `json:"versions"`
	Operator []listingBool     `json:"operatorVerified"`
	Credited []listingCredit   `json:"creditedOffers"`
	Reports  []listingParse    `json:"reports"`
	Tap      []listingTap      `json:"tap"`
	Sanitize []listingText     `json:"sanitizeText"`
}

type listingEventKAT struct {
	ID    string      `json:"id"`
	Event nip01.Event `json:"event"`
	Note  string      `json:"note,omitempty"`
}

// listingParse: ParseListing (or ParseReport) with the wallet's chains and
// test-network setting: the failing step (0 = shown) and the parsed fields.
type listingParse struct {
	Name     string         `json:"name"`
	Event    nip01.Event    `json:"event"`
	Chains   []string       `json:"chains,omitempty"`
	TestNets bool           `json:"testNetworks,omitempty"`
	Step     int            `json:"step"`
	Error    string         `json:"error,omitempty"`
	Want     map[string]any `json:"want,omitempty"`
}

type listingExpiry struct {
	ID         string `json:"id"`
	Expiration string `json:"expiration"`
	ExpiresAt  int64  `json:"expiresAt"`
}

// listingVersion: a sequence of VersionBook.Offer calls (event ids, at now)
// and what is current after it.
type listingVersion struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Offers    []string `json:"offers"`
	At        []int64  `json:"at"`
	Accepted  []bool   `json:"accepted"`
	CurrentAt int64    `json:"currentAt"`
	Current   string   `json:"current"`
}

type listingBool struct {
	Name     string      `json:"name"`
	Listing  string      `json:"listingId"`
	Offers   nip01.Event `json:"operatorOffers"`
	Verified bool        `json:"verified"`
}

type listingCredit struct {
	ID             string            `json:"id"`
	Recommendation nip01.Event       `json:"recommendation"`
	OfNode         []string          `json:"ofNode"`
	Operators      map[string]string `json:"operators"`
	Credited       []string          `json:"credited"`
}

type listingTap struct {
	Name        string `json:"name"`
	Listing     string `json:"listing"`
	GetInfo     string `json:"getInfo,omitempty"`
	InfoError   string `json:"infoError,omitempty"`
	Outcome     string `json:"outcome"`
	Reason      string `json:"reason,omitempty"`
	HintDiffers bool   `json:"hintDiffers"`
}

type listingText struct {
	ID   string `json:"id,omitempty"`
	In   string `json:"in"`
	Max  int    `json:"max"`
	Want string `json:"out"`
}

const (
	lPub2      = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	lPub4      = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
	lKey3      = "0000000000000000000000000000000000000000000000000000000000000003"
	lKey4      = "0000000000000000000000000000000000000000000000000000000000000004"
	lCreated   = 1792713600
	lExpires   = 1795305600
	lOtherConn = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
)

func lsign(priv string) func(*nip01.Event) error {
	return func(ev *nip01.Event) error { return ev.Sign(priv) }
}

func signedAtV(ev *nip01.Event, at int64, priv string) nip01.Event {
	ev.CreatedAt = uint64(at)
	if err := ev.Sign(priv); err != nil {
		panic(err)
	}
	return *ev
}

func lResign(ev *nip01.Event, priv string, edit func(*nip01.Event)) nip01.Event {
	c := ev.Copy()
	edit(c)
	if err := c.Sign(priv); err != nil {
		panic(err)
	}
	return *c
}

func lSetTag(ev *nip01.Event, name, value string) {
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == name {
			tg[1] = value
			return
		}
	}
	ev.Tags = append(ev.Tags, []string{name, value})
}

func lDropTag(ev *nip01.Event, name string) {
	var out [][]string
	for _, tg := range ev.Tags {
		if len(tg) == 0 || tg[0] != name {
			out = append(out, tg)
		}
	}
	ev.Tags = out
}

func stepOf(err error) int {
	var le *listing.ListingError
	if errors.As(err, &le) {
		return le.Step
	}
	if err != nil {
		return -1
	}
	return 0
}

func buildListing() (any, error) {
	f := listingFile{header: newHeader(
		"NIP-CASH offer listings (kind 31190) and their signals: K-LIST-1..2, the deletion (K-LDEL-1), operator offers (K-OPS-1), a recommendation (K-REC-1) and a report (K-REP-1); ParseListing's steps in order, ignored tags, expiry and skew (K-LEXP-1..3), versions (K-LVER-1), operator verification, recommendation crediting, report shapes, at-tap outcomes and SanitizeText (K-TXT-1).",
		"nipcash/listing/*.go; nipcash/listing/kat_test.go, listing_test.go",
	)}
	order := connInputs(kindCashOrder, "Alice's cash counter", true)
	order, err := signConn(kindCashOrder, order, connKey1)
	if err != nil {
		return nil, err
	}
	oc := order.order()
	fields := listing.ListingFields{
		Order: &oc, Network: "mainnet", Summary: []string{"lightning", "onchain"}, Title: "Alice's cash counter",
		Image: "https://example.com/counter.png", Content: "Cash for the Lisbon meetup. Lightning or on-chain, paid out within the hour.",
		Location: "Lisbon, Baixa", Operator: &listing.Ref{Pubkey: lPub2, Relay: connRelay}, Status: listing.StatusOpen, Expiration: lExpires,
		Hints:     []listing.Hint{{Payment: "lightning", MinMillis: 1000000, MaxMillis: 1000000000, FeeBase: 1000, FeePpm: 1000}},
		Languages: []string{"pt", "en"}, Geohashes: []string{"eyc"},
	}
	l1ev, err := listing.NewListing(fields, lCreated, lCreated, lsign(connKey1))
	if err != nil {
		return nil, err
	}
	mainnet := listing.CheckOptions{Chains: []string{"bitcoin"}}
	l1, err := listing.ParseListing(l1ev, mainnet)
	if err != nil {
		return nil, err
	}
	addr1 := l1.Address()
	f.Events = append(f.Events, listingEventKAT{"K-LIST-1", *l1ev, "address " + addr1})
	l2ev, err := listing.ClosedListing(l1, 1793318400, lsign(connKey1))
	if err != nil {
		return nil, err
	}
	f.Events = append(f.Events, listingEventKAT{"K-LIST-2", *l2ev, ""})
	del, err := listing.NewListingDeletion(addr1, 1793318460, lsign(connKey1))
	if err != nil {
		return nil, err
	}
	f.Events = append(f.Events, listingEventKAT{"K-LDEL-1", *del, ""})
	ops := signedAtV(listing.NewOperatorOffers([]listing.Ref{{Pubkey: addr1, Relay: connRelay}}, []listing.Ref{{Pubkey: connIdentity, Relay: connRelay}}), lCreated, connKey2)
	f.Events = append(f.Events, listingEventKAT{"K-OPS-1", ops, ""})
	rec := signedAtV(listing.NewRecommendation(connIdentity, connRelay, []listing.Ref{{Pubkey: addr1, Relay: connRelay}}, "fast payouts, used it for months"), 1792800000, lKey4)
	f.Events = append(f.Events, listingEventKAT{"K-REC-1", rec, ""})
	rep := signedAtV(listing.NewReport(connIdentity, addr1, l1ev.ID, listing.ReasonNoPayout, "took my payment, never minted"), 1792800000, lKey4)
	f.Events = append(f.Events, listingEventKAT{"K-REP-1", rep, ""})

	parse := func(name string, ev nip01.Event, o listing.CheckOptions) {
		c := listingParse{Name: name, Event: ev, Chains: o.Chains, TestNets: o.TestNetworks}
		l, err := listing.ParseListing(&ev, o)
		c.Step, c.Error = stepOf(err), errString(err)
		if err == nil {
			c.Want = map[string]any{"type": l.Type, "d": l.D, "chain": l.Chain, "network": l.Network, "summary": l.Summary, "title": l.Title,
				"image": l.Image, "location": l.Location, "status": l.Status, "expiration": l.Expiration, "hints": l.Hints, "languages": l.Languages,
				"geohashes": l.Geohashes, "followSet": l.FollowSet, "connection": l.Connection, "address": l.Address(), "operator": l.Operator}
		}
		f.Parse = append(f.Parse, c)
	}
	unv := oc
	unv.Label = "Bob's cash counter"
	unvStr := must(nipCO.EncodeOrderConnection(unv))
	hub := connInputs(kindCashHub, "", false)
	hub.Secret = order.Secret
	hub, _ = signConn(kindCashHub, hub, connKey1)
	hubStr := must(nipcash.EncodeCashHubConnection(hub.cashHub()))
	circle := connInputs(kindCircleHub, "", false)
	circle.Secret = order.Secret
	circle, _ = signConn(kindCircleHub, circle, connKey1)
	circleStr := must(nipcw.EncodeCircleHubConnection(circle.circleHub()))
	r := func(priv string, edit func(*nip01.Event)) nip01.Event { return lResign(l1ev, priv, edit) }
	k1 := connKey1
	parse("K-LIST-1", *l1ev, mainnet)
	parse("K-LIST-2", *l2ev, mainnet)
	parse("step 1: two d", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"d", connPubkey}) }), mainnet)
	parse("step 1: no status", r(k1, func(e *nip01.Event) { lDropTag(e, "status") }), mainnet)
	parse("step 1: no expiration", r(k1, func(e *nip01.Event) { lDropTag(e, "expiration") }), mainnet)
	parse("step 1: two titles", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"title", "x"}) }), mainnet)
	parse("step 1: two lightning hints", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"hint", "lightning", "1", "2", "3", "4"}) }), mainnet)
	parse("step 1: two type t of one value", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"t", "cash_order"}) }), mainnet)
	parse("step 1: expiration 1795305600.0", r(k1, func(e *nip01.Event) { lSetTag(e, "expiration", "1795305600.0") }), mainnet)
	parse("step 1: unknown status", r(k1, func(e *nip01.Event) { lSetTag(e, "status", "gone") }), mainnet)
	parse("step 1: two location", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"location", "x"}) }), mainnet)
	badSig := *l1ev.Copy()
	badSig.Content = "changed"
	parse("step 1: bad signature", badSig, mainnet)
	parse("step 2: both type values", r(k1, func(e *nip01.Event) { e.Tags = append(e.Tags, []string{"t", "circle_wallet"}) }), mainnet)
	parse("step 2: no type", r(k1, func(e *nip01.Event) { lSetTag(e, "t", "lightning") }), mainnet)
	parse("step 2: wrong HRP: a cashhub1 string", r(k1, func(e *nip01.Event) { lSetTag(e, "connection", hubStr) }), mainnet)
	parse("step 2: circlehub1 under cash_order", r(k1, func(e *nip01.Event) { lSetTag(e, "connection", circleStr) }), mainnet)
	parse("step 2: cashorder1 under circle_wallet", r(k1, func(e *nip01.Event) { lSetTag(e, "t", "circle_wallet") }), mainnet)
	parse("step 2: garbage connection", r(k1, func(e *nip01.Event) { lSetTag(e, "connection", "cashorder1qqqq") }), mainnet)
	parse("step 3: an unverified string", r(k1, func(e *nip01.Event) { lSetTag(e, "connection", unvStr) }), mainnet)
	parse("step 3: TLV 4 is not pubkey", r(lKey3, func(*nip01.Event) {}), mainnet)
	parse("step 3: TLV 0 is not d", r(k1, func(e *nip01.Event) { lSetTag(e, "d", lOtherConn) }), mainnet)
	parse("step 3: TLV 6 is not n", r(k1, func(e *nip01.Event) { lSetTag(e, "n", "litecoin") }), listing.CheckOptions{Chains: []string{"litecoin"}})
	parse("step 4: a chain not held", *l1ev, listing.CheckOptions{Chains: []string{"litecoin"}})
	parse("step 4: a test network", r(k1, func(e *nip01.Event) { lSetTag(e, "network", "regtest") }), mainnet)
	parse("a test network with test networks enabled", r(k1, func(e *nip01.Event) { lSetTag(e, "network", "regtest") }), listing.CheckOptions{Chains: []string{"bitcoin"}, TestNetworks: true})
	parse("step 1 before step 3", r(lKey3, func(e *nip01.Event) { lDropTag(e, "status") }), mainnet)
	parse("an uppercase connection is read lowercased", r(k1, func(e *nip01.Event) {
		for _, tg := range e.Tags {
			if tg[0] == "connection" {
				tg[1] = strings.ToUpper(tg[1])
			}
		}
	}), mainnet)
	parse("ignored tags dropped", r(k1, func(e *nip01.Event) {
		e.Tags = append(e.Tags, []string{"t", "bogus"}, []string{"t", "allowlist"}, []string{"hint", "bolt12", "1", "2", "3", "4"},
			[]string{"g", "eycabc"}, []string{"a", "30000:" + lPub2 + ":x"}, []string{"hint", "onchain", "1", "x", "3", "4"})
		lSetTag(e, "image", "http://example.com/counter.png")
	}), mainnet)
	parse("closed", *l2ev, mainnet)

	for _, c := range [][2]string{{"K-LEXP-1", "1795305600"}, {"K-LEXP-2", "1800000000"}, {"K-LEXP-3", "1793000000"}} {
		ev := r(k1, func(e *nip01.Event) { lSetTag(e, "expiration", c[1]) })
		l, err := listing.ParseListing(&ev, mainnet)
		if err != nil {
			return nil, err
		}
		f.Expiry = append(f.Expiry, listingExpiry{c[0], c[1], l.ExpiresAt()})
	}

	l2 := must(listing.ParseListing(l2ev, mainnet))
	alt := r(k1, func(e *nip01.Event) { e.Content = "another text" })
	lalt := must(listing.ParseListing(&alt, mainnet))
	f.Events = append(f.Events, listingEventKAT{"", alt, "K-LIST-1 with other content, same created_at (K-LVER-1)"})
	ver := func(id, name string, at int64, currentAt int64, ls ...*listing.Listing) {
		b := listing.NewVersionBook()
		c := listingVersion{ID: id, Name: name, CurrentAt: currentAt}
		for _, l := range ls {
			c.Offers = append(c.Offers, l.Event.ID)
			c.At = append(c.At, at)
			c.Accepted = append(c.Accepted, b.Offer(l, at))
		}
		if cur, ok := b.Current(addr1, currentAt); ok {
			c.Current = cur.Event.ID
		}
		f.Versions = append(f.Versions, c)
	}
	ver("K-LEXP-1", "seen 900 s ahead: accepted", 1792712700, 1792712700, l1)
	ver("K-LEXP-1", "seen 901 s ahead: ignored", 1792712699, 1792712699, l1)
	ver("K-LEXP-1", "current at its expiry", lCreated, lExpires, l1)
	ver("K-LEXP-1", "not current after its expiry", lCreated, lExpires+1, l1)
	ver("K-LVER-1", "equal created_at: the lower id kept", lCreated, lCreated, l1, lalt)
	ver("K-LVER-1", "equal created_at, other order: the lower id kept", lCreated, lCreated, lalt, l1)
	ver("K-LVER-1", "K-LIST-1 offered after K-LIST-2: refused", 1793318400, 1793318400, l2, l1)
	ver("K-LVER-1", "K-LIST-2 expired then K-LIST-1 again: still refused", 1793318400, lExpires+100, l2, l1)

	opsP := must(listing.ParseOperatorOffers(&ops))
	vb := func(name string, l *listing.Listing, ev nip01.Event) {
		o, _ := listing.ParseOperatorOffers(&ev)
		f.Operator = append(f.Operator, listingBool{name, l.Event.ID, ev, listing.OperatorVerified(l, o)})
	}
	vb("K-OPS-1 with K-LIST-1: verified", l1, ops)
	vb("an 11191 without the a: not verified", l1, signedAtV(listing.NewOperatorOffers(nil, []listing.Ref{{Pubkey: connIdentity, Relay: connRelay}}), lCreated, connKey2))
	otherP := r(k1, func(e *nip01.Event) { lSetTag(e, "p", connPubkey) })
	f.Events = append(f.Events, listingEventKAT{"", otherP, "K-LIST-1 whose p names another key (operatorVerified)"})
	vb("K-LIST-1's p naming another key: not verified", must(listing.ParseListing(&otherP, mainnet)), ops)
	_ = opsP

	recP := must(listing.ParseRecommendation(&rec))
	same := listing.Address(connIdentity, lOtherConn)
	another := listing.Address(connIdentity, lPub2)
	ofNode := []*listing.Listing{l1, {NodeIdentity: connIdentity, D: lOtherConn}, {NodeIdentity: connIdentity, D: lPub2}}
	operators := map[string]string{addr1: lPub2, same: lPub2, another: lPub4}
	credited := listing.CreditedOffers(recP, ofNode, func(a string) (string, bool) { v, ok := operators[a]; return v, ok })
	f.Credited = append(f.Credited, listingCredit{"K-REC-1", rec, []string{addr1, same, another}, operators, nonNil(credited)})

	report := func(name string, ev nip01.Event) {
		c := listingParse{Name: name, Event: ev}
		rp, err := listing.ParseReport(&ev)
		c.Error = errString(err)
		if err == nil {
			c.Want = map[string]any{"reason": rp.Reason, "node": rp.Node, "addr": rp.Addr, "listingId": rp.ListingID, "author": rp.Author}
		}
		f.Reports = append(f.Reports, c)
	}
	report("K-REP-1", rep)
	for _, reason := range []listing.ReportReason{listing.ReasonImpersonation, listing.ReasonSpam, listing.ReasonTermsMismatch} {
		report("only p: "+string(reason), signedAtV(listing.NewReport(connIdentity, "", "", reason, ""), 1792800000, lKey4))
	}
	report("no p", signedAtV(nip01.NewEvent(listing.KindReport, "", []string{"e", l1ev.ID, "other"}), 1792800000, lKey4))

	tapTerms := `{"pubkey":"` + connIdentity + `","network":"mainnet","chain":"bitcoin","methods":["get_info"],"cash_order":{"lightning":{"min_millis":1000000,"max_millis":1000000000,"fee_base":1000,"fee_ppm":1000,"window":3600}}}`
	tap := func(name string, l *listing.Listing, raw string, infoErr error) {
		c := listingTap{Name: name, Listing: l.Event.ID, GetInfo: raw, InfoError: errString(infoErr)}
		var gi *nip47.GetInfoResult
		if raw != "" {
			gi = &nip47.GetInfoResult{}
			if err := json.Unmarshal([]byte(raw), gi); err != nil {
				panic(err)
			}
		}
		res := listing.CheckTap(l, gi, json.RawMessage(raw), infoErr)
		c.Outcome, c.Reason, c.HintDiffers = res.Outcome.String(), res.Reason, res.HintDiffers
		f.Tap = append(f.Tap, c)
	}
	tap("terms shown", l1, tapTerms, nil)
	tap("the hint differs from the terms", l1, strings.Replace(tapTerms, `"fee_ppm":1000`, `"fee_ppm":2000`, 1), nil)
	tap("a 66-hex identity", l1, strings.Replace(tapTerms, connIdentity, "02"+connIdentity, 1), nil)
	tap("network differs: hidden for good", l1, strings.Replace(tapTerms, `"mainnet"`, `"regtest"`, 1), nil)
	tap("identity differs: hidden for good", l1, strings.Replace(tapTerms, connIdentity, lPub2, 1), nil)
	tap("chain differs: hidden for good", l1, strings.Replace(tapTerms, `"bitcoin"`, `"litecoin"`, 1), nil)
	tap("no chain: hidden for good", l1, strings.Replace(tapTerms, `"chain":"bitcoin",`, ``, 1), nil)
	tap("cash_order {}: hidden until a newer version", l1, `{"pubkey":"`+connIdentity+`","network":"mainnet","chain":"bitcoin","methods":["get_info"],"cash_order":{}}`, nil)
	for _, code := range []string{"RESTRICTED", "RATE_LIMITED", "INTERNAL"} {
		tap("no answer ("+code+"): unavailable", l1, "", fmt.Errorf("nwc error %s", code))
	}
	cev, err := listing.NewListing(listing.ListingFields{Circle: ptrCircle(circle.circleHub()), Network: "mainnet", Summary: []string{"allowlist"}, Title: "Circle", Expiration: lCreated + 1000}, lCreated, lCreated, lsign(connKey1))
	if err != nil {
		return nil, err
	}
	cl := must(listing.ParseListing(cev, mainnet))
	f.Events = append(f.Events, listingEventKAT{"", *cev, "a circle listing (tap)"})
	ci := func(identity, accepting string, available int) string {
		return `{"network":"mainnet","chain":"bitcoin","methods":["get_info"],"circle_wallet":{"available_millis":` + fmt.Sprint(available) +
			`,"max_exp_secs":0,"fees_ppm":0,"circle_policy":"allowlist","identity":"` + identity + `","accepting":` + accepting + `}}`
	}
	tap("circle accepting false: hidden until newer", cl, ci(connIdentity, "false", 1000), nil)
	tap("circle available 0: unavailable", cl, ci(connIdentity, "true", 0), nil)
	tap("circle shown", cl, ci(connIdentity, "true", 1000), nil)
	tap("circle identity differs: hidden for good", cl, ci(lPub2, "true", 1000), nil)

	e41 := strings.Repeat("é", 41)
	for _, c := range []listingText{
		{"K-TXT-1", "Alice\u200b's\u202e cash counter", listing.MaxTitle, ""},
		{"K-TXT-1", "\u2714 Alice", listing.MaxTitle, ""},
		{"", "\u2714\ufe0f Alice", listing.MaxTitle, ""},
		{"K-TXT-1", "A\nB", listing.MaxTitle, ""},
		{"", "A\r\nB\tC", listing.MaxTitle, ""},
		{"K-TXT-1", strings.Repeat("a", 41), listing.MaxTitle, ""},
		{"K-TXT-1", e41, listing.MaxTitle, ""},
		{"K-TXT-1", strings.Repeat("a", 281), listing.MaxContent, ""},
		{"", "see https://evil.example/x", listing.MaxTitle, ""},
		{"", "\u2066x\u2069\u2060\ufeff\u200c\u200d\u221a\u2611\u2705\U0001F5F8\u2713", 0, ""},
		{"", strings.Repeat("e\u0301", 41), listing.MaxTitle, ""},
	} {
		c.Want = listing.SanitizeText(c.In, c.Max)
		f.Sanitize = append(f.Sanitize, c)
	}
	return f, nil
}

func ptrCircle(c nipcw.CircleHubConnection) *nipcw.CircleHubConnection { return &c }
